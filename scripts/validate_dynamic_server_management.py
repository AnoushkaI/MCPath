"""Validation script for MCPath dynamic MCP server management and explicit trust layer.

Runs steps 3-19 from Section 14 Validation.
"""

import asyncio
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mcpath.config.settings import settings
from mcpath.proxy.client_manager import DownstreamClientManager, set_active_client_manager
from mcpath.proxy.server import create_proxy_server
from mcpath.pipeline.pipeline_runner import PipelineRunner
from mcpath.pipeline.stages.stage1_hash import canonicalize_and_hash, Stage1HashCheck
from mcpath.backend.persistence.database import (
    init_db,
    get_approved_hash,
    get_server_db_status,
    save_discovered_tools,
    register_trusted_server_and_tools
)
import mcp.types as types
from mcp.client.session import ClientSession
from mcp.client._memory import create_client_server_memory_streams


async def run_validation():
    print("=" * 60)
    print("MCPATH DYNAMIC SERVER MANAGEMENT VALIDATION")
    print("=" * 60)

    # 1. Database init
    await init_db()
    print("[1] Database initialized.")

    # 2. Check 5 servers in server_config.json
    config = settings.get_server_config()
    print(f"[2] Configured active servers: {config.active_servers}")
    assert len(config.active_servers) >= 5, "Expected at least 5 active servers"

    # 3. Create DownstreamClientManager from configured active servers
    from mcpath.proxy.passthrough import PassthroughProxy
    proxy_coordinator = PassthroughProxy()
    manager = DownstreamClientManager(server_defs=proxy_coordinator.server_defs)
    set_active_client_manager(manager)
    print(f"[3] Connecting to {len(manager.server_defs)} configured downstream servers...")
    
    await manager.start_all_servers()
    try:
        connected_count = sum(1 for s in manager.servers_state.values() if s.is_connected)
        print(f"[4] Connected servers: {connected_count}/{len(manager.server_defs)} ({list(manager.servers_state.keys())})", flush=True)
        print(f"[5] Exposed tools count: {len(manager.exposed_tools)}", flush=True)
        print(f"[5b] Capability graph nodes: {len(manager.capability_graph.graph.nodes)}", flush=True)

        # 6. Add a safe local test MCP server through dynamic add_server
        test_server_name = "test-dynamic-worker"
        test_script_path = str(ROOT / "mock_servers" / "sample_server.py")

        print(f"\n[6] Adding dynamic server '{test_server_name}'...", flush=True)
        add_result = await manager.add_server(
            name=test_server_name,
            command=sys.executable,
            args=[test_script_path],
            env={},
            transport="stdio"
        )

        # 7. Verify it becomes UNTRUSTED
        print(f"[7] Added server status: {add_result['trust_status']}", flush=True)
        assert add_result["trust_status"] == "UNTRUSTED", "Must be UNTRUSTED on add"
        assert add_result["approved_tool_count"] == 0, "Approved tools count must be 0"
        assert add_result["unapproved_tool_count"] > 0, "Unapproved tools count must be > 0"
        print(f"    Discovered tools: {add_result['discovered_tool_count']}, Approved: {add_result['approved_tool_count']}", flush=True)

        # Check DB approved hash is None
        sample_tool_name = list(manager.servers_state[test_server_name].tools.keys())[0]
        db_hash = await get_approved_hash(test_server_name, sample_tool_name)
        assert db_hash is None, f"Tool '{sample_tool_name}' must have NO_APPROVED_BASELINE"
        print(f"[8] Verified tool '{sample_tool_name}' has NO_APPROVED_BASELINE in DB", flush=True)

        # 8. Verify tool call is blocked by Stage 1
        runner = PipelineRunner(persist_events=False)
        proxy = create_proxy_server(client_manager=manager, pipeline_runner=runner)

        exposed_name = None
        for exp_name, exp_t in manager.exposed_tools.items():
            if exp_t.server_name == test_server_name and exp_t.original_name == sample_tool_name:
                exposed_name = exp_name
                break
        assert exposed_name is not None

        call_res = await proxy.handle_call_tool(None, types.CallToolRequestParams(name=exposed_name, arguments={"message": "hello"}))
        print(f"[8b] Calling untrusted tool '{exposed_name}' result error: {call_res.is_error}", flush=True)
        assert call_res.is_error is True
        assert "NO_APPROVED_BASELINE" in call_res.content[0].text
        print(f"     Blocked as expected: NO_APPROVED_BASELINE", flush=True)

        # 9. Trust & Register it
        print(f"\n[9] Trusting server '{test_server_name}'...", flush=True)
        trust_result = await manager.trust_server(test_server_name)
        assert trust_result["trust_status"] == "TRUSTED"
        assert trust_result["approved_tool_count"] == trust_result["discovered_tool_count"]
        print(f"[10] Status after trust: {trust_result['trust_status']}, Approved: {trust_result['approved_tool_count']}", flush=True)

        # 10. Verify its tools now pass Stage 1 when unchanged
        call_res_trusted = await proxy.handle_call_tool(None, types.CallToolRequestParams(name=exposed_name, arguments={"message": "hello"}))
        print(f"[10b] Calling trusted tool '{exposed_name}' result error: {call_res_trusted.is_error}", flush=True)
        assert not call_res_trusted.is_error
        print(f"      Success: Tool passed Stage 1 and executed downstream: {call_res_trusted.content[0].text}", flush=True)

        # 11. Modify one tool description/schema (Rug pull simulation)
        print(f"\n[11] Modifying tool description for '{sample_tool_name}' (Tampering)...", flush=True)
        tampered = types.Tool(
            name=sample_tool_name,
            description="Tampered description injecting backdoor",
            input_schema={"type": "object", "properties": {"message": {"type": "string"}}}
        )
        manager.servers_state[test_server_name].tools[sample_tool_name] = tampered
        manager.recompute_exposed_tools()

        # 12 & 13. Call it, verify HASH_MISMATCH and BLOCK
        call_res_tampered = await proxy.handle_call_tool(None, types.CallToolRequestParams(name=exposed_name, arguments={"message": "hello"}))
        print(f"[12] Calling tampered tool result error: {call_res_tampered.is_error}", flush=True)
        assert call_res_tampered.is_error is True
        err_text = call_res_tampered.content[0].text.lower()
        assert "rug pull detected" in err_text or "hash mismatch" in err_text or "hash_mismatch" in err_text
        print(f"[13] Execution blocked: Hash mismatch detected!", flush=True)

        # 15. Deactivate server
        print(f"\n[15] Deactivating server '{test_server_name}'...", flush=True)
        nodes_before_deact = len(manager.capability_graph.graph.nodes)
        deact_result = await manager.deactivate_server(test_server_name)
        assert deact_result["active"] is False
        assert deact_result["connected"] is False
        assert exposed_name not in manager.exposed_tools
        nodes_after_deact = len(manager.capability_graph.graph.nodes)
        print(f"[16] Tool '{exposed_name}' removed from catalog.", flush=True)
        print(f"     Capability graph nodes: {nodes_before_deact} -> {nodes_after_deact}", flush=True)
        assert nodes_after_deact < nodes_before_deact

        # 17. Activate it again
        print(f"\n[17] Activating server '{test_server_name}'...", flush=True)
        act_result = await manager.activate_server(test_server_name)
        assert act_result["active"] is True
        assert act_result["connected"] is True
        assert exposed_name in manager.exposed_tools
        print(f"[18] Restored to catalog: '{exposed_name}'", flush=True)
        
        # Check previous baseline is preserved
        hash_in_db = await get_approved_hash(test_server_name, sample_tool_name)
        assert hash_in_db is not None, "Baseline must survive deactivate/activate"
        print(f"[18b] Approved baseline preserved in PostgreSQL: {hash_in_db[:16]}...", flush=True)

        # 19. Capability graph restored
        nodes_after_react = len(manager.capability_graph.graph.nodes)
        print(f"[19] Capability graph nodes after reactivate: {nodes_after_react}", flush=True)
        assert nodes_after_react == nodes_before_deact

        # Clean up dynamic worker from config and DB
        await manager.deactivate_server(test_server_name)
        cfg = settings.get_server_config()
        if test_server_name in cfg.servers:
            del cfg.servers[test_server_name]
        if test_server_name in cfg.active_servers:
            cfg.active_servers.remove(test_server_name)
        from mcpath.proxy.client_manager import save_server_config_file
        save_server_config_file(cfg)
    finally:
        await manager.stop_all_servers()

    print("\n" + "=" * 60, flush=True)
    print("ALL VALIDATION STEPS 3-19 COMPLETED SUCCESSFULLY!", flush=True)
    print("=" * 60, flush=True)


if __name__ == "__main__":
    asyncio.run(run_validation())
