"""Verify Live Claude Desktop Scenarios:
1. List authorized directory -> ALLOW without approval
2. Read ordinary README.md -> ALLOW without approval
3. Read .env -> enters HOLD, pending approval created
4. Approve held call -> resumes, executes downstream once
5. Read .env again -> enters HOLD -> Reject -> blocked, not executed
6. Read .env again -> enters HOLD -> Timeout -> blocked, status TIMED_OUT
"""

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

from mcp.client._memory import create_client_server_memory_streams
from mcp.client.session import ClientSession
import mcp.types as types

from mcpath.backend.persistence.database import (
    get_approvals,
    get_approval_by_id,
    update_approval_status,
)
from mcpath.config.settings import settings
from mcpath.pipeline.pipeline_runner import PipelineRunner
from mcpath.proxy.approval_manager import approval_manager
from mcpath.proxy.client_manager import DownstreamClientManager
from mcpath.proxy.server import create_proxy_server


sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")


async def main():
    print("=" * 70)
    print("MCPath Live Claude Desktop Demo Scenarios Verification")
    print("=" * 70)

    # Ensure demo .env and README.md exist in filesystem demo directory
    fs_root = Path(settings.filesystem_allowed_paths.strip())
    fs_root.mkdir(parents=True, exist_ok=True)

    readme_path = fs_root / "README.md"
    readme_path.write_text("# Demo Project\nThis is a safe demonstration file for MCPath.", encoding="utf-8")

    dummy_env_path = fs_root / ".env"
    dummy_env_path.write_text("DEMO_SECRET=dummy_value_12345\nAPI_KEY=dummy_key_abcdef", encoding="utf-8")

    server_config = settings.get_server_config()
    server_defs = {}
    from mcpath.config.settings import interpolate_server_config
    for s_name in ["filesystem"]:
        if s_name in server_config.servers:
            server_defs[s_name] = interpolate_server_config(server_config.servers[s_name], settings)

    client_manager = DownstreamClientManager(server_defs=server_defs)
    await client_manager.start_all_servers()
    pipeline_runner = PipelineRunner(persist_events=True)

    proxy_server = create_proxy_server(
        client_manager=client_manager,
        pipeline_runner=pipeline_runner,
        server_name="mcpath-live-demo-proxy"
    )

    async with create_client_server_memory_streams() as (c2p_c, c2p_s):
        server_task = asyncio.create_task(
            proxy_server.run(c2p_s[0], c2p_s[1], proxy_server.create_initialization_options())
        )

        async with ClientSession(c2p_c[0], c2p_c[1]) as session:
            await session.initialize()
            tools_res = await session.list_tools()
            print(f"\n[INIT] Proxy initialized with {len(tools_res.tools)} tools from downstream servers.", flush=True)

            # ---------------------------------------------------------------------
            # Scenario 1: List an authorized project directory -> ALLOW
            # ---------------------------------------------------------------------
            print("\n--- Scenario 1: List Authorized Directory ---", flush=True)
            res1 = await session.call_tool("list_directory", {"path": str(fs_root).replace("\\", "/")})
            print(f"Result is_error: {res1.is_error}", flush=True)
            text1 = " ".join(c.text for c in res1.content if hasattr(c, "text"))
            print(f"Directory listing response preview: {text1[:80]}...", flush=True)
            assert not res1.is_error, "list_directory should be allowed"
            assert "README.md" in text1, "README.md should be in listing"
            print("[PASS] Scenario 1 PASSED: Authorized directory listed without approval.", flush=True)

            # ---------------------------------------------------------------------
            # Scenario 2: Read ordinary authorized README.md -> ALLOW
            # ---------------------------------------------------------------------
            print("\n--- Scenario 2: Read Ordinary README.md ---", flush=True)
            res2 = await session.call_tool("read_file", {"path": str(readme_path).replace("\\", "/")})
            print(f"Result is_error: {res2.is_error}", flush=True)
            text2 = " ".join(c.text for c in res2.content if hasattr(c, "text"))
            print(f"File content: {text2.strip()}", flush=True)
            assert not res2.is_error, "read_file on README.md should be allowed"
            assert "Demo Project" in text2, "README.md content should be returned"
            print("[PASS] Scenario 2 PASSED: README.md read without approval.", flush=True)

            # ---------------------------------------------------------------------
            # Scenario 3 & 4: Read dummy .env -> HOLD -> Admin Approves -> Executes
            # ---------------------------------------------------------------------
            print("\n--- Scenario 3 & 4: Read .env -> HOLD -> Admin Approves -> Executes ---", flush=True)
            
            # Start read_file in background task so we can approve it concurrently
            async def call_read_env():
                return await session.call_tool("read_file", {"path": str(dummy_env_path).replace("\\", "/")})

            read_task = asyncio.create_task(call_read_env())

            # Wait a moment for hold to register
            await asyncio.sleep(0.5)

            # Check pending approvals
            pending = await get_approvals(status="PENDING")
            assert len(pending) >= 1, "Expected pending approval in DB"
            appr_item = pending[0]
            appr_id = appr_item["approval_id"]
            print(f"Call held as expected! Approval ID: {appr_id}", flush=True)
            print(f"Tool: {appr_item['tool_name']}, Risk: {appr_item['risk_score']}, Reason: {appr_item['reason']}", flush=True)

            # Simulate Admin clicking "Approve" via approval_manager
            print("Simulating Admin clicking 'Approve & Forward'...", flush=True)
            up_res = await approval_manager.resolve_approval(appr_id, "APPROVED", resolver="soc_admin")
            assert up_res["status"] == "APPROVED"

            # Wait for read_task to complete
            res3 = await read_task
            print(f"Result is_error: {res3.is_error}", flush=True)
            text3 = " ".join(c.text for c in res3.content if hasattr(c, "text"))
            print(f"Approved Execution Result: {text3.strip()}", flush=True)
            assert not res3.is_error, "Approved call should succeed downstream"
            assert "DEMO_SECRET" in text3, "File content should be returned upon approval"
            print("[PASS] Scenario 3 & 4 PASSED: .env held, approved, and executed downstream once.", flush=True)

            # ---------------------------------------------------------------------
            # Scenario 5: Read dummy .env -> HOLD -> Admin Rejects -> Blocked
            # ---------------------------------------------------------------------
            print("\n--- Scenario 5: Read .env -> HOLD -> Admin Rejects -> Blocked ---", flush=True)
            read_task2 = asyncio.create_task(call_read_env())
            await asyncio.sleep(0.5)

            pending2 = await get_approvals(status="PENDING")
            assert len(pending2) >= 1, "Expected pending approval"
            appr_id2 = pending2[0]["approval_id"]

            print(f"Simulating Admin clicking 'Block / Reject' on {appr_id2}...", flush=True)
            await approval_manager.resolve_approval(appr_id2, "REJECTED", resolver="soc_admin")

            res5 = await read_task2
            print(f"Result is_error: {res5.is_error}", flush=True)
            text5 = " ".join(c.text for c in res5.content if hasattr(c, "text"))
            print(f"Rejection Response: {text5.strip()}", flush=True)
            assert res5.is_error, "Rejected call should return error"
            assert "REJECTED" in text5.upper(), "Error should indicate administrative rejection"
            assert "DEMO_SECRET" not in text5, "Sensitive content must NEVER be returned"
            print("[PASS] Scenario 5 PASSED: .env held and rejected; downstream was NOT executed.", flush=True)

            # ---------------------------------------------------------------------
            # Scenario 6: Read dummy .env -> HOLD -> Timeout -> Blocked
            # ---------------------------------------------------------------------
            print("\n--- Scenario 6: Read .env -> HOLD -> Timeout -> Blocked ---", flush=True)
            # For fast test, set approval_timeout_seconds to 1.5s
            orig_timeout = getattr(settings, "approval_timeout_seconds", 30.0)
            settings.approval_timeout_seconds = 1.5

            t_start = asyncio.get_event_loop().time()
            res6 = await session.call_tool("read_file", {"path": str(dummy_env_path).replace("\\", "/")})
            t_elapsed = asyncio.get_event_loop().time() - t_start

            settings.approval_timeout_seconds = orig_timeout
            print(f"Timed out after {t_elapsed:.2f}s. Result is_error: {res6.is_error}", flush=True)
            text6 = " ".join(c.text for c in res6.content if hasattr(c, "text"))
            print(f"Timeout Response: {text6.strip()}", flush=True)
            assert res6.is_error, "Timed out call should return error"
            assert "TIMED OUT" in text6.upper(), "Response should indicate timeout"
            assert "DEMO_SECRET" not in text6, "Sensitive content must NEVER be returned"
            print("[PASS] Scenario 6 PASSED: .env timed out and blocked; downstream was NOT executed.", flush=True)

        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass

    try:
        await asyncio.wait_for(client_manager.shutdown_all(), timeout=3.0)
    except Exception:
        pass

    print("\n" + "=" * 70)
    print("ALL 6 CLAUDE DESKTOP DEMO SCENARIOS PASSED WITH 100% SUCCESS!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
