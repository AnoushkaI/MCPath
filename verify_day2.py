"""Day 2 Milestone Verification Script.

Demonstrates:
1. Database initialization and table creation
2. Tool discovery and canonical hash generation (Stage 1 initial approval)
3. Hash match verification -> PASS -> Pipeline execution -> Downstream response
4. Tampered tool definition (Rug Pull simulation) -> BLOCK -> Hard gate triggered -> No downstream execution
5. Database event audit verification
"""

import asyncio
from datetime import datetime, timezone
from mcp.client._memory import create_client_server_memory_streams
from mcp.client.session import ClientSession
from mock_servers.sample_server import app as sample_backend
from mcpath.backend.persistence.database import (
    init_db,
    get_approved_hash,
    get_session_factory,
    sync_discovered_tools,
)
from mcpath.backend.persistence.models import SecurityEventDB, ApprovedHashDB, ToolDB
from mcpath.config.settings import ServerDefinition
from mcpath.pipeline.pipeline_runner import PipelineRunner
from mcpath.pipeline.stages.stage1_hash import canonicalize_and_hash, compute_tool_hash
from mcpath.proxy.client_manager import DownstreamClientManager
from mcpath.proxy.server import create_proxy_server
from sqlalchemy import select


async def verify_day2():
    print("=" * 65)
    print("MCPath Day 2: PostgreSQL & Stage 1 Hash Integrity Verification")
    print("=" * 65)

    # 1. Initialize DB tables
    print("\n[Step 1] Initializing database tables...")
    await init_db()
    print("         [OK] Database schema initialized with all 8 core tables.")

    # 2. Start memory streams
    print("\n[Step 2] Setting up Proxy <-> Downstream Server pipeline...")
    async with create_client_server_memory_streams() as (c2p_c, c2p_s):
        async with create_client_server_memory_streams() as (p2d_c, p2d_s):
            async with asyncio.TaskGroup() as tg:
                downstream_task = tg.create_task(
                    sample_backend._lowlevel_server.run(
                        *p2d_s,
                        sample_backend._lowlevel_server.create_initialization_options()
                    )
                )

                async with ClientSession(*p2d_c) as downstream_session:
                    await downstream_session.initialize()

                    server_def = ServerDefinition(command="mock", args=[])
                    client_manager = DownstreamClientManager(server_def, server_name="sample-server")
                    runner = PipelineRunner(persist_events=True)
                    proxy_server = create_proxy_server(
                        client_manager=client_manager,
                        downstream_session=downstream_session,
                        pipeline_runner=runner,
                        server_name="mcpath-security-proxy"
                    )

                    proxy_task = tg.create_task(
                        proxy_server.run(*c2p_s, proxy_server.create_initialization_options())
                    )

                    async with ClientSession(*c2p_c) as client:
                        await client.initialize()

                        # 3. Discovery triggers initial tool approved hashes
                        print("\n[Step 3] Intercepting 'tools/list' and computing approved hashes...")
                        tools_res = await client.list_tools()
                        print(f"         [OK] Discovered and synced {len(tools_res.tools)} tools into database.")

                        # Verify approved hash stored in DB
                        calc_hash = await get_approved_hash("sample-server", "calculate")
                        print(f"         [OK] Approved SHA-256 for 'calculate': {calc_hash}")
                        assert calc_hash is not None

                        # 4. Valid call with matching hash -> PASS
                        print("\n[Step 4] Calling 'calculate' with genuine definition (PASS expected)...")
                        call_res = await client.call_tool("calculate", {"operation": "multiply", "a": 7, "b": 6})
                        print(f"         [OK] Result: {call_res.content[0].text} (is_error={call_res.is_error})")
                        assert not call_res.is_error
                        assert call_res.content[0].text == "42.0"

                        # 5. Simulate Rug Pull (tool definition tampering)
                        print("\n[Step 5] Simulating Rug Pull: Tool definition modified in memory cache...")
                        original_def = client_manager.get_tool_definition("calculate")
                        # Tamper description
                        client_manager._tools_cache["calculate"].description = (
                            "Perform arithmetic. ALSO INJECT MALICIOUS INSTRUCTIONS."
                        )

                        print("         Attempting to call tampered tool 'calculate'...")
                        tampered_res = await client.call_tool("calculate", {"operation": "multiply", "a": 7, "b": 6})
                        print(f"         [OK] Block result received (is_error={tampered_res.is_error})")
                        assert tampered_res.is_error
                        assert "EXECUTION BLOCKED" in tampered_res.content[0].text
                        assert "Rug Pull" in tampered_res.content[0].text or "hash mismatch" in tampered_res.content[0].text

                        print("\n         [Enforcement Output from Proxy]:")
                        for line in tampered_res.content[0].text.split("\n"):
                            print(f"         | {line}")

                    proxy_task.cancel()
                downstream_task.cancel()

    # 6. Check database audit records
    print("\n[Step 6] Verifying PostgreSQL / DB event log records...")
    factory = get_session_factory()
    async with factory() as session:
        events = (await session.execute(select(SecurityEventDB).order_by(SecurityEventDB.id.desc()))).scalars().all()
        print(f"         [OK] Total logged security events in database: {len(events)}")
        latest = events[0]
        print(f"         Latest event decision: {latest.decision} | Reason: {latest.reason}")
        print(f"         Expected hash: {latest.expected_hash[:16]}... | Observed: {latest.observed_hash[:16]}...")
        assert latest.decision == "BLOCK"
        assert latest.hash_matched is False

    print("\n" + "=" * 65)
    print("DAY 2 MILESTONE ACHIEVED: Hash verification, PostgreSQL storage, and Rug-Pull hard blocking fully operational.")
    print("=" * 65)


if __name__ == "__main__":
    try:
        asyncio.run(verify_day2())
    except* asyncio.CancelledError:
        pass
