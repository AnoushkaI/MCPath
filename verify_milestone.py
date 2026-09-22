"""Milestone 1 Verification Script.

Verifies the complete Step 3 milestone:
Proxy starts -> MCP server connects -> tools/list works -> tools/call works -> response reaches client.
"""

import asyncio
import sys
from mcp.client._memory import create_client_server_memory_streams
from mcp.client.session import ClientSession
from mock_servers.sample_server import app as sample_backend
from mcpath.proxy.server import create_proxy_server
from mcpath.proxy.client_manager import DownstreamClientManager
from mcpath.config.settings import ServerDefinition
from mcpath.pipeline.pipeline_runner import PipelineRunner


async def verify():
    print("=" * 60)
    print("MCPath Day 1 Milestone Verification")
    print("=" * 60)

    # 1. Start memory streams
    print("[Step 1] Initializing client-proxy and proxy-downstream streams...")
    async with create_client_server_memory_streams() as (c2p_c, c2p_s):
        async with create_client_server_memory_streams() as (p2d_c, p2d_s):
            async with asyncio.TaskGroup() as tg:
                # 2. Downstream Server starts
                print("[Step 2] Downstream MCP Server starting...")
                downstream_task = tg.create_task(
                    sample_backend._lowlevel_server.run(
                        *p2d_s,
                        sample_backend._lowlevel_server.create_initialization_options()
                    )
                )

                # 3. Proxy connects to downstream server
                print("[Step 3] MCPath Proxy connecting to downstream server...")
                async with ClientSession(*p2d_c) as downstream_session:
                    await downstream_session.initialize()
                    print(f"         [OK] Connected to: {downstream_session.server_info.name}")

                    server_def = ServerDefinition(command="mock", args=[])
                    client_manager = DownstreamClientManager(server_def, server_name="sample_reference_server")
                    proxy_server = create_proxy_server(
                        client_manager=client_manager,
                        downstream_session=downstream_session,
                        pipeline_runner=PipelineRunner(),
                        server_name="mcpath-security-proxy"
                    )

                    # 4. Proxy starts serving MCP client
                    print("[Step 4] MCPath Proxy server listening for client requests...")
                    proxy_task = tg.create_task(
                        proxy_server.run(*c2p_s, proxy_server.create_initialization_options())
                    )

                    # 5. MCP Client (e.g. Claude Desktop) connects
                    print("[Step 5] Simulated MCP Client (Claude Desktop) connecting...")
                    async with ClientSession(*c2p_c) as client:
                        init_res = await client.initialize()
                        print(f"         [OK] Client initialized with proxy: {init_res.server_info.name}")

                        # 6. tools/list works
                        print("[Step 6] Testing 'tools/list' through proxy...")
                        tools_res = await client.list_tools()
                        tool_names = [t.name for t in tools_res.tools]
                        print(f"         [OK] Discovered {len(tool_names)} tools: {tool_names}")
                        assert len(tool_names) > 0, "No tools discovered"

                        # 7. tools/call works
                        print("[Step 7] Testing 'tools/call' with 'echo' through proxy...")
                        call_res = await client.call_tool("echo", {"message": "Hello via MCPath Zero-Trust Proxy!"})
                        print(f"         [OK] Result text: {call_res.content[0].text}")
                        assert call_res.content[0].text == "ECHO: Hello via MCPath Zero-Trust Proxy!"

                        print("[Step 8] Testing 'tools/call' with 'calculate' (arithmetic) through proxy...")
                        calc_res = await client.call_tool("calculate", {"operation": "multiply", "a": 21, "b": 2})
                        print(f"         [OK] Result text: {calc_res.content[0].text}")
                        assert calc_res.content[0].text == "42.0"

                        # 8. Sensitive tool passthrough check (read_customer)
                        print("[Step 9] Testing 'tools/call' with 'read_customer'...")
                        cust_res = await client.call_tool("read_customer", {"customer_id": "cust_101"})
                        print(f"         [OK] Result text: {cust_res.content[0].text}")

                    proxy_task.cancel()
                downstream_task.cancel()

    print("\n" + "=" * 60)
    print("MILESTONE 1 ACHIEVED: Proxy started, server connected, tools/list worked, tools/call worked, response reached client unmodified.")
    print("=" * 60)


if __name__ == "__main__":
    try:
        asyncio.run(verify())
    except* asyncio.CancelledError:
        pass
