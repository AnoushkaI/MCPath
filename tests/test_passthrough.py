"""Tests verifying minimal MCP passthrough proxy functionality (Day 1 Milestone).

Milestone verification:
Proxy starts -> MCP server connects -> tools/list works -> tools/call works -> response reaches client.
"""

import asyncio
import sys
import pytest
from mcp.client._memory import create_client_server_memory_streams
from mcp.client.session import ClientSession
from mock_servers.sample_server import app as sample_backend
from mcpath.backend.persistence.database import init_db, register_trusted_server_and_tools
from mcpath.proxy.server import create_proxy_server
from mcpath.proxy.client_manager import DownstreamClientManager
from mcpath.config.settings import ServerDefinition
from mcpath.pipeline.pipeline_runner import PipelineRunner
from mcpath.pipeline.stages.stage1_hash import canonicalize_and_hash
import mcp.types as types


@pytest.mark.asyncio
async def test_end_to_end_proxy_passthrough():
    """Verify that an MCP client can connect to MCPath Proxy and call tools on the downstream server."""
    await init_db()

    # Memory streams for Client -> MCPath Proxy
    async with create_client_server_memory_streams() as (c2p_client_streams, c2p_server_streams):
        # Memory streams for MCPath Proxy -> Downstream Server
        async with create_client_server_memory_streams() as (p2d_client_streams, p2d_server_streams):
            c_read, c_write = c2p_client_streams
            proxy_in_read, proxy_in_write = c2p_server_streams
            proxy_out_read, proxy_out_write = p2d_client_streams
            downstream_read, downstream_write = p2d_server_streams

            async with asyncio.TaskGroup() as tg:
                # 1. Start downstream target server
                downstream_task = tg.create_task(
                    sample_backend._lowlevel_server.run(
                        downstream_read,
                        downstream_write,
                        sample_backend._lowlevel_server.create_initialization_options(),
                    )
                )

                # 2. Connect MCPath proxy client session to downstream
                async with ClientSession(proxy_out_read, proxy_out_write) as downstream_session:
                    await downstream_session.initialize()

                    server_def = ServerDefinition(command="mock", args=[])
                    client_manager = DownstreamClientManager(server_def, server_name="sample-server")

                    # Register trusted baseline in DB for Stage 1
                    raw_tools = await downstream_session.list_tools()
                    tools_data = [t.model_dump(mode="json") for t in raw_tools.tools]
                    await register_trusted_server_and_tools(
                        server_name="sample-server",
                        tools=tools_data,
                        canonicalize_and_hash_fn=canonicalize_and_hash
                    )

                    # 3. Create MCPath Proxy Server
                    pipeline_runner = PipelineRunner()
                    proxy_server = create_proxy_server(
                        client_manager=client_manager,
                        downstream_session=downstream_session,
                        pipeline_runner=pipeline_runner,
                        server_name="mcpath-test-proxy"
                    )

                    proxy_task = tg.create_task(
                        proxy_server.run(
                            proxy_in_read,
                            proxy_in_write,
                            proxy_server.create_initialization_options(),
                        )
                    )

                    # 4. Simulate Client (e.g. Claude Desktop) connecting to MCPath Proxy
                    async with ClientSession(c_read, c_write) as client:
                        init_res = await client.initialize()
                        assert init_res.server_info.name == "mcpath-test-proxy"

                        # Test tools/list works
                        tools_res = await client.list_tools()
                        tool_names = [t.name for t in tools_res.tools]
                        assert "echo" in tool_names
                        assert "calculate" in tool_names
                        assert "read_customer" in tool_names
                        assert "send_email" in tool_names

                        # Test tools/call works with echo
                        call_res = await client.call_tool("echo", {"message": "Zero Trust Test"})
                        assert not call_res.is_error
                        assert len(call_res.content) > 0
                        assert call_res.content[0].text == "ECHO: Zero Trust Test"

                        # Test tools/call works with calculate
                        calc_res = await client.call_tool("calculate", {"operation": "multiply", "a": 6, "b": 7})
                        assert not calc_res.is_error
                        assert calc_res.content[0].text == "42.0"

                    proxy_task.cancel()
                downstream_task.cancel()


@pytest.mark.asyncio
async def test_downstream_client_manager_stdio():
    """Verify DownstreamClientManager connects to a real subprocess via stdio."""
    server_def = ServerDefinition(
        command=sys.executable,
        args=["mock_servers/sample_server.py"],
        env={}
    )
    manager = DownstreamClientManager(server_def=server_def, server_name="sample-stdio")

    async with manager.session_context() as session:
        tools_res = await manager.list_tools(session)
        assert len(tools_res.tools) >= 5

        # Verify tool definitions are cached for later pipeline hashing (Stage 1)
        echo_def = manager.get_tool_definition("echo")
        assert echo_def is not None
        assert echo_def["name"] == "echo"

        call_res = await manager.call_tool(session, "echo", {"message": "stdio test"})
        assert not call_res.is_error
        assert call_res.content[0].text == "ECHO: stdio test"
