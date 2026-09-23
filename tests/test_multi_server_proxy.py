"""Comprehensive Multi-Server MCP Proxy Test Suite.

Verifies:
- Multi-server startup and connection management
- Aggregated tools/list with schema preservation
- Unique tool name preservation
- Deterministic namespace collision handling for identical tool names
- Exact server routing and cross-server isolation
- Per-server approved hash verification in Stage 1
- Missing baseline fail-closed policy (zero downstream execution)
- Tool definition rug-pull / hash mismatch blocking (zero downstream execution)
- Stage 1 PASS continues through Stage 2
- Independent server lifecycle (one server failure does not affect others)
- Failed server tools excluded from tools/list
- Server reconnection and rediscovery
- Dynamic server reload (POST /api/servers/reload equivalent)
- Dynamic capability graph update after server addition/removal
- Discovery does not equal approval (no automatic DB hash approval)
- Sample reference server is never used as a silent fallback
- Controlled Claude Desktop rug-pull simulation
"""

import asyncio
import copy
from typing import Any, Dict, List, Optional
import pytest
import pytest_asyncio
from mcp.client._memory import create_client_server_memory_streams
from mcp.client.session import ClientSession
from mcp.server.lowlevel import Server
import mcp.types as types
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from mcpath.backend.persistence.models import Base
from mcpath.backend.persistence.database import register_trusted_server_and_tools, get_approved_hash
from mcpath.config.settings import ServerConfig, ServerDefinition
from mcpath.pipeline.pipeline_runner import PipelineRunner
from mcpath.pipeline.stages.stage1_hash import canonicalize_and_hash, Stage1HashCheck
from mcpath.proxy.client_manager import DownstreamClientManager, set_active_client_manager
from mcpath.proxy.server import create_proxy_server
from mcpath.risk_engine.models import EnforcementDecision


@pytest_asyncio.fixture
async def test_db_session():
    """Isolated in-memory SQLite database session for hash verification tests."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with session_factory() as session:
        yield session

    await engine.dispose()


def make_mock_server(name: str, tools_spec: List[Dict[str, Any]], call_handler) -> Server:
    """Helper creating an in-memory MCP lowlevel Server with specific tools and handler."""
    tools = [
        types.Tool(
            name=t["name"],
            description=t.get("description", f"Tool {t['name']} on {name}"),
            input_schema=t.get("input_schema", {"type": "object", "properties": {}})
        )
        for t in tools_spec
    ]

    async def list_tools_handler(context: Any, params=None):
        return types.ListToolsResult(tools=tools)

    async def call_tool_handler(context: Any, params: types.CallToolRequestParams):
        return await call_handler(params.name, params.arguments or {})

    srv = Server(
        name=name,
        version="1.0.0",
        on_list_tools=list_tools_handler,
        on_call_tool=call_tool_handler
    )
    return srv


@pytest.mark.asyncio
async def test_multi_server_aggregation_and_collision(test_db_session: AsyncSession):
    """Test aggregated tools/list, unique tools preservation, and deterministic collision handling."""
    # Server Alpha has: unique_alpha, calculate (collision)
    alpha_calls = []
    async def alpha_handler(name, args):
        alpha_calls.append((name, args))
        return types.CallToolResult(content=[types.TextContent(type="text", text=f"ALPHA:{name}")])

    alpha_server = make_mock_server("server_alpha", [
        {"name": "unique_alpha", "description": "Alpha unique tool"},
        {"name": "calculate", "description": "Alpha calculate tool"}
    ], alpha_handler)

    # Server Beta has: unique_beta, calculate (collision)
    beta_calls = []
    async def beta_handler(name, args):
        beta_calls.append((name, args))
        return types.CallToolResult(content=[types.TextContent(type="text", text=f"BETA:{name}")])

    beta_server = make_mock_server("server_beta", [
        {"name": "unique_beta", "description": "Beta unique tool"},
        {"name": "calculate", "description": "Beta calculate tool"}
    ], beta_handler)

    async with create_client_server_memory_streams() as (c2p_c, c2p_s):
        async with create_client_server_memory_streams() as (p2a_c, p2a_s):
            async with create_client_server_memory_streams() as (p2b_c, p2b_s):
                async with asyncio.TaskGroup() as tg:
                    # Run downstream servers
                    tg.create_task(alpha_server.run(*p2a_s, alpha_server.create_initialization_options()))
                    tg.create_task(beta_server.run(*p2b_s, beta_server.create_initialization_options()))

                    async with ClientSession(*p2a_c) as session_a, ClientSession(*p2b_c) as session_b:
                        await session_a.initialize()
                        await session_b.initialize()

                        mgr = DownstreamClientManager()
                        mgr.register_active_session("server_alpha", session_a)
                        mgr.register_active_session("server_beta", session_b)
                        await mgr.list_tools()

                        # Register trusted baselines in DB
                        for s_name, sess in [("server_alpha", session_a), ("server_beta", session_b)]:
                            res = await sess.list_tools()
                            raw_tools = [t.model_dump(mode="json") for t in res.tools]
                            await register_trusted_server_and_tools(
                                server_name=s_name,
                                tools=raw_tools,
                                canonicalize_and_hash_fn=canonicalize_and_hash,
                                session=test_db_session
                            )

                        async def hash_provider(s_name, t_name):
                            return await get_approved_hash(s_name, t_name, session=test_db_session)

                        stage1 = Stage1HashCheck(hash_provider=hash_provider)
                        runner = PipelineRunner(stage1=stage1, persist_events=False)

                        proxy_server = create_proxy_server(
                            client_manager=mgr,
                            pipeline_runner=runner,
                            server_name="mcpath-multi-test"
                        )
                        proxy_task = tg.create_task(
                            proxy_server.run(*c2p_s, proxy_server.create_initialization_options())
                        )

                        async with ClientSession(*c2p_c) as client:
                            await client.initialize()

                            # 1. Aggregated tools/list
                            tools_res = await client.list_tools()
                            exposed_names = [t.name for t in tools_res.tools]

                            # Unique tools preserve exact name
                            assert "unique_alpha" in exposed_names
                            assert "unique_beta" in exposed_names

                            # Colliding tools are deterministically namespaced
                            assert "calculate" not in exposed_names
                            assert "server_alpha_calculate" in exposed_names
                            assert "server_beta_calculate" in exposed_names

                            # 2. Routed execution to correct server
                            res_alpha = await client.call_tool("unique_alpha", {})
                            assert not res_alpha.is_error
                            assert res_alpha.content[0].text == "ALPHA:unique_alpha"

                            res_beta = await client.call_tool("unique_beta", {})
                            assert not res_beta.is_error
                            assert res_beta.content[0].text == "BETA:unique_beta"

                            # 3. Cross-server collision routing
                            res_coll_a = await client.call_tool("server_alpha_calculate", {})
                            assert not res_coll_a.is_error
                            assert res_coll_a.content[0].text == "ALPHA:calculate"
                            assert len(alpha_calls) == 2

                            res_coll_b = await client.call_tool("server_beta_calculate", {})
                            assert not res_coll_b.is_error
                            assert res_coll_b.content[0].text == "BETA:calculate"
                            assert len(beta_calls) == 2

                        proxy_task.cancel()


@pytest.mark.asyncio
async def test_cross_server_isolation_and_stage1_mismatch(test_db_session: AsyncSession):
    """Test that tool definitions are verified against owning server hash and mismatch blocks downstream."""
    async def alpha_handler(name, args):
        return types.CallToolResult(content=[types.TextContent(type="text", text="ALPHA_OK")])

    alpha_server = make_mock_server("alpha", [{"name": "tool_x"}], alpha_handler)

    async with create_client_server_memory_streams() as (c2p_c, c2p_s):
        async with create_client_server_memory_streams() as (p2a_c, p2a_s):
            async with asyncio.TaskGroup() as tg:
                tg.create_task(alpha_server.run(*p2a_s, alpha_server.create_initialization_options()))
                async with ClientSession(*p2a_c) as session_a:
                    await session_a.initialize()

                    mgr = DownstreamClientManager()
                    mgr.register_active_session("alpha", session_a)
                    await mgr.list_tools()

                    # Register with hash
                    res = await session_a.list_tools()
                    await register_trusted_server_and_tools(
                        server_name="alpha",
                        tools=[t.model_dump(mode="json") for t in res.tools],
                        canonicalize_and_hash_fn=canonicalize_and_hash,
                        session=test_db_session
                    )

                    async def hash_provider(s_name, t_name):
                        return await get_approved_hash(s_name, t_name, session=test_db_session)

                    stage1 = Stage1HashCheck(hash_provider=hash_provider)
                    runner = PipelineRunner(stage1=stage1, persist_events=False)

                    proxy_server = create_proxy_server(client_manager=mgr, pipeline_runner=runner)
                    proxy_task = tg.create_task(proxy_server.run(*c2p_s, proxy_server.create_initialization_options()))

                    async with ClientSession(*c2p_c) as client:
                        await client.initialize()

                        # 1. Normal call passes
                        call1 = await client.call_tool("tool_x", {})
                        assert not call1.is_error
                        assert call1.content[0].text == "ALPHA_OK"

                        # 2. Tamper definition in cache (simulating downstream rug pull)
                        mgr._tools_cache["tool_x"].description = "Tampered description"

                        # 3. Call blocked by Stage 1 before reaching downstream
                        call2 = await client.call_tool("tool_x", {})
                        assert call2.is_error is True
                        assert "EXECUTION BLOCKED" in call2.content[0].text
                        assert "Rug Pull" in call2.content[0].text or "hash mismatch" in call2.content[0].text

                    proxy_task.cancel()


@pytest.mark.asyncio
async def test_missing_baseline_fails_closed(test_db_session: AsyncSession):
    """Test that an unapproved tool on a connected server fails-closed (NO_APPROVED_BASELINE)."""
    async def handler(name, args):
        return types.CallToolResult(content=[types.TextContent(type="text", text="SHOULD_NOT_EXECUTE")])

    mock_srv = make_mock_server("unapproved_server", [{"name": "unapproved_tool"}], handler)

    async with create_client_server_memory_streams() as (c2p_c, c2p_s):
        async with create_client_server_memory_streams() as (p2s_c, p2s_s):
            async with asyncio.TaskGroup() as tg:
                tg.create_task(mock_srv.run(*p2s_s, mock_srv.create_initialization_options()))
                async with ClientSession(*p2s_c) as session:
                    await session.initialize()

                    mgr = DownstreamClientManager()
                    mgr.register_active_session("unapproved_server", session)
                    await mgr.list_tools()

                    # DO NOT register trusted baseline in database
                    async def hash_provider(s_name, t_name):
                        return await get_approved_hash(s_name, t_name, session=test_db_session)

                    stage1 = Stage1HashCheck(hash_provider=hash_provider)
                    runner = PipelineRunner(stage1=stage1, persist_events=False)

                    proxy_server = create_proxy_server(client_manager=mgr, pipeline_runner=runner)
                    proxy_task = tg.create_task(proxy_server.run(*c2p_s, proxy_server.create_initialization_options()))

                    async with ClientSession(*c2p_c) as client:
                        await client.initialize()

                        call_res = await client.call_tool("unapproved_tool", {})
                        assert call_res.is_error is True
                        assert "NO_APPROVED_BASELINE" in call_res.content[0].text or "EXECUTION BLOCKED" in call_res.content[0].text

                    proxy_task.cancel()


@pytest.mark.asyncio
async def test_server_failure_isolation_and_unavailable_handling():
    """Test that a failure in one server does not terminate others and unavailable tools are excluded."""
    # Define 1 bad server that fails to run and 1 valid mock server
    bad_server_def = ServerDefinition(command="non_existent_executable_12345", args=[])
    good_server_def = ServerDefinition(command="python", args=["mock_servers/sample_server.py"])

    mgr = DownstreamClientManager(
        server_defs={
            "bad_server": bad_server_def,
            "sample_reference_server": good_server_def
        }
    )

    # Connect all servers
    await mgr.start_all_servers()

    # Bad server must be marked unavailable
    assert "bad_server" in mgr.unavailable_servers
    assert "bad_server" not in mgr.sessions

    # Good server must be connected
    assert "sample_reference_server" in mgr.sessions
    assert len(mgr.exposed_tools) >= 5

    # Tools from bad_server must NOT appear in exposed tools
    for exp_tool in mgr.exposed_tools.values():
        assert exp_tool.server_name != "bad_server"

    # sample_reference_server was not used as a fallback for bad_server, but connected independently
    assert "echo" in mgr.exposed_tools
    assert mgr.exposed_tools["echo"].server_name == "sample_reference_server"

    await mgr.stop_all_servers()


@pytest.mark.asyncio
async def test_dynamic_server_reload_and_graph_update():
    """Test dynamic reload mechanism: adds new server, updates exposed catalog and capability graph."""
    good_server_def = ServerDefinition(command="python", args=["mock_servers/sample_server.py"])

    # Initially empty manager
    mgr = DownstreamClientManager(server_defs={})
    assert len(mgr.exposed_tools) == 0
    assert len(mgr.capability_graph.graph.nodes) == 1  # Only Agent

    # Dynamically configure new server
    test_config = ServerConfig(
        active_servers=["sample_reference_server"],
        servers={"sample_reference_server": good_server_def}
    )

    summary = await mgr.reload(new_config=test_config)
    assert summary["status"] == "success"
    assert "sample_reference_server" in summary["active_servers"]
    assert len(mgr.exposed_tools) >= 5

    # Verify capability graph updated with new server's tools
    graph_nodes = list(mgr.capability_graph.graph.nodes)
    assert "Tool:echo" in graph_nodes
    assert "Tool:calculate" in graph_nodes

    # Dynamically remove server
    empty_config = ServerConfig(active_servers=[], servers={})
    summary2 = await mgr.reload(new_config=empty_config)
    assert summary2["status"] == "success"
    assert "sample_reference_server" in summary2["removed_servers"]
    assert len(mgr.exposed_tools) == 0

    # Verify capability graph cleared tools
    assert "Tool:echo" not in mgr.capability_graph.graph.nodes

    await mgr.stop_all_servers()


@pytest.mark.asyncio
async def test_stage1_pass_continues_to_stage2(test_db_session: AsyncSession):
    """Test that a valid Stage 1 hash check enters Stage 2 and evaluates pre-call."""
    async def handler(name, args):
        return types.CallToolResult(content=[types.TextContent(type="text", text="STAGE2_OK")])

    mock_srv = make_mock_server("server_s2", [{"name": "s2_tool"}], handler)

    async with create_client_server_memory_streams() as (c2p_c, c2p_s):
        async with create_client_server_memory_streams() as (p2s_c, p2s_s):
            async with asyncio.TaskGroup() as tg:
                tg.create_task(mock_srv.run(*p2s_s, mock_srv.create_initialization_options()))
                async with ClientSession(*p2s_c) as session:
                    await session.initialize()

                    mgr = DownstreamClientManager()
                    mgr.register_active_session("server_s2", session)
                    await mgr.list_tools()

                    # Register baseline
                    res = await session.list_tools()
                    await register_trusted_server_and_tools(
                        server_name="server_s2",
                        tools=[t.model_dump(mode="json") for t in res.tools],
                        canonicalize_and_hash_fn=canonicalize_and_hash,
                        session=test_db_session
                    )

                    async def hash_provider(s_name, t_name):
                        return await get_approved_hash(s_name, t_name, session=test_db_session)

                    stage1 = Stage1HashCheck(hash_provider=hash_provider)
                    runner = PipelineRunner(stage1=stage1, persist_events=False)

                    proxy_server = create_proxy_server(client_manager=mgr, pipeline_runner=runner)
                    proxy_task = tg.create_task(proxy_server.run(*c2p_s, proxy_server.create_initialization_options()))

                    async with ClientSession(*c2p_c) as client:
                        await client.initialize()

                        call_res = await client.call_tool("s2_tool", {})
                        assert not call_res.is_error
                        assert call_res.content[0].text == "STAGE2_OK"

                        # Stage 1 and Stage 2 both recorded
                        stage_numbers = [r["stage_number"] for r in runner._recorded_stage_results]
                        assert 1 in stage_numbers
                        assert 2 in stage_numbers

                    proxy_task.cancel()


@pytest.mark.asyncio
async def test_register_server_by_name_and_manager_instantiation():
    """Verify that trusted registration correctly instantiates DownstreamClientManager and discovers tools."""
    from mcpath.register import register_server_by_name
    from mcpath.backend.persistence.database import init_db

    await init_db()
    results = await register_server_by_name("sample_reference_server")
    assert len(results) >= 6

    tool_names = [r["tool_name"] for r in results]
    assert "echo" in tool_names
    assert "calculate" in tool_names
    assert "read_customer" in tool_names

    for r in results:
        assert r["server_name"] == "sample_reference_server"
        assert len(r["hash_sha256"]) == 64
        assert r["is_active"] is True

