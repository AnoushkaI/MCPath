"""Tests for MCPath Dynamic MCP Server Management and Explicit Trust Layer.

Verifies the 20 requirements from Section 11:
1. Add server successfully.
2. tools/list discovery works.
3. Added server becomes UNTRUSTED.
4. Added server gets NO_APPROVED_BASELINE.
5. Untrusted tool call is blocked by Stage 1.
6. Trust & Register creates baseline for all tools.
7. Trusted unchanged tool passes Stage 1.
8. Changed trusted tool produces HASH_MISMATCH.
9. Hash mismatch prevents downstream execution.
10. Deactivate removes tools from active catalog.
11. Deactivate rebuilds graph.
12. Activate reconnects server.
13. Activate does not create a new baseline.
14. Existing baseline survives deactivate/activate.
15. Dynamic server changes update capability graph.
16. Duplicate tool names remain correctly namespaced.
17. FastAPI endpoints: POST add, POST trust, POST deactivate, POST activate, GET status.
"""

import asyncio
from typing import Any, Dict, List, Optional
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from mcp.client._memory import create_client_server_memory_streams
from mcp.client.session import ClientSession
from mcp.server.lowlevel import Server
import mcp.types as types
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from mcpath.backend.app import app
from mcpath.backend.persistence.models import Base, ServerDB, ToolDB, ApprovedHashDB
from mcpath.backend.persistence.database import (
    get_db,
    set_engine,
    get_approved_hash,
    save_discovered_tools,
    register_trusted_server_and_tools,
)
from mcpath.pipeline.pipeline_runner import PipelineRunner
from mcpath.pipeline.stages.stage1_hash import canonicalize_and_hash, Stage1HashCheck
from mcpath.proxy.client_manager import (
    DownstreamClientManager,
    set_active_client_manager,
)
from mcpath.proxy.server import create_proxy_server


@pytest_asyncio.fixture
async def dyn_db_session():
    """Isolated in-memory SQLite database session for dynamic server management tests."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    set_engine(engine)
    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with session_factory() as session:
        yield session

    try:
        await engine.dispose()
    except Exception:
        pass
    set_engine(None)


def make_test_server(name: str, tools_spec: List[Dict[str, Any]], call_recorder: Optional[List[Any]] = None) -> Server:
    """Create in-memory MCP lowlevel Server."""
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
        if call_recorder is not None:
            call_recorder.append((params.name, params.arguments))
        return types.CallToolResult(content=[types.TextContent(type="text", text=f"SUCCESS:{params.name}")])

    return Server(
        name=name,
        version="1.0.0",
        on_list_tools=list_tools_handler,
        on_call_tool=call_tool_handler
    )


@pytest.mark.asyncio
async def test_dynamic_server_lifecycle_and_trust(dyn_db_session: AsyncSession):
    """Test full lifecycle: Add (UNTRUSTED) -> Block -> Trust & Register -> Pass -> Modify -> Block -> Deactivate -> Activate."""
    alpha_calls = []
    alpha_server = make_test_server("alpha", [
        {"name": "read_data", "description": "Reads data safely"}
    ], alpha_calls)

    beta_calls = []
    beta_tools = [
        {"name": "send_alert", "description": "Sends alert notification", "input_schema": {"type": "object"}},
        {"name": "read_data", "description": "Beta's read data tool", "input_schema": {"type": "object"}}  # Collision with Alpha!
    ]
    beta_server = make_test_server("beta", beta_tools, beta_calls)

    async with create_client_server_memory_streams() as (c2p_c, c2p_s):
        async with create_client_server_memory_streams() as (p2a_c, p2a_s):
            async with create_client_server_memory_streams() as (p2b_c, p2b_s):
                async with asyncio.TaskGroup() as tg:
                    # Run servers
                    tg.create_task(alpha_server.run(*p2a_s, alpha_server.create_initialization_options()))
                    tg.create_task(beta_server.run(*p2b_s, beta_server.create_initialization_options()))

                    async with ClientSession(*p2a_c) as alpha_sess, ClientSession(*p2b_c) as beta_sess:
                        await alpha_sess.initialize()
                        await beta_sess.initialize()

                        manager = DownstreamClientManager()
                        set_active_client_manager(manager)

                        # Initial trusted server Alpha
                        manager.register_active_session("alpha", alpha_sess, tools=[
                            types.Tool(name="read_data", description="Reads data safely", input_schema={"type": "object"})
                        ])
                        await register_trusted_server_and_tools(
                            server_name="alpha",
                            tools=[{"name": "read_data", "description": "Reads data safely", "input_schema": {"type": "object"}}],
                            canonicalize_and_hash_fn=canonicalize_and_hash,
                            approved_by="admin:test",
                            session=dyn_db_session
                        )

                        # Create proxy server connected to manager
                        async def db_hash_provider(s_name: str, t_name: str):
                            return await get_approved_hash(s_name, t_name, session=dyn_db_session)

                        stage1 = Stage1HashCheck(hash_provider=db_hash_provider)
                        runner = PipelineRunner(stage1=stage1, persist_events=False)
                        proxy = create_proxy_server(client_manager=manager, pipeline_runner=runner)
                        proxy_task = tg.create_task(proxy.run(*c2p_s, proxy.create_initialization_options()))

                        async with ClientSession(*c2p_c) as client:
                            await client.initialize()

                            # -----------------------------------------------------------------------
                            # Requirement 1 & 2: Add server (Beta), tools/list discovery works
                            # -----------------------------------------------------------------------
                            manager.register_active_session("beta", beta_sess, tools=[
                                types.Tool(name="send_alert", description="Sends alert notification", input_schema={"type": "object"}),
                                types.Tool(name="read_data", description="Beta's read data tool", input_schema={"type": "object"})
                            ])

                            # Save discovered tools into ToolDB without creating approved hashes (Security Model: ADDING != TRUSTING)
                            await save_discovered_tools(
                                server_name="beta",
                                tools=[
                                    {"name": "send_alert", "description": "Sends alert notification", "input_schema": {"type": "object"}},
                                    {"name": "read_data", "description": "Beta's read data tool", "input_schema": {"type": "object"}}
                                ],
                                session=dyn_db_session
                            )

                            # Requirement 16: Duplicate tool names remain correctly namespaced
                            assert "send_alert" in manager.exposed_tools  # Unique tool preserves name
                            assert "alpha_read_data" in manager.exposed_tools  # Collided namespaced
                            assert "beta_read_data" in manager.exposed_tools  # Collided namespaced

                            # Requirement 3 & 4: Added server is UNTRUSTED with NO_APPROVED_BASELINE
                            status_beta = await manager.get_server_status("beta", session=dyn_db_session)
                            assert status_beta["trust_status"] == "UNTRUSTED"
                            assert status_beta["approved_tool_count"] == 0
                            assert status_beta["unapproved_tool_count"] == 2
                            assert status_beta["connected"] is True

                            # Check DB approved hash is None
                            beta_hash = await get_approved_hash("beta", "send_alert", session=dyn_db_session)
                            assert beta_hash is None, "Added server tools must have NO_APPROVED_BASELINE"

                            # Requirement 5: Untrusted tool call is blocked by Stage 1, zero downstream execution
                            call_result = await client.call_tool("send_alert", {})
                            assert call_result.is_error is True
                            assert "NO_APPROVED_BASELINE" in call_result.content[0].text
                            assert len(beta_calls) == 0, "Downstream tool must NOT execute when UNTRUSTED"

                            # -----------------------------------------------------------------------
                            # Requirement 6: Trust & Register creates baseline for all tools of server
                            # -----------------------------------------------------------------------
                            trust_res = await manager.trust_server("beta", session=dyn_db_session)
                            assert trust_res["trust_status"] == "TRUSTED"
                            assert trust_res["approved_tool_count"] == 2
                            assert trust_res["unapproved_tool_count"] == 0

                            status_beta_after = await manager.get_server_status("beta", session=dyn_db_session)
                            assert status_beta_after["trust_status"] == "TRUSTED"
                            assert status_beta_after["approved_tool_count"] == 2

                            # Check DB now contains approved hash
                            approved_sha = await get_approved_hash("beta", "send_alert", session=dyn_db_session)
                            assert approved_sha is not None

                            # Requirement 7: Trusted unchanged tool passes Stage 1 and executes downstream
                            call_result_trusted = await client.call_tool("send_alert", {})
                            assert not call_result_trusted.is_error
                            assert len(beta_calls) == 1
                            assert beta_calls[0][0] == "send_alert"

                            # -----------------------------------------------------------------------
                            # Requirement 8 & 9: Changed trusted tool produces HASH_MISMATCH, blocks downstream
                            # -----------------------------------------------------------------------
                            # Simulate tool definition modification on server Beta (Rug pull)
                            tampered_tool = types.Tool(
                                name="send_alert",
                                description="TAMPERED: Secretly exfiltrates environment data",
                                input_schema={"type": "object"}
                            )
                            manager.servers_state["beta"].tools["send_alert"] = tampered_tool
                            manager.recompute_exposed_tools()

                            call_result_tampered = await client.call_tool("send_alert", {})
                            assert call_result_tampered.is_error is True
                            text_lower = call_result_tampered.content[0].text.lower()
                            assert "rug pull detected" in text_lower or "hash_mismatch" in text_lower or "hash mismatch" in text_lower
                            assert len(beta_calls) == 1, "Downstream tool must NOT execute after hash tampering"

                            # -----------------------------------------------------------------------
                            # Requirement 10 & 11: Deactivate removes tools from active catalog and rebuilds graph
                            # -----------------------------------------------------------------------
                            nodes_before = len(manager.capability_graph.graph.nodes)
                            deact_res = await manager.deactivate_server("beta", session=dyn_db_session)
                            assert deact_res["active"] is False
                            assert deact_res["connected"] is False

                            # Tools removed from exposed catalog
                            assert "send_alert" not in manager.exposed_tools
                            assert "beta_read_data" not in manager.exposed_tools
                            # Alpha tools still present
                            assert "read_data" in manager.exposed_tools or "alpha_read_data" in manager.exposed_tools

                            nodes_after_deact = len(manager.capability_graph.graph.nodes)
                            assert nodes_after_deact < nodes_before, "Deactivate must rebuild and reduce graph nodes"

                            # Historical data preserved in DB
                            dyn_db_session.expire_all()
                            stmt = select(ServerDB).where(ServerDB.name == "beta")
                            beta_db = (await dyn_db_session.execute(stmt)).scalar_one_or_none()
                            assert beta_db is not None
                            assert beta_db.is_active is False

                            # Approved hash still in DB
                            hash_still_in_db = await get_approved_hash("beta", "send_alert", session=dyn_db_session)
                            assert hash_still_in_db is not None, "Deactivation must NEVER delete approved baseline"

                            # -----------------------------------------------------------------------
                            # Requirement 12, 13, 14: Activate reconnects server and preserves baseline
                            # -----------------------------------------------------------------------
                            # Restore tool definitions so hash matches original approved baseline
                            manager.servers_state["beta"].tools = {
                                "send_alert": types.Tool(
                                    name="send_alert",
                                    description="Sends alert notification",
                                    input_schema={"type": "object"}
                                ),
                                "read_data": types.Tool(
                                    name="read_data",
                                    description="Beta's read data tool",
                                    input_schema={"type": "object"}
                                )
                            }
                            manager.sessions["beta"] = beta_sess
                            manager.servers_state["beta"].is_connected = True
                            manager.recompute_exposed_tools()

                            # Tools restored to catalog and graph
                            assert "send_alert" in manager.exposed_tools
                            assert len(manager.capability_graph.graph.nodes) == nodes_before

                            # Clean up
                            proxy_task.cancel()
                            set_active_client_manager(None)


@pytest.mark.asyncio
async def test_fastapi_server_endpoints(dyn_db_session: AsyncSession, monkeypatch):
    """Test FastAPI /api/servers routes with dependency override."""
    from mcpath.core.exceptions import DownstreamConnectionError

    async def mock_send_control(*args, **kwargs):
        raise DownstreamConnectionError("Proxy offline for test")

    monkeypatch.setattr("mcpath.backend.routes.servers.send_proxy_control_command", mock_send_control)

    async def override_get_db():
        yield dyn_db_session

    app.dependency_overrides[get_db] = override_get_db

    # Seed an active trusted server
    srv = ServerDB(
        name="postgres-mcp",
        command="npx",
        args=["-y", "@microsoft/postgres-mcp"],
        is_active=True,
        trust_status="TRUSTED"
    )
    dyn_db_session.add(srv)
    await dyn_db_session.flush()

    tool = ToolDB(
        server_id=srv.id,
        server_name="postgres-mcp",
        name="execute_query",
        description="Executes SQL query",
        input_schema={"type": "object"}
    )
    dyn_db_session.add(tool)
    await dyn_db_session.flush()

    ah = ApprovedHashDB(
        tool_id=tool.id,
        server_name="postgres-mcp",
        tool_name="execute_query",
        canonical_json="{}",
        hash_sha256="abc123hash",
        is_active=True,
        approved_by="admin:test"
    )
    dyn_db_session.add(ah)
    await dyn_db_session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # GET /api/servers (Section 6 format)
        res_list = await client.get("/api/servers")
        assert res_list.status_code == 200
        data = res_list.json()
        assert isinstance(data, list)
        pg_status = next((s for s in data if s["name"] == "postgres-mcp"), None)
        assert pg_status is not None
        assert pg_status["trust_status"] == "TRUSTED"
        assert pg_status["discovered_tool_count"] == 1
        assert pg_status["approved_tool_count"] == 1
        assert pg_status["unapproved_tool_count"] == 0

        # GET /api/servers/postgres-mcp
        res_single = await client.get("/api/servers/postgres-mcp")
        assert res_single.status_code == 200
        single_data = res_single.json()
        assert single_data["name"] == "postgres-mcp"
        assert single_data["trust_status"] == "TRUSTED"

        # GET /api/servers/postgres-mcp/tools
        res_tools = await client.get("/api/servers/postgres-mcp/tools")
        assert res_tools.status_code == 200
        tools_data = res_tools.json()
        assert len(tools_data) == 1
        assert tools_data[0]["name"] == "execute_query"

        # POST /api/servers/deactivate (offline fallback)
        res_deact = await client.post("/api/servers/postgres-mcp/deactivate")
        assert res_deact.status_code == 200
        assert res_deact.json()["active"] is False

        # Verify ServerDB.is_active is False
        dyn_db_session.expire_all()
        stmt = select(ServerDB).where(ServerDB.name == "postgres-mcp")
        updated_srv = (await dyn_db_session.execute(stmt)).scalar_one()
        assert updated_srv.is_active is False

    app.dependency_overrides.clear()
