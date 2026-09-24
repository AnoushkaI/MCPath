"""Comprehensive tests proving MCPath server-state synchronization between config and database.

Verifies:
1. Deactivate changes BOTH config (active_servers) and PostgreSQL state (is_active = False),
   while preserving historical tools, hashes, and trust history.
2. Activate changes BOTH config (active_servers) and PostgreSQL state (is_active = True),
   restoring tools/graph while preserving existing approved baselines (never re-baselined).
3. Startup / restart / reload reconciles PostgreSQL is_active with config.active_servers as authoritative.
4. Trust changes trust state and approved hashes only, and does NOT alter active/inactive state.
5. Add creates UNTRUSTED state consistently (no approved baselines), and only adds to active_servers on success.
6. Legacy inactive sample_reference_server is reconciled to is_active = False while preserving TRUSTED status and hashes.
"""

import asyncio
from typing import Any, Dict, List, Optional
import pytest
import pytest_asyncio
from mcp.client._memory import create_client_server_memory_streams
from mcp.client.session import ClientSession
from mcp.server.lowlevel import Server
import mcp.types as types
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from mcpath.backend.persistence.models import Base, ServerDB, ToolDB, ApprovedHashDB
from mcpath.backend.persistence.database import (
    set_engine,
    reconcile_server_active_states,
    set_server_active_state,
    register_trusted_server_and_tools,
    save_discovered_tools,
    get_server_db_status,
)
from mcpath.config.settings import Settings, ServerConfig, ServerDefinition
from mcpath.pipeline.stages.stage1_hash import canonicalize_and_hash
from mcpath.proxy.client_manager import (
    DownstreamClientManager,
    DownstreamServerState,
    save_server_config_file,
)


@pytest_asyncio.fixture
async def sync_db_session():
    """Isolated in-memory SQLite database session for state synchronization testing."""
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


def make_mock_server(name: str, tool_names: List[str]) -> Server:
    """Create in-memory MCP lowlevel Server for testing."""
    tools = [
        types.Tool(
            name=t,
            description=f"Description of {t}",
            input_schema={"type": "object", "properties": {"arg": {"type": "string"}}}
        )
        for t in tool_names
    ]

    async def list_tools_handler(context: Any, params=None):
        return types.ListToolsResult(tools=tools)

    async def call_tool_handler(context: Any, params: types.CallToolRequestParams):
        return types.CallToolResult(content=[types.TextContent(type="text", text=f"SUCCESS:{params.name}")])

    return Server(name=name, version="1.0.0", on_list_tools=list_tools_handler, on_call_tool=call_tool_handler)


@pytest.mark.asyncio
async def test_deactivate_changes_both_config_and_db_state(sync_db_session: AsyncSession, monkeypatch):
    """Test 1: Deactivate changes BOTH config (active_servers) and PostgreSQL state (is_active=False).

    Preserves historical tools, hashes, and trust history in the database.
    """
    server_name = "test_worker"
    s_def = ServerDefinition(command="python", args=["worker.py"])

    # 1. Config has server_name in active_servers
    test_config = ServerConfig(
        active_server=server_name,
        active_servers=[server_name, "other_server"],
        servers={
            server_name: s_def,
            "other_server": ServerDefinition(command="python", args=[])
        }
    )
    saved_configs = []
    monkeypatch.setattr(Settings, "get_server_config", lambda self: test_config)
    monkeypatch.setattr("mcpath.proxy.client_manager.save_server_config_file", lambda cfg: saved_configs.append(cfg))

    # 2. Seed ServerDB, ToolDB, ApprovedHashDB with an active trusted baseline
    srv_rec = ServerDB(name=server_name, command="python", args=["worker.py"], is_active=True, trust_status="TRUSTED")
    sync_db_session.add(srv_rec)
    await sync_db_session.flush()

    tool_rec = ToolDB(server_id=srv_rec.id, server_name=server_name, name="run_task", description="Executes task", input_schema={})
    sync_db_session.add(tool_rec)
    await sync_db_session.flush()

    hash_rec = ApprovedHashDB(
        tool_id=tool_rec.id,
        server_name=server_name,
        tool_name="run_task",
        hash_sha256="abc123hash",
        canonical_json="{}",
        approved_by="admin:test",
        is_active=True
    )
    sync_db_session.add(hash_rec)
    await sync_db_session.commit()

    # Verify initial active state in DB
    db_stat_initial = await get_server_db_status(server_name=server_name, session=sync_db_session)
    assert db_stat_initial[0]["is_active"] is True
    assert server_name in test_config.active_servers

    # 3. Deactivate server
    mgr = DownstreamClientManager(server_defs={server_name: s_def})
    deact_res = await mgr.deactivate_server(server_name, session=sync_db_session)

    # 4. Verify config state: server removed from active_servers
    assert server_name not in test_config.active_servers
    assert "other_server" in test_config.active_servers

    # 5. Verify database state: ServerDB.is_active is False
    stmt = select(ServerDB).where(ServerDB.name == server_name)
    server_after = (await sync_db_session.execute(stmt)).scalars().first()
    assert server_after.is_active is False

    # 6. Verify historical records preserved: ToolDB and ApprovedHashDB intact
    stmt_tools = select(ToolDB).where(ToolDB.server_name == server_name)
    tools_after = (await sync_db_session.execute(stmt_tools)).scalars().all()
    assert len(tools_after) == 1
    assert tools_after[0].name == "run_task"

    stmt_hashes = select(ApprovedHashDB).where(ApprovedHashDB.server_name == server_name)
    hashes_after = (await sync_db_session.execute(stmt_hashes)).scalars().all()
    assert len(hashes_after) == 1
    assert hashes_after[0].hash_sha256 == "abc123hash"

    # Status response check
    assert deact_res["active"] is False
    assert deact_res["is_active"] is False
    assert deact_res["connected"] is False


@pytest.mark.asyncio
async def test_activate_changes_both_config_and_db_state(sync_db_session: AsyncSession, monkeypatch):
    """Test 2: Activate changes BOTH config (active_servers) and PostgreSQL state (is_active=True).

    Preserves existing baseline and never creates a new baseline.
    """
    server_name = "test_worker"
    s_def = ServerDefinition(command="python", args=["worker.py"])

    # 1. Config has server in servers, but NOT in active_servers
    test_config = ServerConfig(
        active_server="other_server",
        active_servers=["other_server"],
        servers={
            server_name: s_def,
            "other_server": ServerDefinition(command="python", args=[])
        }
    )
    saved_configs = []
    monkeypatch.setattr(Settings, "get_server_config", lambda self: test_config)
    monkeypatch.setattr("mcpath.proxy.client_manager.save_server_config_file", lambda cfg: saved_configs.append(cfg))

    # 2. Seed ServerDB with is_active = False and existing ApprovedHashDB
    srv_rec = ServerDB(name=server_name, command="python", args=["worker.py"], is_active=False, trust_status="TRUSTED")
    sync_db_session.add(srv_rec)
    await sync_db_session.flush()

    tool_rec = ToolDB(server_id=srv_rec.id, server_name=server_name, name="run_task", description="Executes task", input_schema={})
    sync_db_session.add(tool_rec)
    await sync_db_session.flush()

    hash_rec = ApprovedHashDB(
        tool_id=tool_rec.id,
        server_name=server_name,
        tool_name="run_task",
        hash_sha256="original_approved_hash",
        canonical_json="{}",
        approved_by="admin:original",
        is_active=True
    )
    sync_db_session.add(hash_rec)
    await sync_db_session.commit()

    # 3. Setup mock server connection
    mock_server = make_mock_server(server_name, ["run_task"])
    async with create_client_server_memory_streams() as (p2s_c, p2s_s):
        async with asyncio.TaskGroup() as tg:
            tg.create_task(mock_server.run(*p2s_s, mock_server.create_initialization_options()))
            async with ClientSession(*p2s_c) as session:
                await session.initialize()

                mgr = DownstreamClientManager(server_defs={server_name: s_def})
                # Mock connect_server to use initialized session
                async def mock_connect(name):
                    tools_res = await session.list_tools()
                    tools_map = {t.name: t for t in tools_res.tools}
                    mgr.servers_state[name] = DownstreamServerState(
                        server_name=name,
                        server_def=s_def,
                        session=session,
                        is_connected=True,
                        tools=tools_map
                    )
                    mgr.sessions[name] = session
                    return True

                monkeypatch.setattr(mgr, "connect_server", mock_connect)

                # 4. Activate server
                act_res = await mgr.activate_server(server_name, session=sync_db_session)

                # 5. Verify config: server_name added to active_servers
                assert server_name in test_config.active_servers

                # 6. Verify database: ServerDB.is_active is True
                stmt = select(ServerDB).where(ServerDB.name == server_name)
                server_after = (await sync_db_session.execute(stmt)).scalars().first()
                assert server_after.is_active is True

                # 7. Verify existing baseline preserved (never silently replaced)
                stmt_hashes = select(ApprovedHashDB).where(ApprovedHashDB.server_name == server_name)
                hashes_after = (await sync_db_session.execute(stmt_hashes)).scalars().all()
                assert len(hashes_after) == 1
                assert hashes_after[0].hash_sha256 == "original_approved_hash"

                # Status response check
                assert act_res["active"] is True
                assert act_res["is_active"] is True
                assert act_res["connected"] is True


@pytest.mark.asyncio
async def test_restart_reload_reconciles_db_with_config(sync_db_session: AsyncSession):
    """Test 3: Startup / restart / reload reconciles PostgreSQL is_active with config.active_servers as authoritative."""
    # Seed DB with out-of-sync state:
    # server_a is False in DB but should be active
    # server_b is True in DB but should be inactive
    # server_c is True in DB and should remain active
    srv_a = ServerDB(name="server_a", command="python", args=[], is_active=False)
    srv_b = ServerDB(name="server_b", command="python", args=[], is_active=True)
    srv_c = ServerDB(name="server_c", command="python", args=[], is_active=True)
    sync_db_session.add_all([srv_a, srv_b, srv_c])
    await sync_db_session.commit()

    # Authoritative configuration
    active_servers = ["server_a", "server_c"]
    configured_servers = ["server_a", "server_b", "server_c"]

    # Run reconciliation
    reconciled = await reconcile_server_active_states(
        active_servers=active_servers,
        configured_servers=configured_servers,
        session=sync_db_session
    )

    assert reconciled["server_a"] is True
    assert reconciled["server_b"] is False
    assert reconciled["server_c"] is True

    # Check database records
    stmt = select(ServerDB)
    servers = {s.name: s for s in (await sync_db_session.execute(stmt)).scalars().all()}
    assert servers["server_a"].is_active is True
    assert servers["server_b"].is_active is False
    assert servers["server_c"].is_active is True


@pytest.mark.asyncio
async def test_trust_does_not_alter_active_state(sync_db_session: AsyncSession, monkeypatch):
    """Test 4: Trust changes trust state and approved hashes only; must NOT change active/inactive state."""
    # Seed an inactive server
    srv_inactive = ServerDB(name="dormant_server", command="python", args=[], is_active=False, trust_status="UNTRUSTED")
    # Seed an active server
    srv_active = ServerDB(name="running_server", command="python", args=[], is_active=True, trust_status="UNTRUSTED")
    sync_db_session.add_all([srv_inactive, srv_active])
    await sync_db_session.flush()

    tools_dormant = [{"name": "tool_d", "description": "Dormant tool", "input_schema": {}}]
    tools_running = [{"name": "tool_r", "description": "Running tool", "input_schema": {}}]

    # Trust dormant server
    await register_trusted_server_and_tools(
        server_name="dormant_server",
        tools=tools_dormant,
        canonicalize_and_hash_fn=canonicalize_and_hash,
        session=sync_db_session
    )

    # Trust running server
    await register_trusted_server_and_tools(
        server_name="running_server",
        tools=tools_running,
        canonicalize_and_hash_fn=canonicalize_and_hash,
        session=sync_db_session
    )

    # Verify in DB:
    # dormant_server must STILL have is_active = False!
    stmt_d = select(ServerDB).where(ServerDB.name == "dormant_server")
    res_d = (await sync_db_session.execute(stmt_d)).scalars().first()
    assert res_d.trust_status == "TRUSTED"
    assert res_d.is_active is False, "Trusting an inactive server must NOT make it active!"

    # running_server must STILL have is_active = True!
    stmt_r = select(ServerDB).where(ServerDB.name == "running_server")
    res_r = (await sync_db_session.execute(stmt_r)).scalars().first()
    assert res_r.trust_status == "TRUSTED"
    assert res_r.is_active is True, "Trusting an active server must preserve active state!"


@pytest.mark.asyncio
async def test_add_creates_untrusted_state_consistently(sync_db_session: AsyncSession, monkeypatch):
    """Test 5: Add creates UNTRUSTED state consistently with NO approved baselines, and adds to active_servers only on success."""
    server_name = "newly_added_server"
    s_def = ServerDefinition(command="python", args=["new.py"])

    test_config = ServerConfig(
        active_server="existing",
        active_servers=["existing"],
        servers={"existing": ServerDefinition(command="python", args=[])}
    )
    saved_configs = []
    monkeypatch.setattr(Settings, "get_server_config", lambda self: test_config)
    monkeypatch.setattr("mcpath.proxy.client_manager.save_server_config_file", lambda cfg: saved_configs.append(cfg))

    mock_server = make_mock_server(server_name, ["do_something"])
    async with create_client_server_memory_streams() as (p2s_c, p2s_s):
        async with asyncio.TaskGroup() as tg:
            tg.create_task(mock_server.run(*p2s_s, mock_server.create_initialization_options()))
            async with ClientSession(*p2s_c) as session:
                await session.initialize()

                mgr = DownstreamClientManager(server_defs={})
                async def mock_connect(name):
                    tools_res = await session.list_tools()
                    tools_map = {t.name: t for t in tools_res.tools}
                    mgr.servers_state[name] = DownstreamServerState(
                        server_name=name,
                        server_def=s_def,
                        session=session,
                        is_connected=True,
                        tools=tools_map
                    )
                    mgr.sessions[name] = session
                    return True

                monkeypatch.setattr(mgr, "connect_server", mock_connect)

                # Add server
                add_res = await mgr.add_server(
                    name=server_name,
                    command="python",
                    args=["new.py"],
                    session=sync_db_session
                )

                # Verify: added to active_servers only upon successful connection
                assert server_name in test_config.active_servers
                assert add_res["active"] is True
                assert add_res["is_active"] is True
                assert add_res["trust_status"] == "UNTRUSTED"
                assert add_res["approved_tool_count"] == 0
                assert add_res["unapproved_tool_count"] == 1

                # Verify database: ServerDB has trust_status = UNTRUSTED
                stmt_s = select(ServerDB).where(ServerDB.name == server_name)
                db_srv = (await sync_db_session.execute(stmt_s)).scalars().first()
                assert db_srv.is_active is True
                assert db_srv.trust_status == "UNTRUSTED"

                # Verify database: ToolDB has tool, ApprovedHashDB has 0 rows
                stmt_t = select(ToolDB).where(ToolDB.server_name == server_name)
                db_tools = (await sync_db_session.execute(stmt_t)).scalars().all()
                assert len(db_tools) == 1

                stmt_h = select(ApprovedHashDB).where(ApprovedHashDB.server_name == server_name)
                db_hashes = (await sync_db_session.execute(stmt_h)).scalars().all()
                assert len(db_hashes) == 0, "New server must have NO approved baselines in ApprovedHashDB"

                # Verify connection failure case: must NOT add to active_servers and must persist is_active=False
                from mcpath.core.exceptions import DownstreamConnectionError
                async def mock_fail_connect(name):
                    mgr.servers_state[name] = DownstreamServerState(
                        server_name=name,
                        server_def=s_def,
                        is_connected=False,
                        error="Connection refused"
                    )
                    return False

                monkeypatch.setattr(mgr, "connect_server", mock_fail_connect)
                with pytest.raises(DownstreamConnectionError):
                    await mgr.add_server(
                        name="failed_server",
                        command="python",
                        args=["invalid.py"],
                        session=sync_db_session
                    )

                assert "failed_server" not in test_config.active_servers
                stmt_f = select(ServerDB).where(ServerDB.name == "failed_server")
                db_fail = (await sync_db_session.execute(stmt_f)).scalars().first()
                assert db_fail is not None
                assert db_fail.is_active is False


@pytest.mark.asyncio
async def test_legacy_inactive_sample_reference_server_reconciled(sync_db_session: AsyncSession, monkeypatch):
    """Test 6: Legacy inactive sample_reference_server is reconciled to is_active=False while preserving TRUSTED status and approved hashes."""
    legacy_name = "sample_reference_server"

    # 1. Seed legacy server in DB with is_active = True and approved hash
    srv_rec = ServerDB(name=legacy_name, command="python", args=["mock_servers/sample_server.py"], is_active=True, trust_status="TRUSTED")
    sync_db_session.add(srv_rec)
    await sync_db_session.flush()

    tool_rec = ToolDB(server_id=srv_rec.id, server_name=legacy_name, name="calculate", description="Calculator tool", input_schema={})
    sync_db_session.add(tool_rec)
    await sync_db_session.flush()

    hash_rec = ApprovedHashDB(
        tool_id=tool_rec.id,
        server_name=legacy_name,
        tool_name="calculate",
        hash_sha256="sample_calc_hash_12345",
        canonical_json="{}",
        approved_by="admin:trusted_registration",
        is_active=True
    )
    sync_db_session.add(hash_rec)
    await sync_db_session.commit()

    # 2. Config has sample_reference_server in servers, but NOT in active_servers
    test_config = ServerConfig(
        active_servers=["filesystem", "git", "postgres-mcp", "rugpull-test", "email-server"],
        servers={
            legacy_name: ServerDefinition(command="python", args=["mock_servers/sample_server.py"]),
            "filesystem": ServerDefinition(command="cmd", args=[]),
            "git": ServerDefinition(command="uvx", args=[]),
            "postgres-mcp": ServerDefinition(command="cmd", args=[]),
            "rugpull-test": ServerDefinition(command="python", args=[]),
            "email-server": ServerDefinition(command="python", args=[]),
        }
    )
    monkeypatch.setattr(Settings, "get_server_config", lambda self: test_config)

    # 3. Run startup reconciliation
    await reconcile_server_active_states(session=sync_db_session)

    # 4. Check DB status
    stmt = select(ServerDB).where(ServerDB.name == legacy_name)
    srv_after = (await sync_db_session.execute(stmt)).scalars().first()

    assert srv_after.is_active is False, "sample_reference_server must have is_active=False because it is absent from active_servers"
    assert srv_after.trust_status == "TRUSTED", "sample_reference_server must remain TRUSTED"

    stmt_h = select(ApprovedHashDB).where(ApprovedHashDB.server_name == legacy_name)
    hashes_after = (await sync_db_session.execute(stmt_h)).scalars().all()
    assert len(hashes_after) == 1
    assert hashes_after[0].hash_sha256 == "sample_calc_hash_12345", "Approved hash must not be regenerated or lost"
