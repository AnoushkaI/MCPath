"""Focused tests for ServerDB.is_active lifecycle during server reload.

Verifies:
1. Configured active server -> is_active = True
2. Removed server -> is_active = False
3. Restored server -> is_active = True
4. Historical ServerDB rows are NEVER deleted
5. Approved hashes and tools remain intact in database
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from mcpath.backend.app import app
from mcpath.backend.persistence.database import get_db
from mcpath.backend.persistence.models import Base, ServerDB, ToolDB, ApprovedHashDB
from mcpath.config.settings import settings, Settings, ServerConfig, ServerDefinition


@pytest_asyncio.fixture
async def reload_test_session():
    """In-memory SQLite database session isolated for reload lifecycle testing."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with session_factory() as session:
        yield session

    try:
        await engine.dispose()
    except Exception:
        pass


@pytest.mark.asyncio
async def test_server_reload_is_active_lifecycle(reload_test_session: AsyncSession, monkeypatch):
    """Test full lifecycle of server addition, removal, and restoration in ServerDB."""
    from mcpath.core.exceptions import DownstreamConnectionError

    async def mock_send_control(*args, **kwargs):
        raise DownstreamConnectionError("Proxy offline for test")

    monkeypatch.setattr("mcpath.backend.routes.servers.send_proxy_control_command", mock_send_control)

    # 1. Override FastAPI get_db dependency to use the isolated test session
    async def override_get_db():
        yield reload_test_session

    app.dependency_overrides[get_db] = override_get_db

    # 2. Seed initial ServerDB, ToolDB, and ApprovedHashDB records
    srv_fs = ServerDB(name="filesystem", command="cmd", args=["/c", "npx"], is_active=True)
    srv_git = ServerDB(name="git", command="uvx", args=["mcp-server-git"], is_active=True)
    srv_pg = ServerDB(name="postgres-mcp", command="cmd", args=["/c", "npx"], is_active=True)
    reload_test_session.add_all([srv_fs, srv_git, srv_pg])
    await reload_test_session.flush()

    # Seed tools and approved hash for git
    tool_git = ToolDB(
        server_id=srv_git.id,
        server_name="git",
        name="git_status",
        description="Shows working tree status",
        input_schema={"type": "object", "properties": {}}
    )
    reload_test_session.add(tool_git)
    await reload_test_session.flush()

    hash_git = ApprovedHashDB(
        tool_id=tool_git.id,
        server_name="git",
        tool_name="git_status",
        hash_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        canonical_json="{}",
        approved_by="admin:trusted_registration",
        is_active=True
    )
    reload_test_session.add(hash_git)
    await reload_test_session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # -------------------------------------------------------------------
        # Phase 1: All servers active in configuration -> All is_active = True
        # -------------------------------------------------------------------
        current_config = ServerConfig(
            active_server="filesystem",
            active_servers=["filesystem", "git", "postgres-mcp"],
            servers={
                "filesystem": ServerDefinition(command="cmd", args=[]),
                "git": ServerDefinition(command="uvx", args=[]),
                "postgres-mcp": ServerDefinition(command="cmd", args=[])
            }
        )
        monkeypatch.setattr(
            Settings,
            "get_server_config",
            lambda self: current_config
        )

        res_reload_1 = await client.post("/api/servers/reload")
        assert res_reload_1.status_code == 200

        res_get_1 = await client.get("/api/servers?format=dict")
        assert res_get_1.status_code == 200
        reg_1 = {s["name"]: s for s in res_get_1.json()["registered_in_db"]}
        assert reg_1["git"]["is_active"] is True
        assert reg_1["filesystem"]["is_active"] is True
        assert reg_1["postgres-mcp"]["is_active"] is True

        # -------------------------------------------------------------------
        # Phase 2: "git" removed from server_config.json -> git is_active = False
        # -------------------------------------------------------------------
        current_config = ServerConfig(
            active_server="filesystem",
            active_servers=["filesystem", "postgres-mcp"],
            servers={
                "filesystem": ServerDefinition(command="cmd", args=[]),
                "postgres-mcp": ServerDefinition(command="cmd", args=[])
            }
        )

        res_reload_2 = await client.post("/api/servers/reload")
        assert res_reload_2.status_code == 200

        res_get_2 = await client.get("/api/servers?format=dict")
        assert res_get_2.status_code == 200
        data_2 = res_get_2.json()

        # configured_servers must NOT contain git
        assert "git" not in data_2["configured_servers"]

        # registered_in_db must STILL contain git, but with is_active = False
        reg_2 = {s["name"]: s for s in data_2["registered_in_db"]}
        assert "git" in reg_2, "Historical git ServerDB record must be retained in registered_in_db"
        assert reg_2["git"]["is_active"] is False, "Removed server must have is_active = False"
        assert reg_2["filesystem"]["is_active"] is True
        assert reg_2["postgres-mcp"]["is_active"] is True

        # -------------------------------------------------------------------
        # Phase 4 & 5: Invariants: Records and Hashes NEVER deleted
        # -------------------------------------------------------------------
        # Verify ServerDB row for git was NOT deleted
        stmt_srv = select(ServerDB).where(ServerDB.name == "git")
        git_db_row = (await reload_test_session.execute(stmt_srv)).scalar_one_or_none()
        assert git_db_row is not None
        assert git_db_row.is_active is False
        assert git_db_row.command == "uvx"

        # Verify ToolDB and ApprovedHashDB records for git remain completely intact
        stmt_tool = select(ToolDB).where(ToolDB.server_name == "git")
        git_tools = (await reload_test_session.execute(stmt_tool)).scalars().all()
        assert len(git_tools) == 1
        assert git_tools[0].name == "git_status"

        stmt_hash = select(ApprovedHashDB).where(ApprovedHashDB.server_name == "git")
        git_hashes = (await reload_test_session.execute(stmt_hash)).scalars().all()
        assert len(git_hashes) == 1
        assert git_hashes[0].is_active is True
        assert git_hashes[0].hash_sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        # -------------------------------------------------------------------
        # Phase 3: "git" restored to server_config.json -> git is_active = True
        # -------------------------------------------------------------------
        current_config = ServerConfig(
            active_server="filesystem",
            active_servers=["filesystem", "git", "postgres-mcp"],
            servers={
                "filesystem": ServerDefinition(command="cmd", args=[]),
                "git": ServerDefinition(command="uvx", args=[]),
                "postgres-mcp": ServerDefinition(command="cmd", args=[])
            }
        )

        res_reload_3 = await client.post("/api/servers/reload")
        assert res_reload_3.status_code == 200

        res_get_3 = await client.get("/api/servers?format=dict")
        assert res_get_3.status_code == 200
        reg_3 = {s["name"]: s for s in res_get_3.json()["registered_in_db"]}
        assert reg_3["git"]["is_active"] is True, "Restored server must have is_active = True again"
        assert reg_3["filesystem"]["is_active"] is True
        assert reg_3["postgres-mcp"]["is_active"] is True

    app.dependency_overrides.clear()
