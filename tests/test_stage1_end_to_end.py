"""End-to-end integration tests for Day 2.1 Stage 1 lifecycle.

Tests:
1. Register sample MCP server -> verify PostgreSQL contains its tools and approved hashes.
2. Call a tool with unchanged definition -> Stage 1 = PASS, downstream tool executes.
3. Change only the tool description -> Stage 1 = BLOCK, expected != observed, downstream NOT called.
4. Change input schema -> Stage 1 = BLOCK, downstream NOT called.
5. Reorder JSON object keys -> Same canonical hash and PASS.
6. Delete/remove approved hash from DB -> NO_APPROVED_BASELINE, BLOCK, downstream NOT called.
7. Run registration twice -> Idempotent, no duplicate server/tool/hash baseline records.
"""

import asyncio
import copy
import pytest
import pytest_asyncio
from mcp.client._memory import create_client_server_memory_streams
from mcp.client.session import ClientSession
from mock_servers.sample_server import app as sample_backend
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from mcpath.backend.persistence.models import Base, ServerDB, ToolDB, ApprovedHashDB, SecurityEventDB
from mcpath.backend.persistence.database import (
    register_trusted_server_and_tools,
    get_approved_hash,
)
from mcpath.config.settings import ServerDefinition
from mcpath.pipeline.pipeline_runner import PipelineRunner
from mcpath.pipeline.stages.stage1_hash import (
    canonicalize_and_hash,
    compute_tool_hash,
    Stage1HashCheck,
)
from mcpath.proxy.client_manager import DownstreamClientManager
from mcpath.proxy.server import create_proxy_server


@pytest_asyncio.fixture
async def e2e_db_session():
    """Create isolated test DB session with all 8 tables initialized."""
    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(test_engine, expire_on_commit=False, class_=AsyncSession)
    async with session_factory() as session:
        yield session

    await test_engine.dispose()


@pytest.mark.asyncio
async def test_1_trusted_registration_creates_baseline(e2e_db_session: AsyncSession):
    """Test 1: Trusted registration stores server, tools, and approved hashes in database."""
    server_name = "test_sample_server"
    sample_tools = [
        {
            "name": "echo",
            "description": "Echoes back the provided message",
            "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}}}
        },
        {
            "name": "calculate",
            "description": "Perform basic arithmetic calculations",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "operation": {"type": "string"},
                    "a": {"type": "number"},
                    "b": {"type": "number"}
                }
            }
        }
    ]

    synced = await register_trusted_server_and_tools(
        server_name=server_name,
        tools=sample_tools,
        canonicalize_and_hash_fn=canonicalize_and_hash,
        command="python",
        args=["mock_servers/sample_server.py"],
        env_vars={},
        approved_by="admin:trusted_registration",
        session=e2e_db_session
    )

    assert len(synced) == 2

    # Query DB tables
    servers = (await e2e_db_session.execute(select(ServerDB).where(ServerDB.name == server_name))).scalars().all()
    assert len(servers) == 1
    assert servers[0].name == server_name

    tools = (await e2e_db_session.execute(select(ToolDB).where(ToolDB.server_name == server_name))).scalars().all()
    assert len(tools) == 2
    tool_names = [t.name for t in tools]
    assert "echo" in tool_names
    assert "calculate" in tool_names

    hashes = (await e2e_db_session.execute(select(ApprovedHashDB).where(ApprovedHashDB.server_name == server_name))).scalars().all()
    assert len(hashes) == 2
    for h in hashes:
        assert h.is_active is True
        assert len(h.hash_sha256) == 64
        assert h.approved_by == "admin:trusted_registration"


@pytest.mark.asyncio
async def test_2_unchanged_definition_passes_and_executes(e2e_db_session: AsyncSession):
    """Test 2: Call tool with unchanged definition -> Stage 1 = PASS -> Downstream tool executes."""
    server_name = "sample_reference_server"

    async def db_hash_provider(s_name, t_name):
        return await get_approved_hash(s_name, t_name, session=e2e_db_session)

    # Start proxy and test client
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
                    client_manager = DownstreamClientManager(server_def, server_name=server_name)
                    
                    # 1. Discover tools and register trusted baseline in DB
                    tools_res = await client_manager.list_tools(downstream_session)
                    tools_data = [t.model_dump(mode="json") for t in tools_res.tools]
                    await register_trusted_server_and_tools(
                        server_name=server_name,
                        tools=tools_data,
                        canonicalize_and_hash_fn=canonicalize_and_hash,
                        session=e2e_db_session
                    )

                    stage1 = Stage1HashCheck(hash_provider=db_hash_provider)
                    runner = PipelineRunner(stage1=stage1, persist_events=False)
                    proxy_server = create_proxy_server(
                        client_manager=client_manager,
                        downstream_session=downstream_session,
                        pipeline_runner=runner,
                        server_name="mcpath-test-proxy"
                    )

                    proxy_task = tg.create_task(
                        proxy_server.run(*c2p_s, proxy_server.create_initialization_options())
                    )

                    async with ClientSession(*c2p_c) as client:
                        await client.initialize()

                        call_res = await client.call_tool("calculate", {"operation": "multiply", "a": 9, "b": 9})
                        assert not call_res.is_error
                        assert call_res.content[0].text == "81.0"

                    proxy_task.cancel()
                downstream_task.cancel()


@pytest.mark.asyncio
async def test_3_changed_description_rug_pull_blocks(e2e_db_session: AsyncSession):
    """Test 3: Change only tool description -> Stage 1 = BLOCK, downstream tool is NOT called."""
    server_name = "sample_reference_server"

    async def db_hash_provider(s_name, t_name):
        return await get_approved_hash(s_name, t_name, session=e2e_db_session)

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
                    client_manager = DownstreamClientManager(server_def, server_name=server_name)
                    tools_res = await client_manager.list_tools(downstream_session)
                    tools_data = [t.model_dump(mode="json") for t in tools_res.tools]
                    await register_trusted_server_and_tools(
                        server_name=server_name,
                        tools=tools_data,
                        canonicalize_and_hash_fn=canonicalize_and_hash,
                        session=e2e_db_session
                    )

                    # Attacker / modified downstream modifies description (Rug Pull)
                    client_manager._tools_cache["echo"].description = "Modified description with hidden jailbreak"

                    stage1 = Stage1HashCheck(hash_provider=db_hash_provider)
                    runner = PipelineRunner(stage1=stage1, persist_events=False)
                    proxy_server = create_proxy_server(
                        client_manager=client_manager,
                        downstream_session=downstream_session,
                        pipeline_runner=runner,
                        server_name="mcpath-test-proxy"
                    )

                    proxy_task = tg.create_task(
                        proxy_server.run(*c2p_s, proxy_server.create_initialization_options())
                    )

                    async with ClientSession(*c2p_c) as client:
                        await client.initialize()

                        call_res = await client.call_tool("echo", {"message": "test rug pull"})
                        assert call_res.is_error is True
                        assert "EXECUTION BLOCKED" in call_res.content[0].text
                        assert "Rug Pull" in call_res.content[0].text or "hash mismatch" in call_res.content[0].text

                    proxy_task.cancel()
                downstream_task.cancel()


@pytest.mark.asyncio
async def test_4_changed_schema_blocks(e2e_db_session: AsyncSession):
    """Test 4: Change input schema -> Stage 1 = BLOCK, downstream NOT called."""
    server_name = "sample_reference_server"

    async def db_hash_provider(s_name, t_name):
        return await get_approved_hash(s_name, t_name, session=e2e_db_session)

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
                    client_manager = DownstreamClientManager(server_def, server_name=server_name)
                    tools_res = await client_manager.list_tools(downstream_session)
                    tools_data = [t.model_dump(mode="json") for t in tools_res.tools]
                    await register_trusted_server_and_tools(
                        server_name=server_name,
                        tools=tools_data,
                        canonicalize_and_hash_fn=canonicalize_and_hash,
                        session=e2e_db_session
                    )

                    # Tamper input schema: add unexpected property
                    tool_obj = client_manager._tools_cache["calculate"]
                    current_schema = getattr(tool_obj, "inputSchema", getattr(tool_obj, "input_schema", {}))
                    tampered = copy.deepcopy(current_schema)
                    tampered["properties"]["exfil_target"] = {"type": "string"}
                    if hasattr(tool_obj, "inputSchema"):
                        tool_obj.inputSchema = tampered
                    if hasattr(tool_obj, "input_schema"):
                        tool_obj.input_schema = tampered

                    stage1 = Stage1HashCheck(hash_provider=db_hash_provider)
                    runner = PipelineRunner(stage1=stage1, persist_events=False)
                    proxy_server = create_proxy_server(
                        client_manager=client_manager,
                        downstream_session=downstream_session,
                        pipeline_runner=runner,
                        server_name="mcpath-test-proxy"
                    )

                    proxy_task = tg.create_task(
                        proxy_server.run(*c2p_s, proxy_server.create_initialization_options())
                    )

                    async with ClientSession(*c2p_c) as client:
                        await client.initialize()

                        call_res = await client.call_tool("calculate", {"operation": "add", "a": 1, "b": 2})
                        assert call_res.is_error is True
                        assert "EXECUTION BLOCKED" in call_res.content[0].text

                    proxy_task.cancel()
                downstream_task.cancel()


@pytest.mark.asyncio
async def test_5_reordered_json_keys_pass():
    """Test 5: Reordered JSON object keys produce identical canonical hash and PASS."""
    def_normal = {
        "name": "send_email",
        "description": "Sends email message",
        "inputSchema": {
            "type": "object",
            "properties": {
                "body": {"type": "string", "description": "body text"},
                "recipient": {"type": "string", "description": "email address"},
                "subject": {"type": "string", "description": "subject line"}
            },
            "required": ["recipient", "subject", "body"]
        }
    }

    def_reordered = {
        "inputSchema": {
            "required": ["recipient", "subject", "body"],
            "properties": {
                "subject": {"description": "subject line", "type": "string"},
                "recipient": {"description": "email address", "type": "string"},
                "body": {"description": "body text", "type": "string"}
            },
            "type": "object"
        },
        "description": "Sends email message",
        "name": "send_email"
    }

    canon_normal, hash_normal = canonicalize_and_hash(def_normal)
    canon_reordered, hash_reordered = canonicalize_and_hash(def_reordered)

    assert canon_normal == canon_reordered
    assert hash_normal == hash_reordered


@pytest.mark.asyncio
async def test_6_missing_or_deleted_baseline_fails_closed(e2e_db_session: AsyncSession):
    """Test 6: Deleted/missing approved hash -> NO_APPROVED_BASELINE -> BLOCK, downstream NOT called."""
    server_name = "sample_reference_server"
    
    # Do NOT register any baseline in DB
    async def empty_hash_provider(s_name, t_name):
        return await get_approved_hash(s_name, t_name, session=e2e_db_session)

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
                    client_manager = DownstreamClientManager(server_def, server_name=server_name)
                    await client_manager.list_tools(downstream_session)

                    stage1 = Stage1HashCheck(hash_provider=empty_hash_provider)
                    runner = PipelineRunner(stage1=stage1, persist_events=False)
                    proxy_server = create_proxy_server(
                        client_manager=client_manager,
                        downstream_session=downstream_session,
                        pipeline_runner=runner,
                        server_name="mcpath-test-proxy"
                    )

                    proxy_task = tg.create_task(
                        proxy_server.run(*c2p_s, proxy_server.create_initialization_options())
                    )

                    async with ClientSession(*c2p_c) as client:
                        await client.initialize()

                        call_res = await client.call_tool("echo", {"message": "unapproved call"})
                        assert call_res.is_error is True
                        assert "EXECUTION BLOCKED" in call_res.content[0].text
                        assert "NO_APPROVED_BASELINE" in call_res.content[0].text or "no active approved baseline" in call_res.content[0].text

                    proxy_task.cancel()
                downstream_task.cancel()


@pytest.mark.asyncio
async def test_7_registration_is_idempotent(e2e_db_session: AsyncSession):
    """Test 7: Running registration multiple times creates NO duplicate server/tool/hash records."""
    server_name = "sample_reference_server"
    sample_tools = [
        {"name": "echo", "description": "Echo", "inputSchema": {"type": "object"}},
        {"name": "calculate", "description": "Calculate", "inputSchema": {"type": "object"}}
    ]

    # First run
    await register_trusted_server_and_tools(
        server_name=server_name,
        tools=sample_tools,
        canonicalize_and_hash_fn=canonicalize_and_hash,
        session=e2e_db_session
    )

    # Second run (exact same tools)
    await register_trusted_server_and_tools(
        server_name=server_name,
        tools=sample_tools,
        canonicalize_and_hash_fn=canonicalize_and_hash,
        session=e2e_db_session
    )

    # Verify counts
    server_count = (await e2e_db_session.execute(select(func.count(ServerDB.id)).where(ServerDB.name == server_name))).scalar()
    assert server_count == 1

    tool_count = (await e2e_db_session.execute(select(func.count(ToolDB.id)).where(ToolDB.server_name == server_name))).scalar()
    assert tool_count == 2

    active_hash_count = (await e2e_db_session.execute(select(func.count(ApprovedHashDB.id)).where(ApprovedHashDB.server_name == server_name, ApprovedHashDB.is_active == True))).scalar()
    assert active_hash_count == 2
