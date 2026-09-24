"""Async database engine, session management, and repository operations."""

from datetime import datetime, timezone
import json
import logging
import re
from typing import Any, AsyncGenerator, Callable, Dict, List, Optional, Tuple
from sqlalchemy import select, update, text, func
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from mcpath.backend.persistence.models import (
    ApprovedHashDB,
    Base,
    BaselineTraceDB,
    CapabilityDB,
    CapabilityNodeDB,
    CapabilityEdgeDB,
    CapabilityPathDB,
    DecisionDB,
    SecurityEventDB,
    ServerDB,
    StageResultDB,
    ToolDB,
)
from mcpath.config.settings import settings

logger = logging.getLogger("mcpath.backend.database")

_engine = None
_async_session_factory = None
_tables_initialized = False


def get_db_url() -> str:
    """Return database URL from settings."""
    return settings.database_url


def set_engine(custom_engine):
    """Set custom engine (used for testing or switching connection)."""
    global _engine, _async_session_factory, _tables_initialized
    _engine = custom_engine
    if custom_engine is not None:
        _async_session_factory = async_sessionmaker(_engine, expire_on_commit=False, class_=AsyncSession)
    else:
        _async_session_factory = None
    _tables_initialized = False


def _create_engine_instance(db_url: str):
    """Create engine instance with appropriate timeout and pooling."""
    kwargs: Dict[str, Any] = {"echo": False}
    if "sqlite" in db_url:
        kwargs["connect_args"] = {"timeout": 30.0}
    else:
        kwargs["pool_pre_ping"] = True
    return create_async_engine(db_url, **kwargs)


def get_engine():
    """Get or create the global async SQLAlchemy engine."""
    global _engine, _async_session_factory
    if _engine is None:
        db_url = get_db_url()
        try:
            _engine = _create_engine_instance(db_url)
            _async_session_factory = async_sessionmaker(_engine, expire_on_commit=False, class_=AsyncSession)
            logger.info("Database engine initialized for: %s", db_url.split("@")[-1] if "@" in db_url else db_url)
        except Exception as e:
            logger.warning("Primary database engine creation failed (%s), falling back to SQLite fallback URL", e)
            fallback_url = settings.sqlite_fallback_url
            _engine = _create_engine_instance(fallback_url)
            _async_session_factory = async_sessionmaker(_engine, expire_on_commit=False, class_=AsyncSession)
            logger.info("Fallback database engine initialized with: %s", fallback_url)
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Get the async session factory."""
    global _async_session_factory
    if _async_session_factory is None:
        get_engine()
    return _async_session_factory


async def _switch_to_fallback():
    """Switch global engine to SQLite fallback and create tables."""
    global _engine, _async_session_factory, _tables_initialized
    if _engine is not None and getattr(_engine, "dialect", None) is not None and _engine.dialect.name == "sqlite":
        logger.debug("Engine is already SQLite (%s); retaining existing engine.", _engine.url)
        return
    fallback_url = settings.sqlite_fallback_url
    logger.warning("Switching database engine to fallback SQLite: %s", fallback_url)
    _engine = _create_engine_instance(fallback_url)
    _async_session_factory = async_sessionmaker(_engine, expire_on_commit=False, class_=AsyncSession)
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    _tables_initialized = True


async def init_db(engine_instance=None) -> None:
    """Create all database tables if they do not already exist."""
    global _engine, _async_session_factory, _tables_initialized
    target_engine = engine_instance or get_engine()
    try:
        async with target_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            if target_engine.dialect.name == "postgresql":
                for col_stmt in [
                    "ALTER TABLE capabilities ADD COLUMN IF NOT EXISTS server_name VARCHAR(100)",
                    "ALTER TABLE capabilities ADD COLUMN IF NOT EXISTS operation VARCHAR(20)",
                    "ALTER TABLE capabilities ADD COLUMN IF NOT EXISTS data_sensitivity FLOAT DEFAULT 0.0",
                    "ALTER TABLE capabilities ADD COLUMN IF NOT EXISTS action_sensitivity FLOAT DEFAULT 0.0",
                    "ALTER TABLE capabilities ADD COLUMN IF NOT EXISTS external_exposure FLOAT DEFAULT 0.0",
                    "ALTER TABLE capabilities ADD COLUMN IF NOT EXISTS policy_version VARCHAR(50) DEFAULT '1.0.0'",
                    "ALTER TABLE capabilities ADD COLUMN IF NOT EXISTS metadata_json JSON DEFAULT '{}'",
                    "ALTER TABLE servers ADD COLUMN IF NOT EXISTS trust_status VARCHAR(20) DEFAULT 'UNTRUSTED'",
                    "ALTER TABLE servers ADD COLUMN IF NOT EXISTS last_discovery_time TIMESTAMP WITH TIME ZONE",
                    "ALTER TABLE servers ADD COLUMN IF NOT EXISTS last_trust_time TIMESTAMP WITH TIME ZONE"
                ]:
                    try:
                        await conn.execute(text(col_stmt))
                    except Exception:
                        pass
            else:
                for col_stmt in [
                    "ALTER TABLE servers ADD COLUMN trust_status VARCHAR(20) DEFAULT 'UNTRUSTED'",
                    "ALTER TABLE servers ADD COLUMN last_discovery_time TIMESTAMP",
                    "ALTER TABLE servers ADD COLUMN last_trust_time TIMESTAMP"
                ]:
                    try:
                        await conn.execute(text(col_stmt))
                    except Exception:
                        pass
        _tables_initialized = True
        logger.info("Database schemas verified / created successfully.")
    except Exception as e:
        logger.warning("Primary database schema creation failed (%s). Falling back to SQLite fallback URL.", e)
        await _switch_to_fallback()
        logger.info("Fallback database schemas verified / created successfully on SQLite.")

    try:
        await reconcile_server_active_states()
    except Exception as e:
        logger.debug("Startup server active state reconciliation skipped: %s", e)


async def _run_with_retry(operation: Callable[[AsyncSession], Any], session: Optional[AsyncSession] = None) -> Any:
    """Execute a database operation with automatic fallback handling if primary DB connection fails."""
    global _tables_initialized
    if session is not None:
        return await operation(session)

    factory = get_session_factory()
    try:
        if not _tables_initialized:
            await init_db()
            factory = get_session_factory()

        async with factory() as s:
            res = await operation(s)
            try:
                if s.in_transaction():
                    await s.rollback()
            except Exception:
                pass
            return res
    except Exception as primary_exc:
        logger.warning("Primary database query failed (%s), attempting fallback...", primary_exc)
        await _switch_to_fallback()
        fallback_factory = get_session_factory()
        async with fallback_factory() as s:
            res = await operation(s)
            try:
                if s.in_transaction():
                    await s.rollback()
            except Exception:
                pass
            return res


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency provider for async database sessions."""
    global _tables_initialized
    if not _tables_initialized:
        await init_db()
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
        finally:
            await session.close()


# =========================================================================
# Repository Functions for Stage 1, Trusted Registration, and Events
# =========================================================================

async def register_server(
    server_name: str,
    command: str = "python",
    args: Optional[List[str]] = None,
    env_vars: Optional[Dict[str, str]] = None,
    session: Optional[AsyncSession] = None
) -> ServerDB:
    """Register or update an MCP server record."""
    async def _op(s: AsyncSession):
        stmt = select(ServerDB).where(ServerDB.name == server_name)
        result = await s.execute(stmt)
        server = result.scalar_one_or_none()
        if server is None:
            server = ServerDB(
                name=server_name,
                command=command,
                args=args or [],
                env_vars=env_vars or {},
                is_active=True
            )
            s.add(server)
            await s.commit()
            await s.refresh(server)
        else:
            server.command = command
            server.args = args or []
            server.env_vars = env_vars or {}
            server.is_active = True
            await s.commit()
            await s.refresh(server)
        return server

    return await _run_with_retry(_op, session=session)


def _sanitize_env_vars(env_vars: Optional[Dict[str, str]]) -> Dict[str, str]:
    """Redact sensitive credentials from stored environment variables."""
    if not env_vars:
        return {}
    sanitized = {}
    for k, v in env_vars.items():
        if any(secret_kw in k.upper() for secret_kw in ("PASSWORD", "SECRET", "KEY", "TOKEN")):
            sanitized[k] = "******"
        elif "CONNECTION_STRING" in k.upper() or "DATABASE_URL" in k.upper():
            sanitized[k] = re.sub(r"://([^:]+):([^@]+)@", r"://\1:******@", str(v))
        else:
            sanitized[k] = v
    return sanitized


async def register_trusted_server_and_tools(
    server_name: str,
    tools: List[Dict[str, Any]],
    canonicalize_and_hash_fn: Any,
    command: Optional[str] = None,
    args: Optional[List[str]] = None,
    env_vars: Optional[Dict[str, str]] = None,
    approved_by: str = "admin:trusted_registration",
    is_active: Optional[bool] = None,
    session: Optional[AsyncSession] = None
) -> List[Tuple[ToolDB, ApprovedHashDB]]:
    """Register server, tools, and compute/store approved SHA-256 baseline hashes (Idempotent)."""
    async def _op(s: AsyncSession):
        safe_env = _sanitize_env_vars(env_vars) if env_vars is not None else None

        # 1. Upsert server record
        stmt_srv = select(ServerDB).where(ServerDB.name == server_name)
        res_srv = await s.execute(stmt_srv)
        servers = list(res_srv.scalars().all())
        res_srv.close()
        server = servers[0] if servers else None
        now = datetime.now(timezone.utc)
        if server is None:
            server = ServerDB(
                name=server_name,
                command=command or "python",
                args=args if args is not None else [],
                env_vars=safe_env if safe_env is not None else {},
                is_active=is_active if is_active is not None else True,
                trust_status="TRUSTED",
                last_trust_time=now
            )
            s.add(server)
            await s.flush()
        else:
            if command is not None:
                server.command = command
            if args is not None:
                server.args = args
            if safe_env is not None:
                server.env_vars = safe_env
            if is_active is not None:
                server.is_active = is_active
            # NOTE: Trusting must NOT alter is_active state unless explicitly specified
            server.trust_status = "TRUSTED"
            server.last_trust_time = now
            await s.flush()

        synced_records = []

        for tool_dict in tools:
            tool_name = tool_dict.get("name", "")
            description = tool_dict.get("description", "") or ""
            input_schema = tool_dict.get("inputSchema")
            if input_schema is None:
                input_schema = tool_dict.get("input_schema", {})
            if input_schema is None:
                input_schema = {}

            # 2. Upsert tool record
            stmt = select(ToolDB).where(ToolDB.server_id == server.id, ToolDB.name == tool_name)
            res = await s.execute(stmt)
            tools_found = list(res.scalars().all())
            res.close()
            tool = tools_found[0] if tools_found else None

            if tool is None:
                tool = ToolDB(
                    server_id=server.id,
                    server_name=server_name,
                    name=tool_name,
                    description=description,
                    input_schema=input_schema
                )
                s.add(tool)
                await s.flush()
            else:
                tool.description = description
                tool.input_schema = input_schema
                await s.flush()

            # 3. Canonicalize and compute SHA-256 hash using shared canonicalizer
            canonical_json, computed_sha = canonicalize_and_hash_fn(tool_dict)

            # 4. Check existing active approved hash
            hash_stmt = select(ApprovedHashDB).where(
                ApprovedHashDB.tool_id == tool.id,
                ApprovedHashDB.is_active == True
            )
            hash_res = await s.execute(hash_stmt)
            active_hashes = list(hash_res.scalars().all())
            hash_res.close()

            matched_existing = None
            for ah in active_hashes:
                if ah.hash_sha256 == computed_sha:
                    matched_existing = ah
                else:
                    # Deactivate stale hash on re-registration
                    ah.is_active = False
                    ah.revoked_at = datetime.now(timezone.utc)

            if matched_existing is not None:
                approved_hash_rec = matched_existing
            else:
                approved_hash_rec = ApprovedHashDB(
                    tool_id=tool.id,
                    server_name=server_name,
                    tool_name=tool_name,
                    canonical_json=canonical_json,
                    hash_sha256=computed_sha,
                    is_active=True,
                    approved_by=approved_by,
                    approved_at=datetime.now(timezone.utc)
                )
                s.add(approved_hash_rec)
                await s.flush()

            synced_records.append((tool, approved_hash_rec))

        await s.commit()
        return synced_records

    return await _run_with_retry(_op, session=session)


async def save_discovered_tools(
    server_name: str,
    tools: List[Dict[str, Any]],
    command: Optional[str] = None,
    args: Optional[List[str]] = None,
    env_vars: Optional[Dict[str, str]] = None,
    is_active: Optional[bool] = None,
    session: Optional[AsyncSession] = None
) -> List[ToolDB]:
    """Upsert server and discovered tools WITHOUT creating approved hashes.

    Preserves existing approved baseline and trust_status if already TRUSTED.
    """
    async def _op(s: AsyncSession):
        safe_env = _sanitize_env_vars(env_vars) if env_vars is not None else None

        stmt_srv = select(ServerDB).where(ServerDB.name == server_name)
        res_srv = await s.execute(stmt_srv)
        servers = list(res_srv.scalars().all())
        res_srv.close()
        server = servers[0] if servers else None
        now = datetime.now(timezone.utc)
        if server is None:
            server = ServerDB(
                name=server_name,
                command=command or "python",
                args=args if args is not None else [],
                env_vars=safe_env if safe_env is not None else {},
                is_active=is_active if is_active is not None else True,
                trust_status="UNTRUSTED",
                last_discovery_time=now
            )
            s.add(server)
            await s.flush()
        else:
            if command is not None:
                server.command = command
            if args is not None:
                server.args = args
            if safe_env is not None:
                server.env_vars = safe_env
            if is_active is not None:
                server.is_active = is_active
            if not server.trust_status:
                server.trust_status = "UNTRUSTED"
            server.last_discovery_time = now
            await s.flush()

        saved_tools = []
        for tool_dict in tools:
            tool_name = tool_dict.get("name", "")
            description = tool_dict.get("description", "") or ""
            input_schema = tool_dict.get("inputSchema")
            if input_schema is None:
                input_schema = tool_dict.get("input_schema", {})
            if input_schema is None:
                input_schema = {}

            stmt = select(ToolDB).where(ToolDB.server_id == server.id, ToolDB.name == tool_name)
            res_tool = await s.execute(stmt)
            tools_found = list(res_tool.scalars().all())
            res_tool.close()
            tool = tools_found[0] if tools_found else None

            if tool is None:
                tool = ToolDB(
                    server_id=server.id,
                    server_name=server_name,
                    name=tool_name,
                    description=description,
                    input_schema=input_schema
                )
                s.add(tool)
                await s.flush()
            else:
                tool.description = description
                tool.input_schema = input_schema
                await s.flush()
            saved_tools.append(tool)

        await s.commit()
        return saved_tools

    return await _run_with_retry(_op, session=session)


async def set_server_active_state(
    server_name: str,
    is_active: bool,
    session: Optional[AsyncSession] = None
) -> Optional[ServerDB]:
    """Update ServerDB is_active flag while preserving all historical records."""
    async def _op(s: AsyncSession):
        stmt = select(ServerDB).where(ServerDB.name == server_name)
        res = await s.execute(stmt)
        servers = list(res.scalars().all())
        res.close()
        server = servers[0] if servers else None
        if server:
            server.is_active = is_active
            server.updated_at = datetime.now(timezone.utc)
            await s.commit()
        return server

    return await _run_with_retry(_op, session=session)


async def reconcile_server_active_states(
    active_servers: Optional[List[str]] = None,
    configured_servers: Optional[List[str]] = None,
    session: Optional[AsyncSession] = None
) -> Dict[str, bool]:
    """Reconcile ServerDB.is_active in PostgreSQL using config as authoritative.

    - config.active_servers is authoritative for which servers should be active.
    - Servers present in active_servers AND configured in config.servers -> is_active = True
    - Servers absent from active_servers or unconfigured -> is_active = False
    - Preserves historical records, approved hashes, tool baselines, and trust_status.
    - Never deletes rows from ServerDB, ToolDB, or ApprovedHashDB.
    - Existing servers with complete approved baselines remain TRUSTED.
    """
    async def _op(s: AsyncSession) -> Dict[str, bool]:
        if active_servers is None or configured_servers is None:
            from mcpath.config.settings import settings
            config = settings.get_server_config()
            target_active = active_servers if active_servers is not None else (
                getattr(config, "active_servers", None) or ([config.active_server] if config.active_server else [])
            )
            target_configured = configured_servers if configured_servers is not None else list(config.servers.keys())
        else:
            target_active = active_servers
            target_configured = configured_servers

        active_set = set(target_active) & set(target_configured)

        stmt = select(ServerDB)
        res = await s.execute(stmt)
        servers = list(res.scalars().all())
        res.close()
        now = datetime.now(timezone.utc)
        reconciled = {}
        for srv in servers:
            should_be_active = (srv.name in active_set)
            if srv.is_active != should_be_active:
                srv.is_active = should_be_active
                srv.updated_at = now
            reconciled[srv.name] = should_be_active

        await s.commit()
        return reconciled

    return await _run_with_retry(_op, session=session)


async def get_server_db_status(
    server_name: Optional[str] = None,
    session: Optional[AsyncSession] = None
) -> List[Dict[str, Any]]:
    """Query servers from database with discovered tool and active approved baseline counts."""
    async def _op(s: AsyncSession):
        stmt = select(ServerDB)
        if server_name:
            stmt = stmt.where(ServerDB.name == server_name)
        res_srv = await s.execute(stmt)
        servers = list(res_srv.scalars().all())
        res_srv.close()

        tool_counts_stmt = select(ToolDB.server_id, func.count(ToolDB.id)).group_by(ToolDB.server_id)
        res_tools = await s.execute(tool_counts_stmt)
        tool_counts = dict(res_tools.all())
        res_tools.close()

        hash_counts_stmt = (
            select(ApprovedHashDB.server_name, func.count(ApprovedHashDB.id))
            .where(ApprovedHashDB.is_active == True)
            .group_by(ApprovedHashDB.server_name)
        )
        res_hashes = await s.execute(hash_counts_stmt)
        hash_counts = dict(res_hashes.all())
        res_hashes.close()

        status_list = []
        for srv in servers:
            tool_count = tool_counts.get(srv.id, 0)
            approved_count = hash_counts.get(srv.name, 0)
            unapproved_count = max(0, tool_count - approved_count)

            if srv.trust_status:
                trust_status = srv.trust_status
            elif tool_count > 0 and approved_count == tool_count:
                trust_status = "TRUSTED"
            else:
                trust_status = "UNTRUSTED"

            status_list.append({
                "id": srv.id,
                "name": srv.name,
                "command": srv.command,
                "args": srv.args,
                "active": srv.is_active,
                "is_active": srv.is_active,
                "connected": False,
                "trust_status": trust_status,
                "discovered_tool_count": tool_count,
                "approved_tool_count": approved_count,
                "unapproved_tool_count": unapproved_count,
                "last_discovery_time": srv.last_discovery_time.isoformat() if srv.last_discovery_time else (srv.created_at.isoformat() if srv.created_at else None),
                "last_trust_time": srv.last_trust_time.isoformat() if srv.last_trust_time else None,
                "created_at": srv.created_at.isoformat() if srv.created_at else None,
            })
        return status_list

    return await _run_with_retry(_op, session=session)


async def get_approved_hash(
    server_name: str,
    tool_name: str,
    session: Optional[AsyncSession] = None
) -> Optional[str]:
    """Retrieve the active approved SHA-256 hash for a specific tool on a server."""
    async def _op(s: AsyncSession) -> Optional[str]:
        stmt = (
            select(ApprovedHashDB.hash_sha256)
            .join(ToolDB, ApprovedHashDB.tool_id == ToolDB.id)
            .where(
                ToolDB.server_name == server_name,
                ToolDB.name == tool_name,
                ApprovedHashDB.is_active == True
            )
            .order_by(ApprovedHashDB.id.desc())
        )
        res = await s.execute(stmt)
        rows = list(res.scalars().all())
        res.close()
        return rows[0] if rows else None

    return await _run_with_retry(_op, session=session)


async def persist_security_event(
    event_dict: Dict[str, Any],
    stage_results: Optional[List[Dict[str, Any]]] = None,
    session: Optional[AsyncSession] = None
) -> SecurityEventDB:
    """Persist security event, stage evaluation results, and decision record into database."""
    async def _op(s: AsyncSession):
        event_id = event_dict.get("event_id") or f"evt_{datetime.now(timezone.utc).timestamp()}"
        timestamp = event_dict.get("timestamp") or datetime.now(timezone.utc).isoformat()
        server_name = event_dict.get("server_name", "unknown")
        tool_name = event_dict.get("tool_name", "unknown")
        arguments = event_dict.get("arguments", {})
        decision = event_dict.get("decision", "ALLOW")
        reason = event_dict.get("reason", "")
        hard_gate = event_dict.get("hard_gate_triggered")
        action_taken = event_dict.get("action_taken", "Tool call forwarded")

        scores = event_dict.get("scores", {})
        if isinstance(scores, dict):
            cap_risk = scores.get("capability_risk")
            int_risk = scores.get("intent_risk")
            beh_risk = scores.get("behaviour_risk")
            res_risk = scores.get("response_risk")
        else:
            cap_risk = getattr(scores, "capability_risk", None)
            int_risk = getattr(scores, "intent_risk", None)
            beh_risk = getattr(scores, "behaviour_risk", None)
            res_risk = getattr(scores, "response_risk", None)

        sec_event = SecurityEventDB(
            event_id=event_id,
            timestamp=timestamp,
            server_name=server_name,
            tool_name=tool_name,
            arguments_json=arguments,
            user_prompt=event_dict.get("user_prompt"),
            expected_hash=event_dict.get("expected_hash"),
            observed_hash=event_dict.get("observed_hash"),
            hash_matched=event_dict.get("hash_matched"),
            capability_risk=cap_risk,
            intent_risk=int_risk,
            behaviour_risk=beh_risk,
            response_risk=res_risk,
            decision=decision if isinstance(decision, str) else getattr(decision, "value", str(decision)),
            reason=reason,
            hard_gate_triggered=hard_gate,
            action_taken=action_taken
        )
        s.add(sec_event)
        await s.flush()

        # Add granular stage results if provided
        if stage_results:
            for sr in stage_results:
                stage_rec = StageResultDB(
                    event_id=event_id,
                    stage_number=sr.get("stage_number", 1),
                    stage_name=sr.get("stage_name", "Stage"),
                    passed=sr.get("passed", True),
                    hard_block=sr.get("hard_block", False),
                    score=sr.get("score"),
                    explanation=sr.get("explanation"),
                    metadata_json=sr.get("metadata", {})
                )
                s.add(stage_rec)

        # Add decision record
        decision_rec = DecisionDB(
            event_id=event_id,
            decision=decision if isinstance(decision, str) else getattr(decision, "value", str(decision)),
            reason=reason,
            hard_gate_triggered=hard_gate,
            action_taken=action_taken
        )
        s.add(decision_rec)

        await s.commit()
        return sec_event

    return await _run_with_retry(_op, session=session)


# Backwards compatibility alias
sync_discovered_tools = register_trusted_server_and_tools


# =========================================================================
# Capability Graph & Path Persistence Functions (Stage 2)
# =========================================================================

async def persist_capability_graph(
    graph_data: Dict[str, Any],
    session: Optional[AsyncSession] = None
) -> None:
    """Persist graph nodes, typed edges, and compatible paths into PostgreSQL."""
    async def _op(s: AsyncSession):
        policy_ver = graph_data.get("policy_version", "1.0.0")

        # 1. Clear existing nodes, edges, paths for clean refresh
        await s.execute(text("DELETE FROM capability_paths"))
        await s.execute(text("DELETE FROM capability_edges"))
        await s.execute(text("DELETE FROM capability_nodes"))

        # 2. Insert nodes
        for node in graph_data.get("nodes", []):
            node_rec = CapabilityNodeDB(
                node_id=node.get("id", ""),
                node_type=node.get("type", "Unknown"),
                label=node.get("label", node.get("id", "")),
                server_name=node.get("server"),
                attributes_json={k: v for k, v in node.items() if k not in ("id", "type", "label", "server")},
                policy_version=policy_ver,
                updated_at=datetime.now(timezone.utc)
            )
            s.add(node_rec)

        # 3. Insert edges
        for edge in graph_data.get("edges", []):
            edge_rec = CapabilityEdgeDB(
                source_node=edge.get("source", ""),
                target_node=edge.get("target", ""),
                relation=edge.get("relation", "CONNECTED"),
                attributes_json={k: v for k, v in edge.items() if k not in ("source", "target", "relation")},
                policy_version=policy_ver,
                updated_at=datetime.now(timezone.utc)
            )
            s.add(edge_rec)

        # 4. Insert paths
        for path in graph_data.get("paths", []):
            tool_name = "unknown"
            path_nodes = path.get("path_nodes", [])
            for n in path_nodes:
                if n.startswith("Tool:"):
                    tool_name = n.split("Tool:", 1)[1]
                    break

            path_rec = CapabilityPathDB(
                tool_name=tool_name,
                path_nodes=path_nodes,
                path_edges=path.get("path_edges", []),
                data_sensitivity=float(path.get("data_sensitivity", 0.0)),
                action_sensitivity=float(path.get("action_sensitivity", 0.0)),
                external_exposure=float(path.get("external_exposure", 0.0)),
                chain_risk=float(path.get("chain_risk", 0.0)),
                path_risk_score=float(path.get("path_risk_score", 0.0)),
                classification=path.get("classification", "LOW"),
                is_critical_override=bool(path.get("is_critical_override", False)),
                explanation=path.get("explanation", ""),
                policy_version=policy_ver,
                created_at=datetime.now(timezone.utc)
            )
            s.add(path_rec)

        await s.commit()

    return await _run_with_retry(_op, session=session)


async def persist_tool_capabilities(
    capabilities: List[Dict[str, Any]],
    session: Optional[AsyncSession] = None
) -> None:
    """Persist classified tool capabilities into capabilities table."""
    async def _op(s: AsyncSession):
        # 1. Clear existing capabilities for clean refresh
        await s.execute(text("DELETE FROM capabilities"))

        # Pre-fetch all tools into lookup dictionary to avoid nested queries in loop
        stmt = select(ToolDB.id, ToolDB.name, ToolDB.server_name)
        tool_res = await s.execute(stmt)
        tool_rows = tool_res.all()
        tool_lookup: Dict[Any, int] = {}
        for tid, tname, tsrv in tool_rows:
            if tsrv:
                tool_lookup[(tname, tsrv)] = tid
            tool_lookup[tname] = tid

        for cap in capabilities:
            tool_name = cap.get("tool_name", "")
            server_name = cap.get("server_name")
            tool_id = tool_lookup.get((tool_name, server_name)) or tool_lookup.get(tool_name)

            # Handle collision-namespaced tool names (e.g. filesystem_list_directory -> list_directory)
            if tool_id is None and server_name and tool_name.startswith(f"{server_name}_"):
                raw_name = tool_name[len(server_name) + 1:]
                tool_id = tool_lookup.get((raw_name, server_name)) or tool_lookup.get(raw_name)

            cap_rec = CapabilityDB(
                tool_id=tool_id,
                tool_name=tool_name,
                server_name=server_name,
                resource_type=cap.get("data_target"),
                action=cap.get("action_type"),
                operation=cap.get("operation"),
                destination=cap.get("external_destination"),
                data_sensitivity=float(cap.get("data_sensitivity", 0.0)),
                action_sensitivity=float(cap.get("action_sensitivity", 0.0)),
                external_exposure=float(cap.get("external_exposure", 0.0)),
                risk_weight=float(cap.get("action_sensitivity", 0.0)),
                policy_version=cap.get("policy_version", "1.0.0"),
                metadata_json=cap.get("raw_metadata", {}),
                created_at=datetime.now(timezone.utc)
            )
            s.add(cap_rec)
        await s.commit()

    return await _run_with_retry(_op, session=session)


async def get_persisted_capability_graph(session: Optional[AsyncSession] = None) -> Dict[str, Any]:
    """Retrieve persisted capability graph nodes and edges from PostgreSQL."""
    async def _op(s: AsyncSession) -> Dict[str, Any]:
        stmt_nodes = select(CapabilityNodeDB)
        res_nodes = await s.execute(stmt_nodes)
        nodes = [
            {
                "id": n.node_id,
                "type": n.node_type,
                "label": n.label,
                "server": n.server_name,
                **n.attributes_json
            }
            for n in res_nodes.scalars().all()
        ]

        stmt_edges = select(CapabilityEdgeDB)
        res_edges = await s.execute(stmt_edges)
        edges = [
            {
                "source": e.source_node,
                "target": e.target_node,
                "relation": e.relation,
                **e.attributes_json
            }
            for e in res_edges.scalars().all()
        ]

        return {"nodes": nodes, "edges": edges}

    return await _run_with_retry(_op, session=session)


async def get_persisted_capability_paths(
    tool_name: Optional[str] = None,
    session: Optional[AsyncSession] = None
) -> List[Dict[str, Any]]:
    """Retrieve persisted compatible paths from PostgreSQL."""
    async def _op(s: AsyncSession) -> List[Dict[str, Any]]:
        stmt = select(CapabilityPathDB).order_by(CapabilityPathDB.path_risk_score.desc())
        if tool_name:
            stmt = stmt.where(CapabilityPathDB.tool_name == tool_name)
        res = await s.execute(stmt)
        return [
            {
                "id": p.id,
                "tool_name": p.tool_name,
                "path_nodes": p.path_nodes,
                "path_edges": p.path_edges,
                "data_sensitivity": p.data_sensitivity,
                "action_sensitivity": p.action_sensitivity,
                "external_exposure": p.external_exposure,
                "chain_risk": p.chain_risk,
                "path_risk_score": p.path_risk_score,
                "classification": p.classification,
                "is_critical_override": p.is_critical_override,
                "explanation": p.explanation,
                "policy_version": p.policy_version,
                "created_at": p.created_at.isoformat() if p.created_at else None
            }
            for p in res.scalars().all()
        ]

    return await _run_with_retry(_op, session=session)
