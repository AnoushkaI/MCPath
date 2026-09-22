"""Async database engine, session management, and repository operations."""

from datetime import datetime, timezone
import json
import logging
from typing import Any, AsyncGenerator, Callable, Dict, List, Optional, Tuple
from sqlalchemy import select, update, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from mcpath.backend.persistence.models import (
    ApprovedHashDB,
    Base,
    BaselineTraceDB,
    CapabilityDB,
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
    _async_session_factory = async_sessionmaker(_engine, expire_on_commit=False, class_=AsyncSession)
    _tables_initialized = False


def _create_engine_instance(db_url: str):
    """Create engine instance."""
    return create_async_engine(db_url, echo=False, pool_pre_ping=True)


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
    fallback_url = settings.sqlite_fallback_url
    logger.warning("Switching database engine to fallback SQLite: %s", fallback_url)
    _engine = create_async_engine(fallback_url, echo=False)
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
        _tables_initialized = True
        logger.info("Database schemas verified / created successfully.")
    except Exception as e:
        logger.warning("Primary database schema creation failed (%s). Falling back to SQLite fallback URL.", e)
        await _switch_to_fallback()
        logger.info("Fallback database schemas verified / created successfully on SQLite.")


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
            return await operation(s)
    except Exception as primary_exc:
        logger.warning("Primary database query failed (%s), attempting fallback...", primary_exc)
        await _switch_to_fallback()
        fallback_factory = get_session_factory()
        async with fallback_factory() as s:
            return await operation(s)


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


async def register_trusted_server_and_tools(
    server_name: str,
    tools: List[Dict[str, Any]],
    canonicalize_and_hash_fn: Any,
    command: str = "python",
    args: Optional[List[str]] = None,
    env_vars: Optional[Dict[str, str]] = None,
    approved_by: str = "admin:trusted_registration",
    session: Optional[AsyncSession] = None
) -> List[Tuple[ToolDB, ApprovedHashDB]]:
    """Register server, tools, and compute/store approved SHA-256 baseline hashes (Idempotent)."""
    async def _op(s: AsyncSession):
        # 1. Upsert server record
        stmt_srv = select(ServerDB).where(ServerDB.name == server_name)
        res_srv = await s.execute(stmt_srv)
        server = res_srv.scalar_one_or_none()
        if server is None:
            server = ServerDB(
                name=server_name,
                command=command,
                args=args or [],
                env_vars=env_vars or {},
                is_active=True
            )
            s.add(server)
            await s.flush()
        else:
            server.command = command
            server.args = args or []
            server.env_vars = env_vars or {}
            server.is_active = True
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
            tool = res.scalar_one_or_none()

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
            active_hashes = hash_res.scalars().all()

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
        return res.scalar_one_or_none()

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
        await s.refresh(sec_event)
        return sec_event

    return await _run_with_retry(_op, session=session)


# Backwards compatibility alias
sync_discovered_tools = register_trusted_server_and_tools
