"""Async database engine and session management."""

import logging
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from mcpath.backend.persistence.models import Base
from mcpath.config.settings import settings

logger = logging.getLogger("mcpath.backend.database")

# Try connecting to PostgreSQL, with transparent fallback to SQLite for local development
engine = None
async_session_factory = None


def get_db_url() -> str:
    return settings.database_url


def init_engine(db_url: str | None = None):
    global engine, async_session_factory
    target_url = db_url or get_db_url()
    try:
        engine = create_async_engine(target_url, echo=False)
        async_session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
        logger.info("Database engine initialized with URL: %s", target_url.split("@")[-1])
    except Exception as e:
        logger.warning("Primary database connection failed (%s), falling back to SQLite", e)
        target_url = settings.sqlite_fallback_url
        engine = create_async_engine(target_url, echo=False)
        async_session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
        logger.info("Fallback database engine initialized with: %s", target_url)


async def init_db():
    """Create tables if they don't already exist."""
    if engine is None:
        init_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency provider for FastAPI route handlers."""
    if async_session_factory is None:
        init_engine()
    async with async_session_factory() as session:
        yield session
