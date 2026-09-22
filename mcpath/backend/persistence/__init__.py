"""Persistence package for MCPath."""

from mcpath.backend.persistence.models import (
    Base,
    ServerDB,
    ToolDB,
    ApprovedHashDB,
    CapabilityDB,
    BaselineTraceDB,
    SecurityEventDB,
    StageResultDB,
    DecisionDB,
)
from mcpath.backend.persistence.database import (
    get_db,
    get_engine,
    init_db,
    register_server,
    sync_discovered_tools,
    get_approved_hash,
    persist_security_event,
)

# Backwards compatibility alias
ToolDefinitionDB = ToolDB

__all__ = [
    "Base",
    "ServerDB",
    "ToolDB",
    "ToolDefinitionDB",
    "ApprovedHashDB",
    "CapabilityDB",
    "BaselineTraceDB",
    "SecurityEventDB",
    "StageResultDB",
    "DecisionDB",
    "get_db",
    "get_engine",
    "init_db",
    "register_server",
    "sync_discovered_tools",
    "get_approved_hash",
    "persist_security_event",
]
