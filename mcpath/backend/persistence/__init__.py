"""Persistence package for MCPath."""

from mcpath.backend.persistence.models import (
    Base,
    ServerDB,
    ToolDB,
    ApprovedHashDB,
    CapabilityDB,
    CapabilityNodeDB,
    CapabilityEdgeDB,
    CapabilityPathDB,
    BaselineTraceDB,
    SecurityEventDB,
    StageResultDB,
    DecisionDB,
    IntentEvaluationDB,
)
from mcpath.backend.persistence.database import (
    get_db,
    get_engine,
    init_db,
    register_server,
    register_trusted_server_and_tools,
    get_approved_hash,
    persist_security_event,
    get_intent_evaluation,
    set_server_active_state,
    reconcile_server_active_states,
    get_server_db_status,
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
    "CapabilityNodeDB",
    "CapabilityEdgeDB",
    "CapabilityPathDB",
    "BaselineTraceDB",
    "SecurityEventDB",
    "StageResultDB",
    "DecisionDB",
    "IntentEvaluationDB",
    "get_db",
    "get_engine",
    "init_db",
    "register_server",
    "register_trusted_server_and_tools",
    "get_approved_hash",
    "persist_security_event",
    "get_intent_evaluation",
    "set_server_active_state",
    "reconcile_server_active_states",
    "get_server_db_status",
]
