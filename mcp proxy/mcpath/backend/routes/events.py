"""FastAPI route: Security Events.

Provides read/write endpoints for security event records in the explainability format.
"""

from typing import List, Optional
from fastapi import APIRouter
from mcpath.risk_engine.models import SecurityEventRecord

router = APIRouter(prefix="/api/events", tags=["Events"])

# In-memory buffer for initial development / testing
_events_log: List[SecurityEventRecord] = []


@router.get("", response_model=List[SecurityEventRecord])
async def list_security_events(
    limit: int = 50,
    server: Optional[str] = None,
    decision: Optional[str] = None
):
    """List recent security events, filterable by server or enforcement decision.

    [TODO Day 12-13: Fetch directly from PostgreSQL persistence]
    """
    events = _events_log
    if server:
        events = [e for e in events if e.server_name == server]
    if decision:
        events = [e for e in events if e.decision.value == decision]
    return events[-limit:]


@router.post("", response_model=SecurityEventRecord)
async def record_security_event(event: SecurityEventRecord):
    """Record an intercepted security event from the MCPath proxy.

    [TODO Day 1-2: Save to PostgreSQL database]
    """
    _events_log.append(event)
    return event
