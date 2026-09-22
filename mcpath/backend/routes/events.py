"""FastAPI route: Security Events.

Provides read/write endpoints for security event records directly querying PostgreSQL.
"""

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from mcpath.backend.persistence.database import get_db, persist_security_event
from mcpath.backend.persistence.models import SecurityEventDB
from mcpath.risk_engine.models import SecurityEventRecord

logger = logging.getLogger("mcpath.backend.events")

router = APIRouter(prefix="/api/events", tags=["Events"])


@router.get("")
async def list_security_events(
    limit: int = Query(50, ge=1, le=500),
    server: Optional[str] = None,
    decision: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """List recent security events from PostgreSQL persistence with filtering."""
    try:
        stmt = select(SecurityEventDB).order_by(desc(SecurityEventDB.id)).limit(limit)
        if server:
            stmt = stmt.where(SecurityEventDB.server_name == server)
        if decision:
            stmt = stmt.where(SecurityEventDB.decision == decision.upper())

        res = await db.execute(stmt)
        records = res.scalars().all()

        return [
            {
                "event_id": r.event_id,
                "timestamp": r.timestamp,
                "server_name": r.server_name,
                "tool_name": r.tool_name,
                "arguments": r.arguments_json,
                "user_prompt": r.user_prompt,
                "expected_hash": r.expected_hash,
                "observed_hash": r.observed_hash,
                "hash_matched": r.hash_matched,
                "scores": {
                    "capability_risk": r.capability_risk,
                    "intent_risk": r.intent_risk,
                    "behaviour_risk": r.behaviour_risk,
                    "response_risk": r.response_risk,
                },
                "decision": r.decision,
                "reason": r.reason,
                "hard_gate_triggered": r.hard_gate_triggered,
                "action_taken": r.action_taken,
                "created_at": r.created_at.isoformat() if r.created_at else None
            }
            for r in records
        ]
    except Exception as e:
        logger.error("Failed to query security events: %s", e)
        return []


@router.post("", response_model=SecurityEventRecord)
async def record_security_event(
    event: SecurityEventRecord,
    db: AsyncSession = Depends(get_db)
):
    """Persist an intercepted security event into PostgreSQL."""
    try:
        await persist_security_event(event.model_dump(), session=db)
    except Exception as e:
        logger.error("Failed to save security event: %s", e)
    return event
