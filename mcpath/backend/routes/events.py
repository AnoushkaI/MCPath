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
                "runtime_path_id": getattr(r, "runtime_path_id", None),
                "matched_path": getattr(r, "matched_path", None),
                "match_status": getattr(r, "match_status", None),
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


@router.get("/{event_id}")
async def get_event_detail(
    event_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Retrieve full details for a specific security event, including stage results and intent evaluation."""
    from fastapi import HTTPException
    from mcpath.backend.persistence.models import StageResultDB, DecisionDB
    from mcpath.backend.persistence.database import get_intent_evaluation

    stmt = select(SecurityEventDB).where(SecurityEventDB.event_id == event_id)
    res = await db.execute(stmt)
    r = res.scalar_one_or_none()
    if not r:
        raise HTTPException(status_code=404, detail=f"Security event '{event_id}' not found")

    # Fetch stage results
    stage_stmt = select(StageResultDB).where(StageResultDB.event_id == event_id).order_by(StageResultDB.stage_number)
    stage_res = await db.execute(stage_stmt)
    stages = [
        {
            "id": s.id,
            "stage_number": s.stage_number,
            "stage_name": s.stage_name,
            "passed": s.passed,
            "hard_block": s.hard_block,
            "score": s.score,
            "explanation": s.explanation,
            "metadata": s.metadata_json,
            "evaluated_at": s.evaluated_at.isoformat() if s.evaluated_at else None
        }
        for s in stage_res.scalars().all()
    ]

    # Fetch intent evaluation if available
    intent_eval = await get_intent_evaluation(event_id, session=db)

    # Fetch decision record
    dec_stmt = select(DecisionDB).where(DecisionDB.event_id == event_id)
    dec_res = await db.execute(dec_stmt)
    dec_record = dec_res.scalar_one_or_none()

    # Fetch matched capability path if runtime_path_id exists
    matched_path_obj = None
    if getattr(r, "runtime_path_id", None):
        try:
            from mcpath.backend.persistence.models import CapabilityPathDB
            path_stmt = select(CapabilityPathDB).where(CapabilityPathDB.path_id == r.runtime_path_id)
            path_res = await db.execute(path_stmt)
            p_row = path_res.scalars().first()
            if p_row:
                matched_path_obj = {
                    "path_id": p_row.path_id,
                    "tool_name": p_row.tool_name,
                    "path_nodes": p_row.path_nodes,
                    "path_edges": p_row.path_edges,
                    "data_sensitivity": p_row.data_sensitivity,
                    "action_sensitivity": p_row.action_sensitivity,
                    "external_exposure": p_row.external_exposure,
                    "chain_risk": p_row.chain_risk,
                    "path_risk_score": p_row.path_risk_score,
                    "classification": p_row.classification,
                    "is_critical_override": p_row.is_critical_override,
                    "explanation": p_row.explanation,
                }
        except Exception:
            pass

    return {
        "event_id": r.event_id,
        "timestamp": r.timestamp,
        "server_name": r.server_name,
        "tool_name": r.tool_name,
        "arguments": r.arguments_json,
        "user_prompt": r.user_prompt,
        "expected_hash": r.expected_hash,
        "observed_hash": r.observed_hash,
        "hash_matched": r.hash_matched,
        "runtime_path_id": getattr(r, "runtime_path_id", None),
        "matched_path": getattr(r, "matched_path", None),
        "match_status": getattr(r, "match_status", None),
        "matched_capability_path": matched_path_obj,
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
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "stage_results": stages,
        "intent_evaluation": intent_eval,
        "decision_record": {
            "decision": dec_record.decision,
            "reason": dec_record.reason,
            "hard_gate_triggered": dec_record.hard_gate_triggered,
            "action_taken": dec_record.action_taken,
            "evaluated_at": dec_record.evaluated_at.isoformat() if dec_record.evaluated_at else None
        } if dec_record else None
    }


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

