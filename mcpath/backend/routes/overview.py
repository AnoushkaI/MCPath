"""FastAPI route: Security Overview.

Aggregates metrics from PostgreSQL database:
- Total tool calls
- Allowed calls
- Blocked calls
- Held calls
- High-risk events
- Hash violations
"""

from datetime import datetime
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from mcpath.backend.persistence.database import get_db
from mcpath.backend.persistence.models import SecurityEventDB, ServerDB, ToolDB, ApprovedHashDB

logger = logging.getLogger("mcpath.backend.overview")

router = APIRouter(prefix="/api/overview", tags=["Overview"])


class OverviewMetrics(BaseModel):
    total_calls: int = 0
    allowed_count: int = 0
    blocked_count: int = 0
    held_count: int = 0
    high_risk_events: int = 0
    hash_violations: int = 0
    # Additional overview metrics for frontend
    active_servers: int = 0
    total_servers: int = 0
    connected_servers: int = 0
    trusted_servers: int = 0
    untrusted_servers: int = 0
    total_tools: int = 0
    stages: Optional[Dict[str, Any]] = None
    recent_events: Optional[List[Dict[str, Any]]] = None


@router.get("", response_model=OverviewMetrics)
async def get_security_overview(db: AsyncSession = Depends(get_db)):
    """Return live security summary metrics aggregated from PostgreSQL."""
    try:
        # Total calls
        total_stmt = select(func.count(SecurityEventDB.id))
        total_res = await db.execute(total_stmt)
        total_calls = total_res.scalar() or 0

        # Allowed count
        allow_stmt = select(func.count(SecurityEventDB.id)).where(SecurityEventDB.decision == "ALLOW")
        allow_res = await db.execute(allow_stmt)
        allowed_count = allow_res.scalar() or 0

        # Blocked count
        block_stmt = select(func.count(SecurityEventDB.id)).where(SecurityEventDB.decision == "BLOCK")
        block_res = await db.execute(block_stmt)
        blocked_count = block_res.scalar() or 0

        # Held count
        held_stmt = select(func.count(SecurityEventDB.id)).where(SecurityEventDB.decision == "HOLD")
        held_res = await db.execute(held_stmt)
        held_count = held_res.scalar() or 0

        # Hash violations
        hash_stmt = select(func.count(SecurityEventDB.id)).where(SecurityEventDB.hash_matched == False)
        hash_res = await db.execute(hash_stmt)
        hash_violations = hash_res.scalar() or 0

        # High risk events (blocked or held)
        high_risk_events = blocked_count + held_count

        # Servers
        srv_res = await db.execute(select(ServerDB))
        servers = srv_res.scalars().all()
        total_servers = len(servers)
        active_servers = sum(1 for s in servers if s.is_active)
        trusted_servers = sum(1 for s in servers if s.trust_status == "TRUSTED")
        untrusted_servers = total_servers - trusted_servers

        # Tools
        tool_cnt_res = await db.execute(select(func.count(ToolDB.id)))
        total_tools = tool_cnt_res.scalar() or 0

        # Stages status
        stages = {
            "stage_1": {
                "name": "Tool Integrity Hash",
                "type": "Hard Gate",
                "status": "ACTIVE",
                "algorithm": "Canonical SHA-256",
                "fail_mode": "Fail-Closed (BLOCK on mismatch/missing)",
                "description": "Verifies tool name, description, and schema against cryptographic baseline"
            },
            "stage_2": {
                "name": "Capability Graph Risk",
                "type": "Scored Metric",
                "status": "ACTIVE",
                "algorithm": "Typed-edge path analysis",
                "scoring": "Sensitivities (Data: 35%, Action: 40%, Exposure: 15%, Chain: 10%)",
                "description": "Causal traversal from Agent -> Tool -> Resource -> Action -> Destination"
            },
            "stage_3": {
                "name": "Semantic Intent Risk",
                "type": "Scored Metric",
                "status": "ACTIVE",
                "algorithm": "all-MiniLM-L6-v2 cosine similarity",
                "scoring": "Linear-inverted: (1 - cosine_similarity) * 100",
                "description": "Compares user prompt intent against normalized tool action representation"
            },
            "stage_4": {
                "name": "Behaviour Deviation",
                "type": "Baseline Deviation",
                "status": "STUB",
                "algorithm": "Trace variance comparison",
                "scoring": "Score: 0.0 (Pass-through stub)",
                "description": "Behavioral trace deviation tracking against operational baseline"
            },
            "stage_5": {
                "name": "Response Risk",
                "type": "Post-Call Inspection",
                "status": "STUB",
                "algorithm": "Egress pattern analysis",
                "scoring": "Score: 0.0 (Pass-through stub)",
                "description": "Post-execution tool response content and data leak inspection"
            },
            "risk_engine": {
                "name": "Risk Engine",
                "type": "Deterministic Enforcer",
                "status": "ACTIVE",
                "algorithm": "Tiered max-risk threshold evaluation",
                "thresholds": "Low: < 30.0 (ALLOW) | Medium: 30.0-70.0 (HOLD) | High: >= 70.0 (BLOCK)",
                "description": "Sole authority for live enforcement decisions: ALLOW / HOLD / BLOCK"
            }
        }

        # Recent events (5 most recent)
        recent_stmt = select(SecurityEventDB).order_by(desc(SecurityEventDB.id)).limit(5)
        recent_res = await db.execute(recent_stmt)
        recent_events = [
            {
                "event_id": r.event_id,
                "timestamp": r.timestamp,
                "server_name": r.server_name,
                "tool_name": r.tool_name,
                "decision": r.decision,
                "reason": r.reason,
                "hash_matched": r.hash_matched,
                "capability_risk": r.capability_risk,
                "intent_risk": r.intent_risk,
                "created_at": r.created_at.isoformat() if r.created_at else None
            }
            for r in recent_res.scalars().all()
        ]

        return OverviewMetrics(
            total_calls=total_calls,
            allowed_count=allowed_count,
            blocked_count=blocked_count,
            held_count=held_count,
            high_risk_events=high_risk_events,
            hash_violations=hash_violations,
            active_servers=active_servers,
            total_servers=total_servers,
            connected_servers=active_servers,
            trusted_servers=trusted_servers,
            untrusted_servers=untrusted_servers,
            total_tools=total_tools,
            stages=stages,
            recent_events=recent_events
        )
    except Exception as e:
        logger.warning("Failed to aggregate metrics from DB (%s), returning defaults", e)
        return OverviewMetrics()

