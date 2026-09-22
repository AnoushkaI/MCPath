"""FastAPI route: Security Overview.

Aggregates metrics from PostgreSQL database:
- Total tool calls
- Allowed calls
- Blocked calls
- Held calls
- High-risk events
- Hash violations
"""

import logging
from typing import Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from mcpath.backend.persistence.database import get_db
from mcpath.backend.persistence.models import SecurityEventDB

logger = logging.getLogger("mcpath.backend.overview")

router = APIRouter(prefix="/api/overview", tags=["Overview"])


class OverviewMetrics(BaseModel):
    total_calls: int = 0
    allowed_count: int = 0
    blocked_count: int = 0
    held_count: int = 0
    high_risk_events: int = 0
    hash_violations: int = 0


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

        return OverviewMetrics(
            total_calls=total_calls,
            allowed_count=allowed_count,
            blocked_count=blocked_count,
            held_count=held_count,
            high_risk_events=high_risk_events,
            hash_violations=hash_violations
        )
    except Exception as e:
        logger.warning("Failed to aggregate metrics from DB (%s), returning defaults", e)
        return OverviewMetrics()
