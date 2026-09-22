"""FastAPI route: Stage Results.

Inspect granular per-stage pipeline evaluation logs in PostgreSQL.
"""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from mcpath.backend.persistence.database import get_db
from mcpath.backend.persistence.models import StageResultDB

logger = logging.getLogger("mcpath.backend.stage_results")

router = APIRouter(prefix="/api/stage-results", tags=["Stage Results"])


@router.get("")
async def list_stage_results(
    event_id: Optional[str] = None,
    stage_number: Optional[int] = None,
    hard_block: Optional[bool] = None,
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db)
):
    """List granular stage evaluation logs from PostgreSQL."""
    try:
        stmt = select(StageResultDB).order_by(desc(StageResultDB.id)).limit(limit)
        if event_id:
            stmt = stmt.where(StageResultDB.event_id == event_id)
        if stage_number:
            stmt = stmt.where(StageResultDB.stage_number == stage_number)
        if hard_block is not None:
            stmt = stmt.where(StageResultDB.hard_block == hard_block)

        res = await db.execute(stmt)
        records = res.scalars().all()

        return [
            {
                "id": r.id,
                "event_id": r.event_id,
                "stage_number": r.stage_number,
                "stage_name": r.stage_name,
                "passed": r.passed,
                "hard_block": r.hard_block,
                "score": r.score,
                "explanation": r.explanation,
                "metadata": r.metadata_json,
                "evaluated_at": r.evaluated_at.isoformat() if r.evaluated_at else None
            }
            for r in records
        ]
    except Exception as e:
        logger.error("Failed to query stage results: %s", e)
        return []
