"""FastAPI route: Security Overview.

Aggregates:
- Total tool calls
- Allowed calls
- Blocked calls
- Held calls
- High-risk events
- Hash violations
"""

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/api/overview", tags=["Overview"])


class OverviewMetrics(BaseModel):
    total_calls: int = 0
    allowed_count: int = 0
    blocked_count: int = 0
    held_count: int = 0
    high_risk_events: int = 0
    hash_violations: int = 0


@router.get("", response_model=OverviewMetrics)
async def get_security_overview():
    """Return live security summary metrics for the dashboard.

    [TODO Day 12-13: Aggregate directly from PostgreSQL database]
    """
    return OverviewMetrics(
        total_calls=0,
        allowed_count=0,
        blocked_count=0,
        held_count=0,
        high_risk_events=0,
        hash_violations=0
    )
