"""FastAPI route: Approved Hashes.

Inspect and manage approved SHA-256 tool integrity hashes in PostgreSQL.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from mcpath.backend.persistence.database import get_db
from mcpath.backend.persistence.models import ApprovedHashDB, ToolDB
from mcpath.pipeline.stages.stage1_hash import canonicalize_and_hash

logger = logging.getLogger("mcpath.backend.hashes")

router = APIRouter(prefix="/api/hashes", tags=["Approved Hashes"])


class ApproveHashRequest(BaseModel):
    server_name: str
    tool_name: str
    tool_definition: Dict[str, Any]
    approved_by: str = "admin:manual"


@router.get("")
async def list_approved_hashes(
    server_name: Optional[str] = None,
    tool_name: Optional[str] = None,
    is_active: bool = True,
    db: AsyncSession = Depends(get_db)
):
    """List approved tool hashes stored in PostgreSQL."""
    try:
        stmt = select(ApprovedHashDB).where(ApprovedHashDB.is_active == is_active).order_by(desc(ApprovedHashDB.id))
        if server_name:
            stmt = stmt.where(ApprovedHashDB.server_name == server_name)
        if tool_name:
            stmt = stmt.where(ApprovedHashDB.tool_name == tool_name)

        res = await db.execute(stmt)
        hashes = res.scalars().all()

        return [
            {
                "id": h.id,
                "tool_id": h.tool_id,
                "server_name": h.server_name,
                "tool_name": h.tool_name,
                "hash_sha256": h.hash_sha256,
                "canonical_json": h.canonical_json,
                "is_active": h.is_active,
                "approved_by": h.approved_by,
                "approved_at": h.approved_at.isoformat() if h.approved_at else None
            }
            for h in hashes
        ]
    except Exception as e:
        logger.error("Failed to query approved hashes: %s", e)
        return []


@router.get("/{tool_name}")
async def get_tool_hash(
    tool_name: str,
    server_name: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """Retrieve active approved hash for a specific tool."""
    stmt = (
        select(ApprovedHashDB)
        .where(ApprovedHashDB.tool_name == tool_name, ApprovedHashDB.is_active == True)
        .order_by(desc(ApprovedHashDB.id))
    )
    if server_name:
        stmt = stmt.where(ApprovedHashDB.server_name == server_name)

    res = await db.execute(stmt)
    h = res.scalar_one_or_none()
    if not h:
        raise HTTPException(status_code=404, detail=f"No active approved hash found for tool '{tool_name}'")

    return {
        "id": h.id,
        "tool_id": h.tool_id,
        "server_name": h.server_name,
        "tool_name": h.tool_name,
        "hash_sha256": h.hash_sha256,
        "canonical_json": h.canonical_json,
        "is_active": h.is_active,
        "approved_by": h.approved_by,
        "approved_at": h.approved_at.isoformat() if h.approved_at else None
    }


@router.post("/approve")
async def approve_tool_hash(
    req: ApproveHashRequest,
    db: AsyncSession = Depends(get_db)
):
    """Manually approve a new or updated tool definition hash."""
    canonical_json, computed_sha = canonicalize_and_hash(req.tool_definition)

    # Find tool record
    stmt = select(ToolDB).where(ToolDB.server_name == req.server_name, ToolDB.name == req.tool_name)
    res = await db.execute(stmt)
    tool = res.scalar_one_or_none()

    if not tool:
        raise HTTPException(
            status_code=404,
            detail=f"Tool '{req.tool_name}' not found under server '{req.server_name}'"
        )

    # Deactivate existing hashes
    deact_stmt = select(ApprovedHashDB).where(
        ApprovedHashDB.tool_id == tool.id,
        ApprovedHashDB.is_active == True
    )
    deact_res = await db.execute(deact_stmt)
    for old_h in deact_res.scalars().all():
        old_h.is_active = False
        old_h.revoked_at = datetime.now(timezone.utc)

    # Insert new approved hash
    new_hash = ApprovedHashDB(
        tool_id=tool.id,
        server_name=req.server_name,
        tool_name=req.tool_name,
        canonical_json=canonical_json,
        hash_sha256=computed_sha,
        is_active=True,
        approved_by=req.approved_by
    )
    db.add(new_hash)
    await db.commit()
    await db.refresh(new_hash)

    return {
        "status": "approved",
        "tool_name": req.tool_name,
        "server_name": req.server_name,
        "hash_sha256": computed_sha,
        "approved_by": req.approved_by,
        "approved_at": new_hash.approved_at.isoformat()
    }
