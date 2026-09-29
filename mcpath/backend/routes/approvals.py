"""FastAPI route: Administrative Approvals.

Provides read/write endpoints for managing tool calls held for administrative review.
Supports listing pending calls, approving, rejecting, and live status inspection.
"""

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from mcpath.backend.persistence.database import (
    get_db,
    get_approvals,
    get_approval_by_id,
    update_approval_status,
)
from mcpath.proxy.control import send_proxy_control_command

logger = logging.getLogger("mcpath.backend.approvals")

router = APIRouter(prefix="/api/approvals", tags=["Approvals"])


@router.get("")
async def list_approvals(
    status: Optional[str] = Query(None, description="Filter by status (PENDING, APPROVED, REJECTED, TIMED_OUT)"),
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db)
):
    """List administrative approvals with optional status filtering."""
    try:
        return await get_approvals(status=status, limit=limit, session=db)
    except Exception as e:
        logger.error("Failed to list approvals: %s", e)
        return []


@router.get("/pending")
async def list_pending_approvals(
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db)
):
    """Retrieve only active pending approvals awaiting review."""
    try:
        return await get_approvals(status="PENDING", limit=limit, session=db)
    except Exception as e:
        logger.error("Failed to list pending approvals: %s", e)
        return []


@router.get("/{approval_id}")
async def get_approval_details(
    approval_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Retrieve details for a specific approval record."""
    record = await get_approval_by_id(approval_id, session=db)
    if not record:
        raise HTTPException(status_code=404, detail=f"Approval record '{approval_id}' not found")
    return record


@router.post("/{approval_id}/approve")
async def approve_held_call(
    approval_id: str,
    resolver: str = Query("admin", description="Identity of approving administrator"),
    db: AsyncSession = Depends(get_db)
):
    """Approve a held tool invocation. Unblocks the waiting proxy and forwards the call downstream."""
    record = await get_approval_by_id(approval_id, session=db)
    if not record:
        raise HTTPException(status_code=404, detail=f"Approval record '{approval_id}' not found")

    if record["status"] != "PENDING":
        return {
            "status": "already_resolved",
            "approval_id": approval_id,
            "current_status": record["status"],
            "message": f"Approval was already resolved as '{record['status']}'."
        }

    # 1. Update DB directly FIRST so proxy will pick it up immediately via DB polling
    db_res = await update_approval_status(
        approval_id=approval_id,
        status="APPROVED",
        resolved_by=resolver,
        session=db
    )

    # 2. Dispatch IPC command to proxy control server to wake in-memory waiter immediately
    ipc_res = None
    try:
        ipc_res = await send_proxy_control_command(
            action="approve_call",
            params={"approval_id": approval_id, "resolver": resolver}
        )
    except Exception as e:
        logger.info("Proxy control IPC notify skipped/fallback for '%s': %s", approval_id, e)
        ipc_res = {"status": "db_polled", "note": str(e)}

    return {
        "status": "success",
        "action": "APPROVED",
        "approval_id": approval_id,
        "resolver": resolver,
        "ipc_result": ipc_res,
        "data": db_res
    }


@router.post("/{approval_id}/reject")
async def reject_held_call(
    approval_id: str,
    resolver: str = Query("admin", description="Identity of rejecting administrator"),
    db: AsyncSession = Depends(get_db)
):
    """Reject a held tool invocation. Prevents downstream execution and returns security rejection."""
    record = await get_approval_by_id(approval_id, session=db)
    if not record:
        raise HTTPException(status_code=404, detail=f"Approval record '{approval_id}' not found")

    if record["status"] != "PENDING":
        return {
            "status": "already_resolved",
            "approval_id": approval_id,
            "current_status": record["status"],
            "message": f"Approval was already resolved as '{record['status']}'."
        }

    # 1. Update DB directly FIRST
    db_res = await update_approval_status(
        approval_id=approval_id,
        status="REJECTED",
        resolved_by=resolver,
        session=db
    )

    # 2. Dispatch IPC command to proxy control server
    ipc_res = None
    try:
        ipc_res = await send_proxy_control_command(
            action="reject_call",
            params={"approval_id": approval_id, "resolver": resolver}
        )
    except Exception as e:
        logger.info("Proxy control IPC notify skipped/fallback for '%s': %s", approval_id, e)
        ipc_res = {"status": "db_polled", "note": str(e)}

    return {
        "status": "success",
        "action": "REJECTED",
        "approval_id": approval_id,
        "resolver": resolver,
        "ipc_result": ipc_res,
        "data": db_res
    }
