"""Administrative Approval Queue Manager for Held Tool Invocations.

Coordinates live pauses for calls held by Stage 6 Risk Engine, manages
approval/rejection/timeout events, and persists state in PostgreSQL/SQLite.
"""

import asyncio
from datetime import datetime, timezone
import logging
from typing import Any, Dict, Optional, Tuple
from uuid import uuid4

from mcpath.backend.persistence.database import (
    create_pending_approval,
    get_approval_by_id,
    update_approval_status,
)
from mcpath.pipeline.stage import PipelineContext

logger = logging.getLogger("mcpath.proxy.approval")


class ApprovalManager:
    """Coordinates approval lifecycles for tool calls held for security review."""

    _instance: Optional["ApprovalManager"] = None

    def __init__(self):
        self._events: Dict[str, asyncio.Event] = {}
        self._resolutions: Dict[str, str] = {}  # approval_id -> "APPROVED" | "REJECTED" | "TIMED_OUT"
        self._lock = asyncio.Lock()

    @classmethod
    def get_instance(cls) -> "ApprovalManager":
        """Return global singleton ApprovalManager."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    async def register_hold(
        self,
        context: PipelineContext,
        event_record: Any,
        timeout_seconds: float = 30.0
    ) -> Tuple[str, asyncio.Event]:
        """Register a held tool invocation as a pending approval."""
        approval_id = f"appr_{uuid4().hex[:12]}"
        event = asyncio.Event()

        async with self._lock:
            self._events[approval_id] = event

        event_id = getattr(event_record, "event_id", f"evt_{uuid4().hex[:8]}")
        scores = getattr(event_record, "scores", None)
        active_scores = []
        if scores:
            for s in [scores.capability_risk, scores.intent_risk, scores.behaviour_risk, scores.response_risk]:
                if s is not None:
                    active_scores.append(float(s))
        risk_score = round(max(active_scores), 2) if active_scores else 50.0
        reason = str(getattr(event_record, "reason", "Execution held for administrative review"))

        try:
            await create_pending_approval(
                approval_id=approval_id,
                event_id=event_id,
                server_name=context.server_name,
                tool_name=context.tool_name,
                arguments=context.arguments,
                risk_score=risk_score,
                reason=reason
            )
            logger.info(
                "Registered pending approval '%s' for tool '%s:%s' (Score: %.1f)",
                approval_id, context.server_name, context.tool_name, risk_score
            )
        except Exception as e:
            logger.error("Failed to persist pending approval '%s' to database: %s", approval_id, e)

        return approval_id, event

    async def resolve_approval(
        self,
        approval_id: str,
        action: str,  # "APPROVED" or "REJECTED"
        resolver: str = "admin"
    ) -> Dict[str, Any]:
        """Resolve a pending approval. Prevents replay or duplicate resolutions."""
        norm_action = action.upper()
        if norm_action not in ("APPROVED", "REJECTED", "BLOCK"):
            raise ValueError(f"Invalid resolution action '{action}'. Must be 'APPROVED' or 'REJECTED'")

        if norm_action == "BLOCK":
            norm_action = "REJECTED"

        # 1. Update database
        db_res = await update_approval_status(
            approval_id=approval_id,
            status=norm_action,
            resolved_by=resolver
        )

        if not db_res:
            raise KeyError(f"Approval '{approval_id}' not found")

        if db_res.get("already_resolved"):
            logger.warning("Approval '%s' was already resolved as '%s'", approval_id, db_res.get("status"))
            return db_res

        # 2. Wake up in-memory waiter if active
        async with self._lock:
            self._resolutions[approval_id] = norm_action
            if approval_id in self._events:
                self._events[approval_id].set()

        logger.info("Approval '%s' resolved as '%s' by '%s'", approval_id, norm_action, resolver)
        return db_res

    async def wait_for_decision(
        self,
        approval_id: str,
        timeout_seconds: float = 30.0
    ) -> str:
        """Wait for an approval to be resolved via UI/API, polling DB as backup.
        
        Returns:
            "APPROVED", "REJECTED", or "TIMED_OUT"
        """
        event = self._events.get(approval_id)
        start_time = asyncio.get_event_loop().time()

        while True:
            # Check in-memory resolution first
            if approval_id in self._resolutions:
                res = self._resolutions[approval_id]
                self._cleanup(approval_id)
                return res

            # Wait on event with 1-second slices so we can poll DB
            if event:
                try:
                    await asyncio.wait_for(asyncio.shield(event.wait()), timeout=1.0)
                    if approval_id in self._resolutions:
                        res = self._resolutions[approval_id]
                        self._cleanup(approval_id)
                        return res
                except asyncio.TimeoutError:
                    pass

            # Check DB in case another process (FastAPI backend) updated it
            try:
                db_record = await get_approval_by_id(approval_id)
                if db_record and db_record.get("status") in ("APPROVED", "REJECTED"):
                    status = db_record["status"]
                    async with self._lock:
                        self._resolutions[approval_id] = status
                    self._cleanup(approval_id)
                    return status
            except Exception as e:
                logger.debug("Error checking DB for approval status: %s", e)

            # Check elapsed time
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed >= timeout_seconds:
                break

        # Timed out
        logger.warning("Approval '%s' timed out after %.1f seconds", approval_id, timeout_seconds)
        try:
            await update_approval_status(
                approval_id=approval_id,
                status="TIMED_OUT",
                resolved_by="system:timeout"
            )
        except Exception as e:
            logger.error("Failed to update timed out approval '%s': %s", approval_id, e)

        self._cleanup(approval_id)
        return "TIMED_OUT"

    def _cleanup(self, approval_id: str) -> None:
        """Remove event references once resolved."""
        self._events.pop(approval_id, None)


# Module-level convenience singleton
approval_manager = ApprovalManager.get_instance()
