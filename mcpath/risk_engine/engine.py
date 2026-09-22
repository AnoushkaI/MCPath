"""Deterministic Risk Engine (Stage 6).

Combines capability, intent, behaviour, and response scores into an overall decision.
Rules:
- Strictly deterministic logic: NO LLM makes the enforcement decision.
- Hard-block gates evaluated first (e.g. hash mismatch upstream, no approved baseline, confirmed exfiltration path).
- Explicit thresholds for ALLOW / HOLD / BLOCK.
"""

import logging
from mcpath.risk_engine.models import EnforcementDecision, RiskScores, SecurityEventRecord

logger = logging.getLogger("mcpath.risk_engine")


class RiskEngine:
    """Deterministic Risk Engine evaluator."""

    def __init__(
        self,
        low_threshold: float = 30.0,
        high_threshold: float = 70.0
    ):
        self.low_threshold = low_threshold
        self.high_threshold = high_threshold

    def evaluate(
        self,
        event: SecurityEventRecord
    ) -> SecurityEventRecord:
        """Evaluate event scores and hard-block gates deterministically."""
        # 1. Check upstream Stage 1 hard gates (Hash mismatch or missing baseline)
        if event.hash_matched is False:
            event.decision = EnforcementDecision.BLOCK
            if event.expected_hash is None:
                event.hard_gate_triggered = "no approved baseline"
                event.reason = "Tool has no active approved baseline in PostgreSQL database (NO_APPROVED_BASELINE)"
            else:
                event.hard_gate_triggered = "hash mismatch"
                event.reason = "Tool definition changed after approval (rug pull detected)"
            event.action_taken = "Tool call not forwarded"
            return event

        # 2. Check individual critical scores (Stages 2 - 5)
        scores = event.scores
        active_scores = [s for s in [scores.capability_risk, scores.intent_risk, scores.behaviour_risk, scores.response_risk] if s is not None]

        if not active_scores:
            # Default passthrough when all gates passed and no downstream risk flags
            event.decision = EnforcementDecision.ALLOW
            event.reason = "Tool definition verified against approved baseline"
            event.action_taken = "Tool call forwarded"
            return event

        max_score = max(active_scores)
        if max_score >= self.high_threshold:
            event.decision = EnforcementDecision.BLOCK
            event.reason = f"High risk score detected (max score: {max_score:.1f} >= {self.high_threshold})"
            event.action_taken = "Tool call blocked"
        elif max_score >= self.low_threshold:
            event.decision = EnforcementDecision.HOLD
            event.reason = f"Medium risk score detected (max score: {max_score:.1f} >= {self.low_threshold})"
            event.action_taken = "Tool call held for review"
        else:
            event.decision = EnforcementDecision.ALLOW
            event.reason = "All active risk scores within low-risk thresholds"
            event.action_taken = "Tool call forwarded"

        return event
