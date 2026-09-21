"""Deterministic Risk Engine (Stage 6).

Combines capability, intent, behaviour, and response scores into an overall decision.
Rules:
- Strictly deterministic logic: NO LLM makes the enforcement decision.
- Hard-block gates evaluated first (e.g. hash mismatch upstream, confirmed exfiltration path).
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
        """Evaluate event scores and hard-block gates deterministically.

        [TODO Day 11: Implement full weighted combination logic and multi-stage gates]
        """
        # 1. Check upstream hard gates (e.g. Hash mismatch from Stage 1)
        if event.hash_matched is False:
            event.decision = EnforcementDecision.BLOCK
            event.hard_gate_triggered = "hash mismatch"
            event.reason = "Tool definition changed after approval (rug pull detected)"
            event.action_taken = "Tool call not forwarded"
            return event

        # 2. Check individual critical scores (Day 11 TODO)
        scores = event.scores
        active_scores = [s for s in [scores.capability_risk, scores.intent_risk, scores.behaviour_risk, scores.response_risk] if s is not None]

        if not active_scores:
            # Default Day 1 passthrough
            event.decision = EnforcementDecision.ALLOW
            event.reason = "Passthrough mode active (Day 1)"
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
