"""Section 7 Explainability Formatter.

Every decision produces attributable evidence across all stages, never a bare 'Blocked'.
"""

from mcpath.risk_engine.models import SecurityEventRecord, EnforcementDecision


def format_explanation(event: SecurityEventRecord) -> str:
    """Format a security event record into the Section 7 standard specification."""
    status_header = f"EXECUTION {event.decision.value}"
    if event.decision == EnforcementDecision.BLOCK:
        status_header = "EXECUTION BLOCKED"
    elif event.decision == EnforcementDecision.HOLD:
        status_header = "EXECUTION HELD FOR REVIEW"
    elif event.decision == EnforcementDecision.ALLOW:
        status_header = "EXECUTION ALLOWED"

    expected_hash_str = event.expected_hash if event.expected_hash else "[NOT SET]"
    observed_hash_str = event.observed_hash if event.observed_hash else "[NOT SET]"

    cap_str = f"{event.scores.capability_risk:.1f}" if event.scores.capability_risk is not None else "[NOT COMPUTED]"
    intent_str = f"{event.scores.intent_risk:.1f}" if event.scores.intent_risk is not None else "[NOT COMPUTED]"
    beh_str = f"{event.scores.behaviour_risk:.1f}" if event.scores.behaviour_risk is not None else "[NOT COMPUTED]"
    resp_str = f"{event.scores.response_risk:.1f}" if event.scores.response_risk is not None else "[NOT COMPUTED]"

    gate_str = f" (hard gate: {event.hard_gate_triggered})" if event.hard_gate_triggered else ""
    overall_str = f"{event.decision.value}{gate_str}"

    lines = [
        status_header,
        f"Reason: {event.reason}",
        f"Expected Hash: {expected_hash_str}",
        f"Observed Hash: {observed_hash_str}",
        f"Capability Risk: {cap_str}",
        f"Intent Risk: {intent_str}",
        f"Behaviour Risk: {beh_str}",
        f"Response Risk: {resp_str}",
        f"Overall Risk: {overall_str}",
        f"Action: {event.action_taken}"
    ]
    return "\n".join(lines)
