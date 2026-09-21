"""Data models for Risk Engine decisions and pipeline scoring."""

from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class EnforcementDecision(str, Enum):
    """Enforcement outcome produced by the deterministic Risk Engine."""
    ALLOW = "ALLOW"
    HOLD = "HOLD"
    BLOCK = "BLOCK"


class RiskScores(BaseModel):
    """Four distinct graded scores (0-100) produced by Stages 2-5."""
    capability_risk: Optional[float] = None
    intent_risk: Optional[float] = None
    behaviour_risk: Optional[float] = None
    response_risk: Optional[float] = None


class SecurityEventRecord(BaseModel):
    """Complete explainable record of an intercepted call and its evaluation."""
    event_id: Optional[str] = None
    timestamp: str
    server_name: str
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    user_prompt: Optional[str] = None

    # Stage 1 Hash details
    expected_hash: Optional[str] = None
    observed_hash: Optional[str] = None
    hash_matched: Optional[bool] = None

    # Graded scores (Stages 2-5)
    scores: RiskScores = Field(default_factory=RiskScores)

    # Risk Engine decision & explanation (Stage 6)
    decision: EnforcementDecision = EnforcementDecision.ALLOW
    reason: str = "Call passed all active pipeline checks"
    hard_gate_triggered: Optional[str] = None
    action_taken: str = "Tool call forwarded"

    # Tool execution result or error
    is_error: bool = False
    result_content: Optional[Any] = None
