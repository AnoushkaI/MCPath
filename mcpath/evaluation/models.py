"""Data models for the MCPath semi-automated evaluation system."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class EvaluationCategory(str, Enum):
    """Evaluation test category."""
    HARMLESS = "harmless"
    DANGEROUS = "dangerous"
    CROSS_TOOL_ATTACK = "cross_tool_attack"
    RUG_PULL = "rug_pull"
    INTENT_MISMATCH = "intent_mismatch"
    BEHAVIOURAL_DEVIATION = "behavioural_deviation"


class OutcomeVerdict(str, Enum):
    """Test outcome comparison verdict."""
    PASS = "PASS"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    FALSE_NEGATIVE = "FALSE_NEGATIVE"
    EXECUTION_FAILURE = "EXECUTION_FAILURE"


class ClaudeDesktopManualStatus(str, Enum):
    """Status of manual verification through Claude Desktop natural language interface."""
    VERIFIED_MANUALLY = "VERIFIED_MANUALLY"
    PENDING_MANUAL_REVIEW = "PENDING_MANUAL_REVIEW"
    NOT_APPLICABLE_SYSTEM_LEVEL = "NOT_APPLICABLE_SYSTEM_LEVEL"


class SafetyClassification(str, Enum):
    """Execution safety classification."""
    SAFE_AUTOMATED = "SAFE_AUTOMATED"
    MANUAL_REVIEW_SAFEGUARDED = "MANUAL_REVIEW_SAFEGUARDED"


@dataclass
class ScenarioDefinition:
    """Definition of an evaluation scenario."""
    scenario_id: str
    server_name: str
    tool_name: str
    category: EvaluationCategory
    safety: SafetyClassification
    description: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    user_prompt: Optional[str] = None
    expected_decision: str = "ALLOW"  # ALLOW, HOLD, BLOCK
    expected_blocking_stage: Optional[str] = None  # Stage1, Stage2, Stage3, Stage4, Stage5, RiskEngine
    claude_desktop_manual_status: ClaudeDesktopManualStatus = ClaudeDesktopManualStatus.PENDING_MANUAL_REVIEW
    cross_tool_sequence: Optional[List[Dict[str, Any]]] = None  # Multi-tool sequence for chained attacks
    notes: Optional[str] = None


@dataclass
class StageOutcome:
    """Outcome of a single pipeline stage."""
    stage_number: int
    stage_name: str
    passed: bool
    hard_block: bool
    score: Optional[float] = None
    explanation: Optional[str] = None


@dataclass
class ScenarioExecutionResult:
    """Execution result for a single scenario."""
    scenario_id: str
    server_name: str
    tool_name: str
    category: str
    safety: str
    description: str
    input_arguments: Dict[str, Any]
    user_prompt: Optional[str]
    expected_decision: str
    expected_blocking_stage: Optional[str]
    actual_decision: str
    actual_reason: str
    outcome_verdict: OutcomeVerdict
    contributing_stage: Optional[str]
    stage_outcomes: List[StageOutcome]
    execution_status: str  # SUCCESS, BLOCKED_AS_EXPECTED, ERROR
    execution_error: Optional[str] = None
    duration_ms: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    claude_desktop_manual_status: str = ClaudeDesktopManualStatus.PENDING_MANUAL_REVIEW.value
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "scenario_id": self.scenario_id,
            "server_name": self.server_name,
            "tool_name": self.tool_name,
            "category": self.category,
            "safety": self.safety,
            "description": self.description,
            "input_arguments": self.input_arguments,
            "user_prompt": self.user_prompt,
            "expected_decision": self.expected_decision,
            "expected_blocking_stage": self.expected_blocking_stage,
            "actual_decision": self.actual_decision,
            "actual_reason": self.actual_reason,
            "outcome_verdict": self.outcome_verdict.value if hasattr(self.outcome_verdict, "value") else str(self.outcome_verdict),
            "contributing_stage": self.contributing_stage,
            "stage_outcomes": [
                {
                    "stage_number": s.stage_number,
                    "stage_name": s.stage_name,
                    "passed": s.passed,
                    "hard_block": s.hard_block,
                    "score": s.score,
                    "explanation": s.explanation,
                }
                for s in self.stage_outcomes
            ],
            "execution_status": self.execution_status,
            "execution_error": self.execution_error,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp,
            "claude_desktop_manual_status": self.claude_desktop_manual_status,
            "notes": self.notes,
        }
