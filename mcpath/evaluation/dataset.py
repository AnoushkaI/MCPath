"""Dataset schema for evaluation scenarios.

Scenario coverage (Section 6):
1. Normal calls
2. Rug pulls (tampered tool definitions)
3. Dangerous cross-tool capability chains (e.g. read_file -> send_external_http or postgres_mcp_query -> git_commit/push)
4. Intent mismatches (e.g. summarize vs delete_repository)
5. Behavioural deviations (unexpected arguments, irregular destinations)
6. Malicious / prompt-injection tool responses
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AttackCategory(str, Enum):
    NORMAL = "normal"
    RUG_PULL = "rug_pull"
    CAPABILITY_CHAIN = "capability_chain"
    INTENT_MISMATCH = "intent_mismatch"
    BEHAVIOUR_DEVIATION = "behaviour_deviation"
    RESPONSE_INJECTION = "response_injection"


class EvaluationScenario(BaseModel):
    """Single labelled evaluation scenario."""
    scenario_id: str
    category: AttackCategory
    description: str
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    user_prompt: Optional[str] = None
    expected_decision: str = "ALLOW"  # ALLOW, BLOCK, HOLD
    expected_blocking_stage: Optional[str] = None
