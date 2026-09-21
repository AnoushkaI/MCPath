"""Stage 5: Response Risk.

Question: "Is the tool's response trying to do something it shouldn't?"
Specification:
- Inspects tool outputs for prompt injection, hidden instructions, secret-exfiltration requests,
  encoded payloads (base64/hex), and suspicious external URLs.
- Rule-based pattern matching heuristics + secondary bounded-output LLM classifier (Claude Haiku 4.5).
- LLM is a secondary signal, never the sole basis for a block.
"""

from mcpath.pipeline.stage import BasePipelineStage, PipelineContext, StageResult


class Stage5ResponseRisk(BasePipelineStage):
    """Stage 5: Response Risk Inspector."""

    def __init__(self, risk_threshold: float = 0.65):
        super().__init__("Stage 5 - Response Risk")
        self.risk_threshold = risk_threshold

    async def process_request(self, context: PipelineContext) -> StageResult:
        """Pre-execution check (Stage 5 primarily evaluates response post-execution)."""
        return StageResult(stage_name=self.name, passed=True, explanation="Pre-execution check skipped")

    async def process_response(self, context: PipelineContext) -> StageResult:
        """Inspect tool output payload for malicious patterns.

        [TODO Day 10: Rule-based regex heuristics + bounded secondary classifier]
        """
        # Day 1 placeholder: passthrough
        context.event_record.scores.response_risk = 0.0

        return StageResult(
            stage_name=self.name,
            score=0.0,
            passed=True,
            explanation="Stage 5 passthrough mode active (Day 1)",
            metadata={"response_type": type(context.tool_response).__name__}
        )
