"""Stage 4: Behaviour Deviation.

Question: "Is this tool acting the way it normally does?"
Specification:
- Known-good baseline defined per tool from declared capabilities + observed execution traces
- Scores only proxy-observable signals: normal inputs, outputs, API/domain destinations, call sequence
- Plain statistical comparison against stored traces — no ML model required for the MVP
"""

from mcpath.pipeline.stage import BasePipelineStage, PipelineContext, StageResult


class Stage4BehaviourDeviation(BasePipelineStage):
    """Stage 4: Behaviour Deviation Detector."""

    def __init__(self, deviation_threshold: float = 0.60):
        super().__init__("Stage 4 - Behaviour Deviation")
        self.deviation_threshold = deviation_threshold

    async def process_request(self, context: PipelineContext) -> StageResult:
        """Compare call parameters against baseline trace statistics.

        [TODO Day 8-9: Compare arguments, call sequence, destinations against statistical baseline]
        """
        # Day 1 placeholder: passthrough
        context.event_record.scores.behaviour_risk = 0.0

        return StageResult(
            stage_name=self.name,
            score=0.0,
            passed=True,
            explanation="Stage 4 passthrough mode active (Day 1)",
            metadata={"arguments_checked": list(context.arguments.keys())}
        )
