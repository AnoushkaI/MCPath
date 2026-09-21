"""Stage 2: Capability Risk.

Question: "Could this call, or the path it's part of, reach somewhere dangerous?"
Specification:
- Causal capability graph: Agent -> Tool -> Data/Resource -> Action -> External Destination
- Scored on explicit attributes: data sensitivity, action sensitivity, external exposure, chain length
- Represents possible attack or capability paths (e.g. read_customer -> send_email)
"""

from mcpath.pipeline.stage import BasePipelineStage, PipelineContext, StageResult


class Stage2CapabilityRisk(BasePipelineStage):
    """Stage 2: Capability Graph Risk Scorer."""

    def __init__(self):
        super().__init__("Stage 2 - Capability Risk")

    async def process_request(self, context: PipelineContext) -> StageResult:
        """Evaluate capability risk based on graph path attributes.

        [TODO Day 5-6: Walk NetworkX capability graph, calculate path risk score 0-100]
        """
        # Day 1 placeholder: passthrough
        context.event_record.scores.capability_risk = 0.0

        return StageResult(
            stage_name=self.name,
            score=0.0,
            passed=True,
            explanation="Stage 2 passthrough mode active (Day 1)",
            metadata={"path": [context.tool_name]}
        )
