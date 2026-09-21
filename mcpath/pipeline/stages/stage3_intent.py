"""Stage 3: Intent Risk.

Question: "Does this call match what the user actually asked for?"
Specification:
- Compares user's stated request and the tool/action called via semantic similarity
- Uses sentence-transformers (all-MiniLM-L6-v2) cosine distance against fixed threshold
- Implemented as a graded score (0-100) handed forward to the Risk Engine
"""

from mcpath.pipeline.stage import BasePipelineStage, PipelineContext, StageResult


class Stage3IntentRisk(BasePipelineStage):
    """Stage 3: Semantic Intent Verification."""

    def __init__(self, similarity_threshold: float = 0.70):
        super().__init__("Stage 3 - Intent Risk")
        self.similarity_threshold = similarity_threshold

    async def process_request(self, context: PipelineContext) -> StageResult:
        """Evaluate semantic similarity between user prompt and tool invocation.

        [TODO Day 7: Compute sentence-transformers embedding cosine similarity and map to risk score 0-100]
        """
        # Day 1 placeholder: passthrough
        context.event_record.scores.intent_risk = 0.0

        return StageResult(
            stage_name=self.name,
            score=0.0,
            passed=True,
            explanation="Stage 3 passthrough mode active (Day 1)",
            metadata={"user_prompt": context.user_prompt}
        )
