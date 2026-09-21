"""Sequential Risk Pipeline Runner.

Enforces strict ordering:
Stage 1 (Hash Check) ->
Stage 2 (Capability Risk) ->
Stage 3 (Intent Risk) ->
Stage 4 (Behaviour Deviation) ->
[Downstream MCP Execution if ALLOW] ->
Stage 5 (Response Risk) ->
Stage 6 (Risk Engine deterministic evaluation)
"""

import logging
from typing import Any, Callable, Coroutine, Optional
from mcpath.pipeline.stage import PipelineContext, StageResult
from mcpath.pipeline.stages.stage1_hash import Stage1HashCheck
from mcpath.pipeline.stages.stage2_capability import Stage2CapabilityRisk
from mcpath.pipeline.stages.stage3_intent import Stage3IntentRisk
from mcpath.pipeline.stages.stage4_behaviour import Stage4BehaviourDeviation
from mcpath.pipeline.stages.stage5_response import Stage5ResponseRisk
from mcpath.risk_engine.engine import RiskEngine
from mcpath.risk_engine.models import EnforcementDecision, SecurityEventRecord
from mcpath.risk_engine.explainability import format_explanation

logger = logging.getLogger("mcpath.pipeline")


class PipelineRunner:
    """Coordinates sequential pipeline evaluation across all stages."""

    def __init__(
        self,
        stage1: Optional[Stage1HashCheck] = None,
        stage2: Optional[Stage2CapabilityRisk] = None,
        stage3: Optional[Stage3IntentRisk] = None,
        stage4: Optional[Stage4BehaviourDeviation] = None,
        stage5: Optional[Stage5ResponseRisk] = None,
        risk_engine: Optional[RiskEngine] = None,
    ):
        self.stage1 = stage1 or Stage1HashCheck()
        self.stage2 = stage2 or Stage2CapabilityRisk()
        self.stage3 = stage3 or Stage3IntentRisk()
        self.stage4 = stage4 or Stage4BehaviourDeviation()
        self.stage5 = stage5 or Stage5ResponseRisk()
        self.risk_engine = risk_engine or RiskEngine()

    async def run_pre_call(self, context: PipelineContext) -> SecurityEventRecord:
        """Run Stages 1 through 4 and pre-execution Risk Engine decision."""
        # 1. Stage 1: Hash Check (Hard Gate)
        res1 = await self.stage1.process_request(context)
        if res1.hard_block:
            context.event_record.hash_matched = False
            self.risk_engine.evaluate(context.event_record)
            logger.warning("Stage 1 Hard Block triggered: %s", res1.explanation)
            return context.event_record

        # 2. Stage 2: Capability Risk
        res2 = await self.stage2.process_request(context)
        context.event_record.scores.capability_risk = res2.score

        # 3. Stage 3: Intent Risk
        res3 = await self.stage3.process_request(context)
        context.event_record.scores.intent_risk = res3.score

        # 4. Stage 4: Behaviour Deviation
        res4 = await self.stage4.process_request(context)
        context.event_record.scores.behaviour_risk = res4.score

        # 5. Risk Engine pre-call evaluation
        self.risk_engine.evaluate(context.event_record)
        return context.event_record

    async def run_post_call(self, context: PipelineContext) -> SecurityEventRecord:
        """Run Stage 5 (Response Risk) and finalize Risk Engine decision."""
        # Stage 5: Response Risk inspection
        res5 = await self.stage5.process_response(context)
        context.event_record.scores.response_risk = res5.score

        # Final Risk Engine evaluation
        self.risk_engine.evaluate(context.event_record)
        return context.event_record
