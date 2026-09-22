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
import sys
from typing import Any, Callable, Coroutine, Dict, List, Optional
from mcpath.backend.persistence.database import persist_security_event
from mcpath.pipeline.stage import PipelineContext, StageResult
from mcpath.pipeline.stages.stage1_hash import Stage1HashCheck
from mcpath.pipeline.stages.stage2_capability import Stage2CapabilityRisk
from mcpath.pipeline.stages.stage3_intent import Stage3IntentRisk
from mcpath.pipeline.stages.stage4_behaviour import Stage4BehaviourDeviation
from mcpath.pipeline.stages.stage5_response import Stage5ResponseRisk
from mcpath.risk_engine.engine import RiskEngine
from mcpath.risk_engine.explainability import format_explanation
from mcpath.risk_engine.models import EnforcementDecision, SecurityEventRecord

logger = logging.getLogger("mcpath.pipeline")


class PipelineRunner:
    """Coordinates sequential pipeline evaluation across all stages with DB audit persistence."""

    def __init__(
        self,
        stage1: Optional[Stage1HashCheck] = None,
        stage2: Optional[Stage2CapabilityRisk] = None,
        stage3: Optional[Stage3IntentRisk] = None,
        stage4: Optional[Stage4BehaviourDeviation] = None,
        stage5: Optional[Stage5ResponseRisk] = None,
        risk_engine: Optional[RiskEngine] = None,
        persist_events: bool = True
    ):
        self.stage1 = stage1 or Stage1HashCheck()
        self.stage2 = stage2 or Stage2CapabilityRisk()
        self.stage3 = stage3 or Stage3IntentRisk()
        self.stage4 = stage4 or Stage4BehaviourDeviation()
        self.stage5 = stage5 or Stage5ResponseRisk()
        self.risk_engine = risk_engine or RiskEngine()
        self.persist_events = persist_events
        self._recorded_stage_results: List[Dict[str, Any]] = []

    def _print_terminal_alert(
        self,
        context: PipelineContext,
        stage_num: Optional[int] = None,
        stage_name: Optional[str] = None,
        stage_res: Optional[StageResult] = None,
        stage_res_list: Optional[List[StageResult]] = None,
    ) -> None:
        """Print a concise, highly visible security alert to stderr for immediate terminal visibility."""
        event = context.event_record
        server_name = context.server_name or (event.server_name if event else "")
        tool_name = context.tool_name or (event.tool_name if event else "")

        if server_name and tool_name:
            if tool_name.startswith(f"{server_name}:"):
                tool_str = tool_name
            else:
                tool_str = f"{server_name}:{tool_name}"
        elif tool_name:
            tool_str = tool_name
        else:
            tool_str = "unknown"

        stage_display_names = {
            1: "1 — Hash Check",
            2: "2 — Capability Risk",
            3: "3 — Intent Risk",
            4: "4 — Behaviour Deviation",
            5: "5 — Response Risk",
        }

        if stage_num and not stage_name:
            stage_name = stage_display_names.get(stage_num, f"{stage_num} — Unknown")
        elif not stage_name and stage_res_list:
            trigger_num = None
            trigger_res = None
            for idx, s_res in enumerate(stage_res_list, start=2):
                if s_res and s_res.hard_block:
                    trigger_num = idx
                    trigger_res = s_res
                    break
            if not trigger_num:
                max_score = -1.0
                for idx, s_res in enumerate(stage_res_list, start=2):
                    if s_res and s_res.score is not None and s_res.score > max_score:
                        max_score = s_res.score
                        trigger_num = idx
                        trigger_res = s_res
            if trigger_num:
                stage_num = trigger_num
                stage_name = stage_display_names.get(trigger_num, f"{trigger_num} — Unknown")
                stage_res = trigger_res
            else:
                stage_name = "6 — Risk Engine"
        elif not stage_name:
            stage_name = "1 — Hash Check"

        # Determine reason and rug-pull status
        is_rug_pull = False
        if stage_num == 1 or (stage_name and "Hash Check" in stage_name):
            if (
                (event and event.hard_gate_triggered == "hash mismatch")
                or (stage_res and stage_res.metadata and stage_res.metadata.get("reason") == "HASH_MISMATCH")
                or (event and event.expected_hash and event.observed_hash and event.expected_hash != event.observed_hash)
            ):
                is_rug_pull = True
                reason = "HASH MISMATCH (Rug Pull)"
            elif (
                (event and event.hard_gate_triggered == "no approved baseline")
                or (stage_res and stage_res.metadata and stage_res.metadata.get("reason") == "NO_APPROVED_BASELINE")
            ):
                reason = "NO APPROVED BASELINE"
            else:
                reason = (stage_res.explanation if stage_res and stage_res.explanation else (event.reason if event else "")) or "INTEGRITY CHECK FAILED"
        else:
            reason = (stage_res.explanation if stage_res and stage_res.explanation else (event.reason if event else "")) or "CRITICAL RISK THRESHOLD EXCEEDED"

        action = "BLOCK — NOT FORWARDED"

        lines = [
            "=" * 60,
            "🚨 MCPath SECURITY BLOCK",
            f"{'Tool:'.ljust(12)}{tool_str}",
            f"{'Stage:'.ljust(12)}{stage_name}",
            f"{'Reason:'.ljust(12)}{reason}",
        ]

        if is_rug_pull and event:
            expected_h = event.expected_hash or (stage_res.metadata.get("expected_hash") if stage_res and stage_res.metadata else "")
            observed_h = event.observed_hash or (stage_res.metadata.get("observed_hash") if stage_res and stage_res.metadata else "")
            if expected_h:
                lines.append(f"{'Expected:'.ljust(12)}{expected_h}")
            if observed_h:
                lines.append(f"{'Observed:'.ljust(12)}{observed_h}")

        lines.append(f"{'Action:'.ljust(12)}{action}")
        lines.append("=" * 60)

        alert_text = "\n" + "\n".join(lines) + "\n"
        try:
            sys.stderr.write(alert_text)
            sys.stderr.flush()
        except UnicodeEncodeError:
            safe_text = alert_text.encode("ascii", errors="replace").decode("ascii")
            sys.stderr.write(safe_text)
            sys.stderr.flush()
        except Exception as e:
            logger.error("Failed to write security alert to stderr: %s", e)

    async def run_pre_call(self, context: PipelineContext) -> SecurityEventRecord:
        """Run Stages 1 through 4 and pre-execution Risk Engine decision."""
        self._recorded_stage_results = []

        # 1. Stage 1: Hash Check (Hard Gate)
        res1 = await self.stage1.process_request(context)
        self._recorded_stage_results.append({
            "stage_number": 1,
            "stage_name": res1.stage_name,
            "passed": res1.passed,
            "hard_block": res1.hard_block,
            "score": res1.score,
            "explanation": res1.explanation,
            "metadata": res1.metadata
        })

        if res1.hard_block:
            context.event_record.hash_matched = False
            self.risk_engine.evaluate(context.event_record)
            logger.warning("Stage 1 Hard Block triggered: %s", res1.explanation)

            # Record Stages 2-5 as NOT_EXECUTED / N/A
            for stage_num, stage_name in [
                (2, "Stage 2 - Capability Risk"),
                (3, "Stage 3 - Intent Risk"),
                (4, "Stage 4 - Behaviour Deviation"),
                (5, "Stage 5 - Response Risk")
            ]:
                self._recorded_stage_results.append({
                    "stage_number": stage_num,
                    "stage_name": stage_name,
                    "passed": False,
                    "hard_block": False,
                    "score": None,
                    "explanation": "NOT_EXECUTED: Blocked prior to evaluation by Stage 1 Hash Integrity Check",
                    "metadata": {"status": "NOT_EXECUTED", "reason": "STAGE_1_BLOCK"}
                })
            
            # Concise, highly visible security alert to stderr
            self._print_terminal_alert(context, stage_num=1, stage_name="1 — Hash Check", stage_res=res1)

            # Persist blocked event immediately
            if self.persist_events:
                try:
                    await persist_security_event(
                        context.event_record.model_dump(),
                        stage_results=self._recorded_stage_results
                    )
                except Exception as e:
                    logger.error("Failed to persist blocked security event: %s", e)

            return context.event_record

        # 2. Stage 2: Capability Risk
        res2 = await self.stage2.process_request(context)
        context.event_record.scores.capability_risk = res2.score
        self._recorded_stage_results.append({
            "stage_number": 2,
            "stage_name": res2.stage_name,
            "passed": res2.passed,
            "hard_block": res2.hard_block,
            "score": res2.score,
            "explanation": res2.explanation,
            "metadata": res2.metadata
        })

        # 3. Stage 3: Intent Risk
        res3 = await self.stage3.process_request(context)
        context.event_record.scores.intent_risk = res3.score
        self._recorded_stage_results.append({
            "stage_number": 3,
            "stage_name": res3.stage_name,
            "passed": res3.passed,
            "hard_block": res3.hard_block,
            "score": res3.score,
            "explanation": res3.explanation,
            "metadata": res3.metadata
        })

        # 4. Stage 4: Behaviour Deviation
        res4 = await self.stage4.process_request(context)
        context.event_record.scores.behaviour_risk = res4.score
        self._recorded_stage_results.append({
            "stage_number": 4,
            "stage_name": res4.stage_name,
            "passed": res4.passed,
            "hard_block": res4.hard_block,
            "score": res4.score,
            "explanation": res4.explanation,
            "metadata": res4.metadata
        })

        # 5. Risk Engine pre-call evaluation
        self.risk_engine.evaluate(context.event_record)

        # If pre-call evaluation results in BLOCK (e.g. from any other gate), persist now
        if context.event_record.decision == EnforcementDecision.BLOCK:
            self._print_terminal_alert(context, stage_res_list=[res2, res3, res4])
            if self.persist_events:
                try:
                    await persist_security_event(
                        context.event_record.model_dump(),
                        stage_results=self._recorded_stage_results
                    )
                except Exception as e:
                    logger.error("Failed to persist pre-call blocked security event: %s", e)

        return context.event_record

    async def run_post_call(self, context: PipelineContext) -> SecurityEventRecord:
        """Run Stage 5 (Response Risk) and finalize Risk Engine decision."""
        # Stage 5: Response Risk inspection
        res5 = await self.stage5.process_response(context)
        context.event_record.scores.response_risk = res5.score
        self._recorded_stage_results.append({
            "stage_number": 5,
            "stage_name": res5.stage_name,
            "passed": res5.passed,
            "hard_block": res5.hard_block,
            "score": res5.score,
            "explanation": res5.explanation,
            "metadata": res5.metadata
        })

        # Final Risk Engine evaluation
        self.risk_engine.evaluate(context.event_record)

        if context.event_record.decision == EnforcementDecision.BLOCK:
            self._print_terminal_alert(context, stage_num=5, stage_name="5 — Response Risk", stage_res=res5)

        # Persist full completed event
        if self.persist_events:
            try:
                await persist_security_event(
                    context.event_record.model_dump(),
                    stage_results=self._recorded_stage_results
                )
            except Exception as e:
                logger.error("Failed to persist post-call security event: %s", e)

        return context.event_record
