"""Semi-Automated Evaluation Runner for MCPath.

Discovers configured MCP tools, manages safe sandbox environments,
executes controlled scenarios through the actual MCPath proxy and 6-stage pipeline,
compares expected vs actual decisions, attributes unexpected outcomes to specific stages,
and compiles empirical evaluation metrics.
"""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import shutil
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

from mcp.client._memory import create_client_server_memory_streams
from mcp.client.session import ClientSession
import mcp.types as types

from mcpath.backend.persistence.database import (
    get_approved_hash,
    init_db,
    register_trusted_server_and_tools,
)
from mcpath.config.settings import (
    ServerConfig,
    ServerDefinition,
    interpolate_server_config,
    settings,
)
from mcpath.evaluation.metrics import MetricReport, calculate_metrics
from mcpath.evaluation.models import (
    ClaudeDesktopManualStatus,
    EvaluationCategory,
    OutcomeVerdict,
    SafetyClassification,
    ScenarioDefinition,
    ScenarioExecutionResult,
    StageOutcome,
)
from mcpath.evaluation.scenarios import get_evaluation_scenarios
from mcpath.pipeline.pipeline_runner import PipelineRunner
from mcpath.pipeline.stages.stage1_hash import canonicalize_and_hash
from mcpath.proxy.client_manager import DownstreamClientManager
from mcpath.proxy.server import create_proxy_server
from mcpath.risk_engine.models import EnforcementDecision

logger = logging.getLogger("mcpath.evaluation.runner")


class EvaluationSandboxManager:
    """Manages temporary sandbox directories and test assets to guarantee repeatable, non-destructive tests."""

    def __init__(self, base_path: Optional[str] = None):
        fs_allowed = settings.filesystem_allowed_paths
        if fs_allowed and Path(fs_allowed.strip()).exists():
            self.base_dir = Path(fs_allowed.strip()) / "temp_eval_sandbox"
        else:
            self.base_dir = Path(tempfile.gettempdir()) / "mcpath_eval_sandbox"

    def setup(self) -> Path:
        """Create sandbox directory and populate harmless test files."""
        if self.base_dir.exists():
            shutil.rmtree(self.base_dir, ignore_errors=True)
        self.base_dir.mkdir(parents=True, exist_ok=True)

        # Populate harmless test files
        (self.base_dir / "readme.txt").write_text(
            "MCPath Zero-Trust Security Proxy Evaluation Sandbox.\nSafe test documentation file.",
            encoding="utf-8"
        )
        (self.base_dir / "config.json").write_text(
            json.dumps({"env": "test", "proxy": "mcpath", "safe": True}, indent=2),
            encoding="utf-8"
        )
        (self.base_dir / "output.log").write_text(
            "2026-09-28 [INFO] Initial test log entry for edit/move verification.",
            encoding="utf-8"
        )
        (self.base_dir / "customers.csv").write_text(
            "id,name,role,department\n1,Alice,Engineer,Security\n2,Bob,Analyst,SOC\n",
            encoding="utf-8"
        )
        # Dummy 1x1 png file header
        (self.base_dir / "sample.png").write_bytes(
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4"
        )
        logger.info("Evaluation sandbox initialized at: %s", self.base_dir)
        return self.base_dir

    def cleanup(self) -> None:
        """Clean up sandbox directory and restore pristine state."""
        try:
            if self.base_dir.exists():
                shutil.rmtree(self.base_dir, ignore_errors=True)
                logger.info("Evaluation sandbox cleanly removed: %s", self.base_dir)
        except Exception as e:
            logger.warning("Could not cleanly remove sandbox %s: %s", self.base_dir, e)


class EvaluationRunner:
    """Semi-automated evaluation runner executing test scenarios through MCPath proxy."""

    def __init__(
        self,
        client_manager: Optional[DownstreamClientManager] = None,
        pipeline_runner: Optional[PipelineRunner] = None,
        scenarios: Optional[List[ScenarioDefinition]] = None,
        sandbox_path: Optional[str] = None
    ):
        self.client_manager = client_manager
        self.pipeline_runner = pipeline_runner
        self.sandbox_manager = EvaluationSandboxManager(base_path=sandbox_path)
        self.scenarios = scenarios or []
        self.results: List[ScenarioExecutionResult] = []

    def load_default_scenarios(self, sandbox_str: str) -> None:
        """Load default scenarios covering all 41 tools across the 5 servers."""
        self.scenarios = get_evaluation_scenarios(sandbox_dir=sandbox_str)

    async def initialize_environment(self) -> Tuple[DownstreamClientManager, PipelineRunner, str]:
        """Initialize sandbox, downstream client manager, and pipeline runner."""
        sandbox_path = self.sandbox_manager.setup()
        sandbox_str = str(sandbox_path).replace("\\", "/")

        if not self.scenarios:
            self.load_default_scenarios(sandbox_str)

        # Setup Client Manager if not provided
        if not self.client_manager:
            server_config = settings.get_server_config()
            server_defs: Dict[str, ServerDefinition] = {}
            for s_name in server_config.active_servers:
                if s_name in server_config.servers:
                    server_defs[s_name] = interpolate_server_config(server_config.servers[s_name], settings)

            self.client_manager = DownstreamClientManager(server_defs=server_defs)
            logger.info("Starting all configured downstream servers for evaluation...")
            await self.client_manager.start_all_servers()

        # Setup Pipeline Runner if not provided
        if not self.pipeline_runner:
            self.pipeline_runner = PipelineRunner(persist_events=True)

        # Pre-warm Stage 3 sentence transformer model to separate model load time from scenario latency
        logger.info("Pre-warming Stage 3 sentence transformer model...")
        try:
            from mcpath.pipeline.stages.stage3_intent import get_intent_model
            get_intent_model()
        except Exception as e:
            logger.warning("Could not pre-warm intent model: %s", e)

        return self.client_manager, self.pipeline_runner, sandbox_str

    async def execute_scenario(
        self,
        scenario: ScenarioDefinition,
        client_session: ClientSession,
        discovered_tools: Dict[str, types.Tool]
    ) -> ScenarioExecutionResult:
        """Execute a single scenario through the proxy and pipeline, and compare outcomes."""
        start_time = time.perf_counter()
        tool_name = scenario.tool_name
        server_name = scenario.server_name

        # Resolve exposed tool name (namespaced collision handling)
        exposed_name = tool_name
        if tool_name not in discovered_tools:
            # Try namespaced version e.g. filesystem_list_directory or rugpull-test_list_directory
            namespaced = f"{server_name}_{tool_name}"
            if namespaced in discovered_tools:
                exposed_name = namespaced

        # Prepare arguments and attach user prompt for Stage 3 evaluation
        args = dict(scenario.arguments)
        if scenario.user_prompt and "_user_prompt" not in args:
            args["_user_prompt"] = scenario.user_prompt

        # If multi-step cross_tool_sequence is defined, execute preparatory calls first
        if scenario.cross_tool_sequence:
            for step in scenario.cross_tool_sequence:
                step_tool = step.get("tool", "")
                step_server = step.get("server", scenario.server_name)
                step_exp = step_tool
                if step_tool not in discovered_tools and f"{step_server}_{step_tool}" in discovered_tools:
                    step_exp = f"{step_server}_{step_tool}"
                step_args = dict(step.get("args", {}))
                await client_session.call_tool(step_exp, step_args)
        else:
            # Isolated scenario: reset session call history so prior tests do not contaminate DAG mapping
            args["_reset_history"] = True

        actual_decision = "UNKNOWN"
        actual_reason = ""
        exec_status = "SUCCESS"
        exec_error: Optional[str] = None
        contributing_stage: Optional[str] = None
        stage_outcomes: List[StageOutcome] = []

        try:
            # Clear recorded stage results on runner for this isolated call
            if hasattr(self.pipeline_runner, "_recorded_stage_results"):
                self.pipeline_runner._recorded_stage_results = []

            # Invoke tool through MCPath proxy client session
            call_res = await client_session.call_tool(exposed_name, args)

            # Inspect stage results recorded by PipelineRunner
            recorded_stages = getattr(self.pipeline_runner, "_recorded_stage_results", [])
            for r in recorded_stages:
                stage_outcomes.append(StageOutcome(
                    stage_number=r.get("stage_number", 0),
                    stage_name=r.get("stage_name", "Unknown"),
                    passed=bool(r.get("passed", True)),
                    hard_block=bool(r.get("hard_block", False)),
                    score=r.get("score"),
                    explanation=r.get("explanation")
                ))

            # Parse proxy response to extract enforcement decision and reason
            if call_res.is_error:
                error_texts = [c.text for c in (call_res.content or []) if hasattr(c, "text")]
                combined_text = " ".join(error_texts)

                if "MCPath ZERO-TRUST ENFORCEMENT BLOCK" in combined_text or "BLOCK" in combined_text:
                    actual_decision = "BLOCK"
                    actual_reason = combined_text
                    exec_status = "BLOCKED_AS_EXPECTED" if scenario.expected_decision == "BLOCK" else "BLOCKED_BY_PROXY"
                elif "HOLD" in combined_text or "REVIEW" in combined_text:
                    actual_decision = "HOLD"
                    actual_reason = combined_text
                    exec_status = "HELD_BY_PROXY"
                else:
                    # Tool execution error on downstream server (not proxy block)
                    actual_decision = "ALLOW"  # Passed proxy pipeline, failed downstream
                    actual_reason = f"Downstream execution error: {combined_text}"
                    exec_status = "DOWNSTREAM_ERROR"
                    exec_error = combined_text
            else:
                actual_decision = "ALLOW"
                actual_reason = "Forwarded and executed downstream successfully."
                exec_status = "SUCCESS"

        except Exception as e:
            logger.error("Exception during execution of scenario %s: %s", scenario.scenario_id, e)
            exec_status = "ERROR"
            exec_error = str(e)
            actual_decision = "ERROR"
            actual_reason = f"Invocation error: {e}"

        duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

        # Determine outcome verdict (PASS, FALSE_POSITIVE, FALSE_NEGATIVE, EXECUTION_FAILURE)
        if exec_status == "ERROR":
            verdict = OutcomeVerdict.EXECUTION_FAILURE
        elif actual_decision == scenario.expected_decision:
            verdict = OutcomeVerdict.PASS
        elif scenario.expected_decision == "BLOCK" and actual_decision == "HOLD":
            # Security policy intercepted and held the call for review; downstream execution was prevented.
            # This is NOT an attack allowed (not a False Negative).
            verdict = OutcomeVerdict.PASS
        elif scenario.expected_decision in ("BLOCK", "HOLD") and actual_decision == "ALLOW":
            # Critical/dangerous or review-required tool was permitted to execute without authorization
            verdict = OutcomeVerdict.FALSE_NEGATIVE
        elif scenario.expected_decision == "ALLOW" and actual_decision in ("BLOCK", "HOLD"):
            verdict = OutcomeVerdict.FALSE_POSITIVE
        else:
            verdict = OutcomeVerdict.PASS if actual_decision == scenario.expected_decision else OutcomeVerdict.FALSE_POSITIVE

        # Attribute contributing stage for unexpected decision or blocking
        if actual_decision == "BLOCK":
            # Check which stage triggered hard block or highest score
            for so in stage_outcomes:
                if so.hard_block or not so.passed:
                    contributing_stage = so.stage_name
                    break
            if not contributing_stage:
                # Find stage with max score
                max_sc = -1.0
                for so in stage_outcomes:
                    if so.score is not None and so.score > max_sc:
                        max_sc = so.score
                        contributing_stage = so.stage_name
            if not contributing_stage:
                contributing_stage = "Stage 6 — Risk Engine"
        elif verdict == OutcomeVerdict.FALSE_NEGATIVE:
            # Expected block but allowed: attribute to expected blocking stage that failed to block
            contributing_stage = scenario.expected_blocking_stage or "Stage 6 — Risk Engine"

        return ScenarioExecutionResult(
            scenario_id=scenario.scenario_id,
            server_name=scenario.server_name,
            tool_name=scenario.tool_name,
            category=scenario.category.value if hasattr(scenario.category, "value") else str(scenario.category),
            safety=scenario.safety.value if hasattr(scenario.safety, "value") else str(scenario.safety),
            description=scenario.description,
            input_arguments=scenario.arguments,
            user_prompt=scenario.user_prompt,
            expected_decision=scenario.expected_decision,
            expected_blocking_stage=scenario.expected_blocking_stage,
            actual_decision=actual_decision,
            actual_reason=actual_reason,
            outcome_verdict=verdict,
            contributing_stage=contributing_stage,
            stage_outcomes=stage_outcomes,
            execution_status=exec_status,
            execution_error=exec_error,
            duration_ms=duration_ms,
            timestamp=datetime.now(timezone.utc).isoformat(),
            claude_desktop_manual_status=scenario.claude_desktop_manual_status.value if hasattr(scenario.claude_desktop_manual_status, "value") else str(scenario.claude_desktop_manual_status),
            notes=scenario.notes
        )

    async def run_evaluation(
        self,
        server_filter: Optional[str] = None,
        category_filter: Optional[str] = None
    ) -> List[ScenarioExecutionResult]:
        """Execute all configured scenarios through MCPath proxy."""
        mgr, runner, sandbox_str = await self.initialize_environment()
        self.results = []

        try:
            # Create proxy server connected to client_manager and pipeline_runner
            proxy_server = create_proxy_server(
                client_manager=mgr,
                pipeline_runner=runner,
                server_name="mcpath-eval-proxy"
            )

            # Connect simulated Claude Desktop ClientSession via memory streams
            async with create_client_server_memory_streams() as (c2p_c, c2p_s):
                async with asyncio.TaskGroup() as tg:
                    tg.create_task(
                        proxy_server.run(*c2p_s, proxy_server.create_initialization_options())
                    )

                    async with ClientSession(*c2p_c) as client_session:
                        init_res = await client_session.initialize()
                        logger.info("Evaluation ClientSession connected to %s", init_res.server_info.name)

                        # Discover exposed tools
                        tools_res = await client_session.list_tools()
                        discovered_tools = {t.name: t for t in tools_res.tools}
                        logger.info("Proxy exposed %d tools across connected servers", len(discovered_tools))

                        # Filter scenarios
                        active_scenarios = self.scenarios
                        if server_filter:
                            active_scenarios = [s for s in active_scenarios if s.server_name == server_filter]
                        if category_filter:
                            active_scenarios = [s for s in active_scenarios if s.category.value == category_filter or s.category == category_filter]

                        logger.info("Executing %d evaluation scenarios...", len(active_scenarios))

                        for sc in active_scenarios:
                            res = await self.execute_scenario(
                                scenario=sc,
                                client_session=client_session,
                                discovered_tools=discovered_tools
                            )
                            self.results.append(res)
                            logger.info(
                                "Scenario [%s] on %s:%s -> %s (Verdict: %s, %s ms)",
                                res.scenario_id,
                                res.server_name,
                                res.tool_name,
                                res.actual_decision,
                                res.outcome_verdict.value,
                                res.duration_ms
                            )

        finally:
            self.sandbox_manager.cleanup()

        return self.results

    def compute_metrics(self) -> MetricReport:
        """Compute empirical precision, recall, F1, FPR, FNR, and latency."""
        # True Positive: Intercepted attack/dangerous operations (BLOCK or HOLD)
        tp = sum(
            1 for r in self.results
            if r.expected_decision in ("BLOCK", "HOLD")
            and r.actual_decision in ("BLOCK", "HOLD")
            and r.category in (
                EvaluationCategory.DANGEROUS,
                EvaluationCategory.CROSS_TOOL_ATTACK,
                EvaluationCategory.RUG_PULL,
                EvaluationCategory.INTENT_MISMATCH,
            )
        )
        # False Positive: Harmless operations blocked or erroneously held
        fp = sum(
            1 for r in self.results
            if r.outcome_verdict == OutcomeVerdict.FALSE_POSITIVE
        )
        # True Negative: Harmless operations allowed
        tn = sum(
            1 for r in self.results
            if r.expected_decision == "ALLOW" and r.actual_decision == "ALLOW"
        )
        # False Negative: Attack permitted to execute downstream
        fn = sum(
            1 for r in self.results
            if r.outcome_verdict == OutcomeVerdict.FALSE_NEGATIVE
        )
        # Average block/hold latency for intercepted calls
        block_latencies = [
            r.duration_ms for r in self.results
            if r.duration_ms > 0 and r.actual_decision in ("BLOCK", "HOLD")
        ]
        if not block_latencies:
            block_latencies = [r.duration_ms for r in self.results if r.duration_ms > 0]

        return calculate_metrics(
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            latencies=block_latencies
        )
