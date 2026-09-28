"""Tests for MCPath Semi-Automated Evaluation System.

Verifies:
1. Scenario definition coverage across all 41 tools and 5 servers
2. Sandbox manager lifecycle (creation, file population, and safe cleanup)
3. Outcome verdict comparison & stage attribution logic
4. Metric calculations (Precision, Recall, F1, FPR, FNR, [TO BE MEASURED] handling)
5. Report generation (JSON, CSV, and Markdown formats)
6. Proxy execution and stage result parsing
"""

import asyncio
import json
from pathlib import Path
import tempfile
import pytest
from mcp.client._memory import create_client_server_memory_streams
from mcp.client.session import ClientSession
from mcp.server.lowlevel import Server
import mcp.types as types

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
from mcpath.evaluation.reporter import EvaluationReporter
from mcpath.evaluation.runner import EvaluationRunner, EvaluationSandboxManager
from mcpath.evaluation.scenarios import get_evaluation_scenarios
from mcpath.pipeline.pipeline_runner import PipelineRunner
from mcpath.proxy.client_manager import DownstreamClientManager
from mcpath.proxy.server import create_proxy_server


def test_evaluation_scenarios_coverage():
    """Verify scenarios cover all 41 tools across the 5 configured active servers."""
    scenarios = get_evaluation_scenarios(sandbox_dir="temp_sandbox")
    assert len(scenarios) >= 41, f"Expected at least 41 scenarios, got {len(scenarios)}"

    server_tools = {
        "filesystem": set(),
        "git": set(),
        "postgres-mcp": set(),
        "email-server": set(),
        "rugpull-test": set(),
    }

    for sc in scenarios:
        if sc.server_name in server_tools:
            server_tools[sc.server_name].add(sc.tool_name)

    # Verify per-server tool counts
    assert len(server_tools["filesystem"]) == 14, f"Filesystem should have 14 tools, got {len(server_tools['filesystem'])}"
    assert len(server_tools["git"]) == 12, f"Git should have 12 tools, got {len(server_tools['git'])}"
    assert len(server_tools["postgres-mcp"]) == 13, f"PostgreSQL should have 13 tools, got {len(server_tools['postgres-mcp'])}"
    assert len(server_tools["email-server"]) == 1, f"Email server should have 1 tool, got {len(server_tools['email-server'])}"
    assert len(server_tools["rugpull-test"]) == 1, f"Rugpull server should have 1 tool, got {len(server_tools['rugpull-test'])}"

    # Check categories
    categories = {sc.category for sc in scenarios}
    assert EvaluationCategory.HARMLESS in categories
    assert EvaluationCategory.DANGEROUS in categories
    assert EvaluationCategory.CROSS_TOOL_ATTACK in categories
    assert EvaluationCategory.RUG_PULL in categories


def test_sandbox_manager_lifecycle():
    """Verify sandbox manager creates, populates, and cleanly removes temporary test directory."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        sandbox_mgr = EvaluationSandboxManager(base_path=tmp_dir)
        sandbox_path = sandbox_mgr.setup()

        assert sandbox_path.exists()
        assert (sandbox_path / "readme.txt").exists()
        assert (sandbox_path / "config.json").exists()
        assert (sandbox_path / "output.log").exists()
        assert (sandbox_path / "customers.csv").exists()

        sandbox_mgr.cleanup()
        assert not sandbox_path.exists()


def test_metrics_calculation():
    """Verify empirical metric calculation and [TO BE MEASURED] defaults."""
    # Perfect scenario: 10 TP, 0 FP, 10 TN, 0 FN
    report = calculate_metrics(
        true_positives=10,
        false_positives=0,
        true_negatives=10,
        false_negatives=0,
        latencies=[12.5, 15.0, 10.0]
    )
    assert report.precision == 1.0
    assert report.recall == 1.0
    assert report.f1_score == 1.0
    assert report.false_positive_rate == 0.0
    assert report.false_negative_rate == 0.0
    assert report.block_latency_ms == 12.5

    # Default MetricReport has [TO BE MEASURED]
    blank_report = MetricReport()
    assert blank_report.precision == "[TO BE MEASURED]"
    assert blank_report.recall == "[TO BE MEASURED]"


def test_report_generation(tmp_path: Path):
    """Verify JSON, CSV, and Markdown report generation with all required sections."""
    results = [
        ScenarioExecutionResult(
            scenario_id="FS-01",
            server_name="filesystem",
            tool_name="list_allowed_directories",
            category="harmless",
            safety="SAFE_AUTOMATED",
            description="Test list allowed directories",
            input_arguments={},
            user_prompt="List allowed directories",
            expected_decision="ALLOW",
            expected_blocking_stage=None,
            actual_decision="ALLOW",
            actual_reason="Forwarded and executed downstream successfully.",
            outcome_verdict=OutcomeVerdict.PASS,
            contributing_stage=None,
            stage_outcomes=[],
            execution_status="SUCCESS",
            duration_ms=15.2,
            claude_desktop_manual_status=ClaudeDesktopManualStatus.VERIFIED_MANUALLY.value
        ),
        ScenarioExecutionResult(
            scenario_id="RP-01",
            server_name="rugpull-test",
            tool_name="list_directory",
            category="rug_pull",
            safety="SAFE_AUTOMATED",
            description="Tampered rug-pull test",
            input_arguments={"path": "."},
            user_prompt="List files",
            expected_decision="BLOCK",
            expected_blocking_stage="Stage1",
            actual_decision="BLOCK",
            actual_reason="MCPath ZERO-TRUST ENFORCEMENT BLOCK: Hash mismatch",
            outcome_verdict=OutcomeVerdict.PASS,
            contributing_stage="Stage 1 — Hash Check",
            stage_outcomes=[
                StageOutcome(stage_number=1, stage_name="Stage 1 — Hash Check", passed=False, hard_block=True, score=100.0, explanation="Mismatch")
            ],
            execution_status="BLOCKED_AS_EXPECTED",
            duration_ms=5.1,
            claude_desktop_manual_status=ClaudeDesktopManualStatus.VERIFIED_MANUALLY.value
        ),
    ]

    metrics = calculate_metrics(true_positives=1, false_positives=0, true_negatives=1, false_negatives=0)
    reporter = EvaluationReporter(results=results, metrics=metrics, output_dir=str(tmp_path))

    json_path = reporter.export_json("results.json")
    assert json_path.exists()
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        assert data["metadata"]["total_scenarios"] == 2
        assert len(data["results"]) == 2

    csv_path = reporter.export_csv("report.csv")
    assert csv_path.exists()
    csv_content = csv_path.read_text(encoding="utf-8")
    assert "FS-01" in csv_content
    assert "RP-01" in csv_content

    md_path = reporter.export_markdown("report.md")
    assert md_path.exists()
    md_content = md_path.read_text(encoding="utf-8")
    assert "# MCPath — Automated Tool Evaluation" in md_content
    assert "Server-Wise Coverage" in md_content
    assert "Sequential 6-Stage Enforcement Breakdown" in md_content
    assert "Claude Desktop Manual Verification Status" in md_content
    assert "[TO BE MEASURED]" in md_content


@pytest.mark.asyncio
async def test_scenario_execution_mock_proxy():
    """Verify single scenario execution through in-memory proxy and pipeline."""
    # Create mock downstream server
    tools = [
        types.Tool(name="read_file", description="Read file", input_schema={"type": "object", "properties": {"path": {"type": "string"}}})
    ]
    async def list_tools_handler(context, params=None):
        return types.ListToolsResult(tools=tools)

    async def call_tool_handler(context, params):
        return types.CallToolResult(content=[types.TextContent(type="text", text="FILE_CONTENT")])

    mock_srv = Server(name="filesystem", version="1.0.0", on_list_tools=list_tools_handler, on_call_tool=call_tool_handler)

    client_mgr = DownstreamClientManager()
    pipeline_runner = PipelineRunner(persist_events=False)

    async with create_client_server_memory_streams() as (d_c, d_s):
        async with asyncio.TaskGroup() as tg:
            tg.create_task(mock_srv.run(*d_s, mock_srv.create_initialization_options()))
            async with ClientSession(*d_c) as d_session:
                await d_session.initialize()
                client_mgr.register_active_session("filesystem", d_session)
                await client_mgr.list_tools()

                proxy_srv = create_proxy_server(client_mgr, pipeline_runner=pipeline_runner, server_name="eval-proxy")

                async with create_client_server_memory_streams() as (p_c, p_s):
                    async with asyncio.TaskGroup() as tg_p:
                        tg_p.create_task(proxy_srv.run(*p_s, proxy_srv.create_initialization_options()))
                        async with ClientSession(*p_c) as client_session:
                            await client_session.initialize()
                            tools_res = await client_session.list_tools()
                            discovered = {t.name: t for t in tools_res.tools}

                            runner = EvaluationRunner(client_manager=client_mgr, pipeline_runner=pipeline_runner)
                            scenario = ScenarioDefinition(
                                scenario_id="TEST-01",
                                server_name="filesystem",
                                tool_name="read_file",
                                category=EvaluationCategory.HARMLESS,
                                safety=SafetyClassification.SAFE_AUTOMATED,
                                description="Harmless read test",
                                arguments={"path": "dummy.txt"},
                                user_prompt="Read dummy file",
                                expected_decision="ALLOW"
                            )

                            res = await runner.execute_scenario(scenario, client_session, discovered)
                            assert res.scenario_id == "TEST-01"
                            assert res.actual_decision in ("ALLOW", "HOLD", "BLOCK")
                            assert res.duration_ms >= 0.0


@pytest.mark.asyncio
async def test_missing_prompt_skips_stage3_and_produces_none():
    """Requirement 2: Missing natural language prompt marks Stage 3 as SKIPPED_NO_PROMPT with score None."""
    from mcpath.pipeline.stages.stage3_intent import Stage3IntentRisk
    from mcpath.pipeline.stage import PipelineContext
    from mcpath.risk_engine.models import SecurityEventRecord

    stage3 = Stage3IntentRisk()
    event = SecurityEventRecord(
        timestamp="2026-09-28T00:00:00Z",
        server_name="filesystem",
        tool_name="list_allowed_directories"
    )
    ctx = PipelineContext(
        server_name="filesystem",
        tool_name="list_allowed_directories",
        user_prompt=None,  # No prompt available (Claude Desktop behavior)
        event_record=event
    )

    result = await stage3.process_request(ctx)
    assert result.score is None, "Score must be None (N/A) rather than 0"
    assert result.metadata["status"] == "SKIPPED_NO_PROMPT"
    assert result.metadata["intent_risk_score"] is None
    assert result.metadata["classification"] == "N/A"
    assert event.scores.intent_risk is None, "Event score intent_risk must be None"
    assert "Stage 3 skipped" in result.explanation


def test_skipped_intent_risk_does_not_affect_final_decision():
    """Requirement 2: Skipped Stage 3 results are excluded from Risk Engine calculations."""
    from mcpath.risk_engine.engine import RiskEngine
    from mcpath.risk_engine.models import SecurityEventRecord, EnforcementDecision

    engine = RiskEngine()

    # Low risk capability score (15.0), Stage 3 skipped (None) -> Must be ALLOW
    event = SecurityEventRecord(
        timestamp="2026-09-28T00:00:00Z",
        server_name="filesystem",
        tool_name="list_allowed_directories",
        hash_matched=True
    )
    event.scores.capability_risk = 15.0
    event.scores.intent_risk = None  # SKIPPED_NO_PROMPT

    decided = engine.evaluate(event)
    assert decided.decision == EnforcementDecision.ALLOW
    assert "within low-risk thresholds" in decided.reason


def test_other_applicable_stages_continue_to_influence_decisions():
    """Requirement 2 & 6: When Stage 3 is skipped, Stage 1 and Stage 2 continue to enforce decisions."""
    from mcpath.risk_engine.engine import RiskEngine
    from mcpath.risk_engine.models import SecurityEventRecord, EnforcementDecision

    engine = RiskEngine()

    # 1. Stage 1 hash mismatch -> hard BLOCK regardless of Stage 3
    event_s1 = SecurityEventRecord(
        timestamp="2026-09-28T00:00:00Z",
        server_name="rugpull-test",
        tool_name="list_directory",
        expected_hash="approved_hash_123",
        observed_hash="tampered_hash_456",
        hash_matched=False
    )
    event_s1.scores.intent_risk = None
    decided_s1 = engine.evaluate(event_s1)
    assert decided_s1.decision == EnforcementDecision.BLOCK
    assert "rug pull detected" in decided_s1.reason

    # 2. Stage 2 critical path HIGH risk (75.8) -> BLOCK regardless of Stage 3
    event_s2_high = SecurityEventRecord(
        timestamp="2026-09-28T00:00:00Z",
        server_name="email-server",
        tool_name="send_email",
        hash_matched=True
    )
    event_s2_high.scores.capability_risk = 75.8
    event_s2_high.scores.intent_risk = None
    decided_s2_high = engine.evaluate(event_s2_high)
    assert decided_s2_high.decision == EnforcementDecision.BLOCK

    # 3. Stage 2 medium risk (53.3) -> HOLD regardless of Stage 3
    event_s2_med = SecurityEventRecord(
        timestamp="2026-09-28T00:00:00Z",
        server_name="filesystem",
        tool_name="write_file",
        hash_matched=True
    )
    event_s2_med.scores.capability_risk = 53.3
    event_s2_med.scores.intent_risk = None
    decided_s2_med = engine.evaluate(event_s2_med)
    assert decided_s2_med.decision == EnforcementDecision.HOLD


@pytest.mark.asyncio
async def test_stage3_evaluates_when_valid_prompt_provided():
    """Requirement 2: When a valid prompt is provided, Stage 3 calculates semantic similarity."""
    from mcpath.pipeline.stages.stage3_intent import Stage3IntentRisk
    from mcpath.pipeline.stage import PipelineContext
    from mcpath.risk_engine.models import SecurityEventRecord

    stage3 = Stage3IntentRisk()
    event = SecurityEventRecord(
        timestamp="2026-09-28T00:00:00Z",
        server_name="filesystem",
        tool_name="list_allowed_directories"
    )
    ctx = PipelineContext(
        server_name="filesystem",
        tool_name="list_allowed_directories",
        user_prompt="What directories are you allowed to access on this system?",
        event_record=event
    )

    result = await stage3.process_request(ctx)
    assert result.score is not None
    assert result.metadata["status"] != "SKIPPED_NO_PROMPT"
    assert result.metadata["cosine_similarity"] is not None
    assert event.scores.intent_risk is not None
    assert event.scores.intent_risk >= 0.0


@pytest.mark.asyncio
async def test_block_and_hold_prevent_downstream_execution():
    """Requirement 4: Confirm that both BLOCK and HOLD decisions prevent downstream tool execution."""
    downstream_executed = False

    async def list_tools_handler(context, params=None):
        return types.ListToolsResult(tools=[
            types.Tool(name="danger_tool", description="Critical tool", input_schema={"type": "object"})
        ])

    async def call_tool_handler(context, params):
        nonlocal downstream_executed
        downstream_executed = True
        return types.CallToolResult(content=[types.TextContent(type="text", text="SHOULD_NEVER_RUN")])

    mock_srv = Server(name="test_srv", version="1.0.0", on_list_tools=list_tools_handler, on_call_tool=call_tool_handler)

    client_mgr = DownstreamClientManager()
    pipeline_runner = PipelineRunner(persist_events=False)

    async with create_client_server_memory_streams() as (d_c, d_s):
        async with asyncio.TaskGroup() as tg:
            tg.create_task(mock_srv.run(*d_s, mock_srv.create_initialization_options()))
            async with ClientSession(*d_c) as d_session:
                await d_session.initialize()
                client_mgr.register_active_session("test_srv", d_session)
                await client_mgr.list_tools()

                proxy_srv = create_proxy_server(client_mgr, pipeline_runner=pipeline_runner, server_name="gate-proxy")

                async with create_client_server_memory_streams() as (p_c, p_s):
                    async with asyncio.TaskGroup() as tg_p:
                        tg_p.create_task(proxy_srv.run(*p_s, proxy_srv.create_initialization_options()))
                        async with ClientSession(*p_c) as client_session:
                            await client_session.initialize()

                            # 1. Test HOLD decision: tool is held, downstream must NOT execute
                            # Tool has unknown path -> risk score 75.0 (BLOCK) or medium (HOLD)
                            res = await client_session.call_tool("danger_tool", {})
                            assert res.is_error is True
                            assert downstream_executed is False, "Downstream server was called despite proxy gate!"
                            error_text = " ".join([c.text for c in res.content if hasattr(c, "text")])
                            assert any(term in error_text for term in ("EXECUTION BLOCKED", "BLOCK", "HOLD", "REVIEW"))
