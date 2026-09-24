"""Comprehensive tests for Stage 3 — Intent Risk.

Covers:
1. Model loading singleton (sentence-transformers with all-MiniLM-L6-v2, loaded once and reused).
2. Strongly matching request/tool -> high similarity -> low intent risk score (< 30.0, LOW).
3. Borderline similarity -> medium intent risk score (30.0 - 70.0, MEDIUM).
4. Obvious mismatch demonstration case:
   User request: "Summarize my latest ticket."
   Actual tool/action: "export all customer records."
   Verified with model embedding cosine similarity producing HIGH intent risk (>= 70.0, HIGH).
5. Stage 3 non-enforcement isolation: Stage 3 produces ONLY scores and attributable evidence.
   It NEVER sets hard_block=True or alters decision directly.
6. Risk Engine integration: Risk Engine remains the ONLY component converting risk signals
   into enforcement decisions (ALLOW, HOLD, BLOCK).
7. Missing user prompt handling: gracefully defaults to 0.0 risk without failure.
8. Configurable policy loading and threshold verification.
9. PostgreSQL persistence: persists IntentEvaluationDB linked to SecurityEventDB with all required fields.
"""

import json
from pathlib import Path
import pytest
import pytest_asyncio
from unittest.mock import MagicMock
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from mcpath.backend.persistence import (
    Base,
    init_db,
    persist_security_event,
    get_intent_evaluation,
    IntentEvaluationDB,
    SecurityEventDB,
    StageResultDB,
)
from mcpath.pipeline.stage import PipelineContext, StageResult
from mcpath.pipeline.stages.stage1_hash import Stage1HashCheck
from mcpath.pipeline.stages.stage2_capability import Stage2CapabilityRisk
from mcpath.pipeline.stages.stage3_intent import (
    Stage3IntentRisk,
    get_intent_model,
    build_tool_action_text,
    compute_cosine_similarity,
)
from mcpath.pipeline.pipeline_runner import PipelineRunner
from mcpath.risk_engine.engine import RiskEngine
from mcpath.risk_engine.models import EnforcementDecision, SecurityEventRecord


@pytest.fixture(scope="module")
def intent_model():
    """Load MiniLM model once for module test suite."""
    return get_intent_model("all-MiniLM-L6-v2")


@pytest_asyncio.fixture
async def test_db_session():
    """Create an isolated in-memory SQLite database session for testing."""
    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(test_engine, expire_on_commit=False, class_=AsyncSession)
    async with session_factory() as session:
        yield session

    await test_engine.dispose()


def test_model_singleton_reuse():
    """Requirement 1: Load model once and reuse it across invocations."""
    m1 = get_intent_model("all-MiniLM-L6-v2")
    m2 = get_intent_model("all-MiniLM-L6-v2")
    assert m1 is m2, "Model singleton must return the identical cached instance"


def test_build_tool_action_text():
    """Requirement 2: Build descriptive tool/action text from tool name, description, schema/action."""
    # 1. Tool with clear description
    text1 = build_tool_action_text(
        tool_name="filesystem_read_file",
        tool_definition={"name": "filesystem_read_file", "description": "Read content of a file."}
    )
    assert "filesystem read file" in text1.lower()
    assert "read content of a file" in text1.lower()

    # 2. Tool without description (cleans underscores)
    text2 = build_tool_action_text(tool_name="export_customer_data")
    assert text2 == "export customer data"

    # 3. Direct natural phrase passed as tool name
    text3 = build_tool_action_text(tool_name="export all customer records.")
    assert text3 == "export all customer records."


@pytest.mark.asyncio
async def test_strong_matching_request_produces_low_intent_risk(intent_model):
    """Requirement 10: Strongly matching request/tool -> low intent risk (< 30.0)."""
    stage3 = Stage3IntentRisk(model=intent_model)

    event = SecurityEventRecord(
        timestamp="2026-09-24T12:00:00Z",
        server_name="filesystem",
        tool_name="read_file",
        arguments={"path": "report.txt"}
    )
    ctx = PipelineContext(
        server_name="filesystem",
        tool_name="read_file",
        tool_definition={"name": "read_file", "description": "Read the contents of a file from the filesystem."},
        user_prompt="Read the contents of a file from the filesystem.",
        event_record=event
    )

    result = await stage3.process_request(ctx)

    assert result.stage_name == "Stage 3 - Intent Risk"
    assert result.hard_block is False
    assert result.score is not None
    assert result.score < 30.0, f"Expected low risk score (< 30.0), got {result.score}"
    assert result.metadata["classification"] == "LOW"
    assert result.metadata["cosine_similarity"] >= 0.70
    assert ctx.event_record.scores.intent_risk == result.score


@pytest.mark.asyncio
async def test_matching_filesystem_request_produces_low_intent_risk(intent_model):
    """Refinement test 1: Matching filesystem request against concise action representation yields low intent risk (< 30.0)."""
    stage3 = Stage3IntentRisk(model=intent_model)

    event = SecurityEventRecord(
        timestamp="2026-09-24T12:00:00Z",
        server_name="filesystem",
        tool_name="list_directory",
        arguments={"path": "."}
    )
    # Full verbose MCP tool description from @modelcontextprotocol/server-filesystem
    verbose_desc = (
        "Get a detailed listing of all files and directories in a specified path. "
        "Results clearly distinguish between files and directories with [FILE] and [DIR] prefixes. "
        "This tool is essential for understanding directory structure and finding specific files within a directory. "
        "Only works within allowed directories."
    )
    ctx = PipelineContext(
        server_name="filesystem",
        tool_name="list_directory",
        tool_definition={"name": "list_directory", "description": verbose_desc},
        user_prompt="List the files in my allowed filesystem directory.",
        event_record=event
    )

    result = await stage3.process_request(ctx)

    assert result.hard_block is False
    assert result.score is not None
    assert result.score < 30.0, f"Expected low risk score (< 30.0), got {result.score}"
    assert result.metadata["classification"] == "LOW"
    assert result.metadata["cosine_similarity"] >= 0.70


@pytest.mark.asyncio
async def test_borderline_similarity_produces_medium_intent_risk(intent_model):
    """Refinement test 2: Borderline similarity -> medium/borderline risk (30.0 - 70.0)."""
    stage3 = Stage3IntentRisk(model=intent_model)

    event = SecurityEventRecord(
        timestamp="2026-09-24T12:00:00Z",
        server_name="filesystem",
        tool_name="read_file",
        arguments={"path": "notes.txt"}
    )
    # Somewhat related topic but not an exact direct match
    ctx = PipelineContext(
        server_name="filesystem",
        tool_name="read_file",
        tool_definition={
            "name": "read_file",
            "description": "Read the complete contents of a file from the file system as text. Handles various text encodings and provides detailed error messages if the file cannot be read."
        },
        user_prompt="Read lines from notes.txt",
        event_record=event
    )

    result = await stage3.process_request(ctx)

    assert result.hard_block is False
    assert 30.0 <= result.score < 70.0, f"Expected borderline/medium score (30-70), got {result.score}"
    assert result.metadata["classification"] == "MEDIUM"
    assert ctx.event_record.scores.intent_risk == result.score


@pytest.mark.asyncio
async def test_demonstration_case_produces_high_intent_risk(intent_model):
    """Requirement 6: Demonstration case:

    User request: "Summarize my latest ticket."
    Actual tool/action: "export all customer records."
    MUST produce HIGH intent risk. Verified with model rather than assumed float.
    """
    stage3 = Stage3IntentRisk(model=intent_model)

    event = SecurityEventRecord(
        timestamp="2026-09-24T12:00:00Z",
        server_name="postgres-mcp",
        tool_name="export_all_customer_records",
        arguments={}
    )
    ctx = PipelineContext(
        server_name="postgres-mcp",
        tool_name="export_all_customer_records",
        tool_definition={
            "name": "export_all_customer_records",
            "description": "export all customer records."
        },
        user_prompt="Summarize my latest ticket.",
        event_record=event
    )

    result = await stage3.process_request(ctx)

    # 1. Cosine similarity must be low
    cosine_sim = result.metadata["cosine_similarity"]
    assert cosine_sim < 0.30, f"Expected low cosine similarity (< 0.30), got {cosine_sim}"

    # 2. Risk score must be HIGH (>= 70.0)
    assert result.score is not None
    assert result.score >= 70.0, f"Expected HIGH risk score (>= 70.0), got {result.score}"
    assert result.metadata["classification"] == "HIGH"
    assert "Summarize my latest ticket." in result.explanation
    assert "export all customer records." in result.explanation

    # 3. Stage 3 does NOT set hard_block
    assert result.hard_block is False


@pytest.mark.asyncio
async def test_stage3_never_directly_blocks_or_allows(intent_model):
    """Requirement 7: Stage 3 produces ONLY risk scores and attributable evidence.

    It must NOT independently ALLOW, BLOCK, or HOLD a request.
    Risk Engine remains the sole authority.
    """
    stage3 = Stage3IntentRisk(model=intent_model)

    event = SecurityEventRecord(
        timestamp="2026-09-24T12:00:00Z",
        server_name="postgres-mcp",
        tool_name="export_all_customer_records",
        decision=EnforcementDecision.ALLOW  # Initial state
    )
    ctx = PipelineContext(
        server_name="postgres-mcp",
        tool_name="export_all_customer_records",
        tool_definition={"name": "export_all_customer_records", "description": "export all customer records."},
        user_prompt="Summarize my latest ticket.",
        event_record=event
    )

    result = await stage3.process_request(ctx)

    # StageResult hard_block is strictly False
    assert result.hard_block is False
    # Event decision was NOT altered by Stage 3
    assert ctx.event_record.decision == EnforcementDecision.ALLOW
    # Only the intent_risk score was populated
    assert ctx.event_record.scores.intent_risk == result.score


@pytest.mark.asyncio
async def test_risk_engine_enforces_stage3_scores(intent_model):
    """Requirement 9: Risk Engine converts Stage 3 intent risk into deterministic decision."""
    risk_engine = RiskEngine(low_threshold=30.0, high_threshold=70.0)

    # Case 1: High intent risk (e.g. demonstration case) -> BLOCK
    event_high = SecurityEventRecord(
        timestamp="2026-09-24T12:00:00Z",
        server_name="postgres-mcp",
        tool_name="export_all_customer_records",
        hash_matched=True
    )
    event_high.scores.intent_risk = 89.94
    decided_high = risk_engine.evaluate(event_high)
    assert decided_high.decision == EnforcementDecision.BLOCK
    assert "High risk score detected" in decided_high.reason

    # Case 2: Borderline / Medium intent risk -> HOLD
    event_med = SecurityEventRecord(
        timestamp="2026-09-24T12:00:00Z",
        server_name="filesystem",
        tool_name="read_file",
        hash_matched=True
    )
    event_med.scores.intent_risk = 50.3
    decided_med = risk_engine.evaluate(event_med)
    assert decided_med.decision == EnforcementDecision.HOLD
    assert "Medium risk score detected" in decided_med.reason

    # Case 3: Low intent risk -> ALLOW
    event_low = SecurityEventRecord(
        timestamp="2026-09-24T12:00:00Z",
        server_name="filesystem",
        tool_name="read_file",
        hash_matched=True
    )
    event_low.scores.intent_risk = 12.5
    decided_low = risk_engine.evaluate(event_low)
    assert decided_low.decision == EnforcementDecision.ALLOW
    assert "within low-risk thresholds" in decided_low.reason


@pytest.mark.asyncio
async def test_missing_user_prompt_handled_gracefully(intent_model):
    """Missing or empty user prompt passes through safely with score 0.0."""
    stage3 = Stage3IntentRisk(model=intent_model)

    event = SecurityEventRecord(
        timestamp="2026-09-24T12:00:00Z",
        server_name="filesystem",
        tool_name="list_directory"
    )
    ctx = PipelineContext(
        server_name="filesystem",
        tool_name="list_directory",
        user_prompt=None,  # No prompt provided
        event_record=event
    )

    result = await stage3.process_request(ctx)
    assert result.hard_block is False
    assert result.passed is True
    assert result.score == 0.0
    assert result.metadata["status"] == "SKIPPED_NO_PROMPT"
    assert ctx.event_record.scores.intent_risk == 0.0


@pytest.mark.asyncio
async def test_intent_policy_configuration():
    """Requirement 5: Configurable policy, thresholds, and versioning."""
    custom_policy = {
        "policy_version": "2.0.0-custom",
        "name": "Custom Policy",
        "model_name": "all-MiniLM-L6-v2",
        "thresholds": {
            "acceptable_similarity_threshold": 0.85
        },
        "scoring": {
            "min_score": 10.0,
            "max_score": 90.0,
            "similarity_floor": 0.0,
            "similarity_ceiling": 1.0
        },
        "levels": {
            "low": {"max_score": 25.0, "label": "LOW"},
            "high": {"min_score": 60.0, "label": "HIGH"}
        }
    }

    tmp_policy_path = Path("config/test_intent_policy.json")
    tmp_policy_path.write_text(json.dumps(custom_policy), encoding="utf-8")

    try:
        stage3 = Stage3IntentRisk(policy_path=str(tmp_policy_path))
        assert stage3.policy_version == "2.0.0-custom"
        assert stage3.acceptable_similarity_threshold == 0.85

        # Test score conversion with custom min/max:
        # sim = 1.0 -> min_score (10.0) -> LOW (< 25.0)
        score_low, cls_low = stage3.calculate_intent_risk_score(1.0)
        assert score_low == 10.0
        assert cls_low == "LOW"

        # sim = 0.0 -> max_score (90.0) -> HIGH (>= 60.0)
        score_high, cls_high = stage3.calculate_intent_risk_score(0.0)
        assert score_high == 90.0
        assert cls_high == "HIGH"
    finally:
        if tmp_policy_path.exists():
            tmp_policy_path.unlink()


@pytest.mark.asyncio
async def test_postgresql_persistence_of_stage3(intent_model, test_db_session: AsyncSession):
    """Requirement 8: Persist Stage 3 results to database linked to the security event."""
    stage3 = Stage3IntentRisk(model=intent_model)

    event_id = "evt_stage3_persistence_test_1"
    event = SecurityEventRecord(
        event_id=event_id,
        timestamp="2026-09-24T12:30:00Z",
        server_name="postgres-mcp",
        tool_name="export_all_customer_records",
        user_prompt="Summarize my latest ticket."
    )
    ctx = PipelineContext(
        server_name="postgres-mcp",
        tool_name="export_all_customer_records",
        tool_definition={"name": "export_all_customer_records", "description": "export all customer records."},
        user_prompt="Summarize my latest ticket.",
        event_record=event
    )

    stage_res = await stage3.process_request(ctx)

    # Persist security event with Stage 3 recorded stage result
    stage_results_list = [{
        "stage_number": 3,
        "stage_name": stage_res.stage_name,
        "passed": stage_res.passed,
        "hard_block": stage_res.hard_block,
        "score": stage_res.score,
        "explanation": stage_res.explanation,
        "metadata": stage_res.metadata
    }]

    sec_rec = await persist_security_event(
        event_dict=event.model_dump(),
        stage_results=stage_results_list,
        session=test_db_session
    )

    assert sec_rec is not None
    assert sec_rec.event_id == event_id

    # Retrieve and verify via query helper
    eval_row = await get_intent_evaluation(event_id, session=test_db_session)
    assert eval_row is not None
    assert eval_row["event_id"] == event_id
    assert eval_row["user_request"] == "Summarize my latest ticket."
    assert "export all customer records." in eval_row["tool_action"]
    assert eval_row["cosine_similarity"] < 0.30
    assert eval_row["intent_risk_score"] >= 70.0
    assert eval_row["classification"] == "HIGH"
    assert eval_row["policy_version"] == "1.0.0"
    assert eval_row["created_at"] is not None
    assert "Semantic similarity" in eval_row["explanation"]


@pytest.mark.asyncio
async def test_end_to_end_pipeline_runner_with_stage3(intent_model):
    """Requirement 9: PipelineRunner executes Stage 1 -> Stage 2 -> Stage 3 -> Risk Engine."""
    # Mock Stage 1 hash pass
    mock_stage1 = MagicMock(spec=Stage1HashCheck)
    async def _mock_s1(ctx):
        ctx.event_record.hash_matched = True
        return StageResult(stage_name="Stage 1 - Hash Integrity Check", hard_block=False, passed=True)
    mock_stage1.process_request = _mock_s1

    # Stage 2 benign
    stage2 = Stage2CapabilityRisk()
    # Stage 3 with real model
    stage3 = Stage3IntentRisk(model=intent_model)
    # Risk Engine
    risk_engine = RiskEngine()

    runner = PipelineRunner(
        stage1=mock_stage1,
        stage2=stage2,
        stage3=stage3,
        risk_engine=risk_engine,
        persist_events=False
    )

    # 1. Demonstration case in pipeline runner
    event = SecurityEventRecord(
        timestamp="2026-09-24T12:00:00Z",
        server_name="postgres-mcp",
        tool_name="export_all_customer_records",
        user_prompt="Summarize my latest ticket."
    )
    ctx = PipelineContext(
        server_name="postgres-mcp",
        tool_name="export_all_customer_records",
        tool_definition={"name": "export_all_customer_records", "description": "export all customer records."},
        user_prompt="Summarize my latest ticket.",
        event_record=event
    )

    evaluated_event = await runner.run_pre_call(ctx)

    # Because Stage 3 produced risk score >= 70.0, Risk Engine produced BLOCK
    assert evaluated_event.scores.intent_risk >= 70.0
    assert evaluated_event.decision == EnforcementDecision.BLOCK
    assert "High risk score detected" in evaluated_event.reason
