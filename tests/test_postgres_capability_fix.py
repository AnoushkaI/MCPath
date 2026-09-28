"""Focused tests for PostgreSQL capability classification fix and Stage 3 prompt capture diagnostics.

Invariants verified:
1. metadata/profile inspection -> LOW/ALLOW
2. sensitive DB data -> external destination -> HIGH/BLOCK
3. harmless description containing "database" does not create database_records
4. explicit rules override generic inference
5. Risk Engine threshold behavior unchanged (weights 30/25/20/25, thresholds 30/70)
6. Stage 3 with explicit _user_prompt -> correctly evaluated
7. standard call without prompt metadata -> SKIPPED_NO_PROMPT
"""

import pytest
from mcpath.graph.capability_inference import CapabilityClassifier
from mcpath.graph.capability_graph import CapabilityGraph
from mcpath.risk_engine.engine import RiskEngine
from mcpath.pipeline.stage import PipelineContext, SecurityEventRecord
from mcpath.pipeline.stages.stage3_intent import Stage3IntentRisk


def test_metadata_profile_inspection_low_allow():
    """Verify that PostgreSQL metadata/profile tools are classified as database_metadata and evaluate to LOW/ALLOW."""
    classifier = CapabilityClassifier()
    metadata_tools = [
        {
            "name": "postgres_mcp_list_connection_profiles",
            "description": "List all available PostgreSQL connection profiles. Returns a list of profiles with ID, name, host, port, and default database.",
            "inputSchema": {"type": "object", "properties": {}}
        },
        {
            "name": "list_connection_profiles",
            "description": "List all available PostgreSQL connection profiles.",
            "inputSchema": {"type": "object", "properties": {}}
        },
        {
            "name": "postgres_mcp_list_databases",
            "description": "List all databases on the connected PostgreSQL server.",
            "inputSchema": {"type": "object", "properties": {"connectionId": {"type": "string"}}}
        },
        {
            "name": "postgres_mcp_get_server_capabilities",
            "description": "Discovers what diagnostic tools are available for the connected server.",
            "inputSchema": {"type": "object", "properties": {"connectionId": {"type": "string"}}}
        },
    ]

    for tool_def in metadata_tools:
        cap = classifier.classify_tool("postgres-mcp", tool_def)
        assert cap.data_target == "database_metadata", f"Expected database_metadata for {tool_def['name']}, got {cap.data_target}"
        assert cap.data_sensitivity == 1.0
        assert cap.operation == "READ"
        assert cap.action_type == "inspect_metadata"
        assert cap.action_sensitivity == 0.5
        assert cap.external_exposure == 0.0
        assert cap.external_destination is None
        assert cap.consumed_data_types == ["database_metadata"]

    # In multi-server graph with an external transmission tool (send_email)
    graph = CapabilityGraph()
    tools = {
        "postgres-mcp": metadata_tools,
        "mock-email": [
            {
                "name": "send_email",
                "description": "Send email out to external recipients.",
                "inputSchema": {"type": "object", "properties": {"to": {"type": "string"}, "body": {"type": "string"}}}
            }
        ]
    }
    graph.rebuild_for_all_servers(tools)

    eval_result = graph.evaluate_runtime_call("postgres_mcp_list_connection_profiles")
    assert eval_result.classification == "LOW"
    assert eval_result.path_risk_score < 30.0
    assert not eval_result.is_critical_override
    assert "send_email" not in " ".join(eval_result.path_nodes)
    assert "external_recipient" not in " ".join(eval_result.path_nodes)

    # Risk Engine evaluation
    engine = RiskEngine()
    event = SecurityEventRecord(
        timestamp="2026-09-25T12:00:00Z",
        server_name="postgres-mcp",
        tool_name="postgres_mcp_list_connection_profiles",
        arguments={}
    )
    event.scores.capability_risk = eval_result.path_risk_score
    event.scores.intent_risk = 0.0
    event.scores.behaviour_risk = 0.0

    evaluated_event = engine.evaluate(event)
    assert evaluated_event.decision.value == "ALLOW"


def test_sensitive_db_data_to_external_destination_high_block():
    """Verify that sensitive database records flowing to an external destination remain HIGH risk and deterministically BLOCK."""
    graph = CapabilityGraph()
    tools = {
        "postgres-mcp": [
            {
                "name": "postgres_mcp_query",
                "description": "Run a formatted SQL query against a database. Executes a single statement.",
                "inputSchema": {"type": "object", "properties": {"connectionId": {"type": "string"}, "query": {"type": "string"}}}
            }
        ],
        "mock-email": [
            {
                "name": "send_email",
                "description": "Send email out to external recipients.",
                "inputSchema": {"type": "object", "properties": {"to": {"type": "string"}, "body": {"type": "string"}}}
            }
        ]
    }
    graph.rebuild_for_all_servers(tools)

    eval_query = graph.evaluate_runtime_call("postgres_mcp_query")
    assert eval_query.classification == "HIGH"
    assert eval_query.path_risk_score >= 85.0
    assert eval_query.is_critical_override is True
    assert "send_email" in " ".join(eval_query.path_nodes)
    assert "external_recipient" in " ".join(eval_query.path_nodes)

    # Risk Engine must deterministically BLOCK
    engine = RiskEngine()
    event = SecurityEventRecord(
        timestamp="2026-09-25T12:00:00Z",
        server_name="postgres-mcp",
        tool_name="postgres_mcp_query",
        arguments={"query": "SELECT * FROM customers"}
    )
    event.scores.capability_risk = eval_query.path_risk_score
    event.scores.intent_risk = 0.0
    event.scores.behaviour_risk = 0.0

    evaluated_event = engine.evaluate(event)
    assert evaluated_event.decision.value == "BLOCK"


def test_harmless_description_containing_database_does_not_create_database_records():
    """Verify words such as 'database', 'query', 'table', or 'record' alone do not classify harmless tools as database_records."""
    classifier = CapabilityClassifier()
    tool_def = {
        "name": "check_service_health",
        "description": "Inspects the database server connectivity, ping latency, and default database status.",
        "inputSchema": {"type": "object", "properties": {}}
    }
    cap = classifier.classify_tool("health_monitor", tool_def)
    assert cap.data_target != "database_records", f"Harmless tool got classified as database_records: {cap.data_target}"
    assert cap.data_target in ("database_metadata", "generic_resource")
    assert cap.data_sensitivity <= 1.0


def test_explicit_rules_override_generic_inference():
    """Verify that explicit tool rules take strict precedence over generic pattern inference."""
    classifier = CapabilityClassifier()
    # Tool description deliberately contains high-sensitivity words and SQL keywords that would otherwise match pattern rules
    synthetic_tool = {
        "name": "postgres_mcp_list_connection_profiles",
        "description": "Dumps customer passwords and executes raw sql query statements directly against records",
        "inputSchema": {"type": "object", "properties": {"sql": {"type": "string"}}}
    }
    cap = classifier.classify_tool("postgres-mcp", synthetic_tool)
    assert cap.data_target == "database_metadata", f"Explicit rule did not take precedence: got {cap.data_target}"
    assert cap.action_type == "inspect_metadata"
    assert cap.data_sensitivity == 1.0
    assert cap.action_sensitivity == 0.5


def test_risk_engine_threshold_behavior_unchanged():
    """Verify that Risk Engine thresholds (30.0 / 70.0) and weights remain strictly unchanged."""
    engine = RiskEngine()
    assert engine.low_threshold == 30.0
    assert engine.high_threshold == 70.0

    # Policy weights check
    classifier = CapabilityClassifier()
    weights = classifier.policy.get("weights", {})
    assert weights.get("data_sensitivity") == 0.30
    assert weights.get("action_sensitivity") == 0.25
    assert weights.get("external_exposure") == 0.20
    assert weights.get("chain_risk") == 0.25


@pytest.mark.asyncio
async def test_stage3_with_explicit_user_prompt_evaluated():
    """Verify Stage 3 properly evaluates semantic similarity when a user prompt is provided."""
    stage = Stage3IntentRisk()
    event = SecurityEventRecord(
        timestamp="2026-09-25T12:00:00Z",
        server_name="postgres-mcp",
        tool_name="postgres_mcp_list_connection_profiles",
        arguments={},
        user_prompt="List all database connection profiles"
    )
    ctx = PipelineContext(
        server_name="postgres-mcp",
        tool_name="postgres_mcp_list_connection_profiles",
        arguments={},
        user_prompt="List all database connection profiles",
        tool_definition={"name": "postgres_mcp_list_connection_profiles", "description": "List connection profiles"},
        event_record=event
    )
    result = await stage.process_request(ctx)
    assert result.passed is True
    assert result.score is not None
    assert result.score < 30.0  # Semantically matching request produces low intent risk
    assert result.metadata["classification"] == "LOW"
    assert result.metadata["user_request"] == "List all database connection profiles"


@pytest.mark.asyncio
async def test_standard_call_without_prompt_metadata_skipped_no_prompt():
    """Verify standard MCP calls without user prompt metadata gracefully result in SKIPPED_NO_PROMPT."""
    stage = Stage3IntentRisk()
    event = SecurityEventRecord(
        timestamp="2026-09-25T12:00:00Z",
        server_name="postgres-mcp",
        tool_name="postgres_mcp_list_connection_profiles",
        arguments={},
        user_prompt=None
    )
    ctx = PipelineContext(
        server_name="postgres-mcp",
        tool_name="postgres_mcp_list_connection_profiles",
        arguments={},
        user_prompt=None,
        tool_definition={"name": "postgres_mcp_list_connection_profiles", "description": "List connection profiles"},
        event_record=event
    )
    result = await stage.process_request(ctx)
    assert result.passed is True
    assert result.score is None
    assert result.metadata["status"] == "SKIPPED_NO_PROMPT"
    assert result.metadata["intent_risk_score"] is None
    assert result.metadata["user_request"] is None
