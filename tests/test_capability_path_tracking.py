"""Focused tests for capability path ID stability, runtime match tracking, explainability, and risk engine verdicts."""

import pytest
from httpx import AsyncClient, ASGITransport

from mcpath.backend.app import app
from mcpath.backend.persistence.database import init_db, persist_security_event
from mcpath.graph.capability_graph import CapabilityGraph, generate_path_id
from mcpath.pipeline.pipeline_runner import PipelineRunner
from mcpath.pipeline.stage import PipelineContext
from mcpath.pipeline.stages.stage1_hash import Stage1HashCheck
from mcpath.pipeline.stages.stage2_capability import Stage2CapabilityRisk
from mcpath.proxy.client_manager import DownstreamClientManager, set_active_client_manager
from mcpath.risk_engine.engine import RiskEngine
from mcpath.risk_engine.models import EnforcementDecision, SecurityEventRecord


SAMPLE_TEST_TOOLS = {
    "server_a": [
        {
            "name": "echo",
            "description": "Echoes back the provided message.",
            "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}}}
        },
        {
            "name": "calculate",
            "description": "Perform basic arithmetic calculations.",
            "inputSchema": {"type": "object", "properties": {"operation": {"type": "string"}, "a": {"type": "number"}, "b": {"type": "number"}}}
        },
        {
            "name": "read_customer",
            "description": "Read customer profile data containing sensitive PII and SSN.",
            "inputSchema": {"type": "object", "properties": {"customer_id": {"type": "string"}}}
        }
    ],
    "server_b": [
        {
            "name": "send_email",
            "description": "Simulates dispatching an email to an external recipient.",
            "inputSchema": {"type": "object", "properties": {"recipient": {"type": "string"}, "subject": {"type": "string"}, "body": {"type": "string"}}}
        }
    ]
}


@pytest.fixture
def populated_test_graph() -> CapabilityGraph:
    """Fixture providing populated graph for testing."""
    g = CapabilityGraph()
    g.rebuild_for_all_servers(SAMPLE_TEST_TOOLS)
    return g


# ---------------------------------------------------------------------------
# 1. Path ID Deterministic Stability
# ---------------------------------------------------------------------------

def test_path_id_deterministic_stability(populated_test_graph: CapabilityGraph):
    """Verify path IDs remain completely stable and identical across graph rebuilds."""
    paths_first = populated_test_graph.get_paths_for_tool("read_customer")
    assert len(paths_first) > 0
    first_ids = [p.path_id for p in paths_first]
    assert all(pid is not None for pid in first_ids)

    # Rebuild graph from scratch
    rebuilt_graph = CapabilityGraph()
    rebuilt_graph.rebuild_for_all_servers(SAMPLE_TEST_TOOLS)
    paths_rebuilt = rebuilt_graph.get_paths_for_tool("read_customer")
    rebuilt_ids = [p.path_id for p in paths_rebuilt]

    assert first_ids == rebuilt_ids, "Path IDs must remain identical across graph rebuilds when underlying path has not changed"


def test_distinct_paths_have_unique_ids(populated_test_graph: CapabilityGraph):
    """Verify distinct capability paths receive distinct, unique path IDs."""
    exported = populated_test_graph.export_graph()
    paths = exported.get("paths", [])
    assert len(paths) > 0

    path_ids = [p.get("path_id") for p in paths]
    assert all(pid for pid in path_ids), "Every exported path must have a non-empty path_id"
    assert len(path_ids) == len(set(path_ids)), "Every distinct capability path must have a unique path_id"


def test_generate_path_id_function():
    """Verify generate_path_id produces deterministic, well-formatted string."""
    nodes1 = ["Agent", "Tool:read_file", "Resource:filesystem_content", "Action:read_file:read"]
    nodes2 = ["Agent", "Tool:read_file", "Resource:filesystem_content", "Action:read_file:read"]
    nodes3 = ["Agent", "Tool:send_email", "Resource:email_message", "Action:send_email:send", "Destination:external_recipient"]

    id1 = generate_path_id(nodes1)
    id2 = generate_path_id(nodes2)
    id3 = generate_path_id(nodes3)

    assert id1 == id2
    assert id1 != id3
    assert id1.startswith("path_read_file_")
    assert id3.startswith("path_send_email_")


# ---------------------------------------------------------------------------
# 2. Runtime Match Logging & Metadata
# ---------------------------------------------------------------------------

def test_runtime_match_metadata_on_known_path(populated_test_graph: CapabilityGraph):
    """Verify evaluating a modeled tool call sets matched_path=True, match_status=MATCHED, and runtime_path_id."""
    eval_result = populated_test_graph.evaluate_runtime_call("read_customer")

    assert eval_result.metadata.get("matched_path") is True
    assert eval_result.metadata.get("match_status") == "MATCHED"
    assert eval_result.metadata.get("runtime_path_id") == eval_result.path_id
    assert eval_result.metadata.get("runtime_path_id") is not None
    assert eval_result.metadata.get("selection_reason") != ""


def test_multiple_matching_paths_selection_documented(populated_test_graph: CapabilityGraph):
    """Verify multiple matching paths document the selection rationale rather than silently choosing."""
    eval_result = populated_test_graph.evaluate_runtime_call(
        tool_name="send_email",
        call_history=["read_customer", "send_email"]
    )

    meta = eval_result.metadata
    assert meta.get("matched_path") is True
    assert meta.get("match_status") == "MATCHED"
    assert "selection_reason" in meta
    assert meta.get("selection_reason") != ""
    assert "candidate_paths_count" in meta


# ---------------------------------------------------------------------------
# 3. Unknown & Unmodeled Paths Distinction
# ---------------------------------------------------------------------------

def test_unknown_path_handling(populated_test_graph: CapabilityGraph):
    """Verify completely unmodeled/novel tool sets matched_path=False, match_status=UNKNOWN, and runtime_path_id=None."""
    eval_result = populated_test_graph.evaluate_runtime_call("completely_unrecognized_tool")

    assert eval_result.path_id is None
    assert eval_result.metadata.get("matched_path") is False
    assert eval_result.metadata.get("match_status") == "UNKNOWN"
    assert eval_result.metadata.get("runtime_path_id") is None
    assert eval_result.path_risk_score >= 70.0
    assert eval_result.classification == "HIGH"
    assert "CAPABILITY PATH: UNKNOWN / UNMODELED" in eval_result.explanation


# ---------------------------------------------------------------------------
# 4. Benign vs Hazardous Path Verdicts Preserved
# ---------------------------------------------------------------------------

def test_benign_metadata_inspection_remains_low_allow(populated_test_graph: CapabilityGraph):
    """Verify benign operations like echo evaluate to LOW classification."""
    eval_result = populated_test_graph.evaluate_runtime_call("echo")

    assert eval_result.classification == "LOW"
    assert eval_result.path_risk_score < 30.0
    assert eval_result.is_critical_override is False


def test_sensitive_data_to_external_remains_high(populated_test_graph: CapabilityGraph):
    """Verify sensitive data to external action chain evaluates to HIGH with critical override."""
    chain_nodes = [
        "Agent",
        "Tool:read_customer",
        "Resource:customer_pii",
        "Action:send_email:external_communication",
        "Destination:external_recipient"
    ]
    scored = populated_test_graph.score_path(chain_nodes)
    assert scored.classification == "HIGH"
    assert scored.path_risk_score >= 70.0
    assert scored.is_critical_override is True


# ---------------------------------------------------------------------------
# 5. Database Model Fields Contract
# ---------------------------------------------------------------------------

def test_model_fields_exist():
    """Verify that SecurityEventRecord and ORM models have all required capability tracking attributes."""
    from mcpath.backend.persistence.models import CapabilityPathDB, SecurityEventDB

    rec = SecurityEventRecord(
        timestamp="2026-09-28T10:00:00Z",
        server_name="test_srv",
        tool_name="echo",
        runtime_path_id="path_echo_12345678",
        matched_path=True,
        match_status="MATCHED"
    )
    assert rec.runtime_path_id == "path_echo_12345678"
    assert rec.matched_path is True
    assert rec.match_status == "MATCHED"

    # ORM Model column verification
    assert hasattr(CapabilityPathDB, "path_id")
    assert hasattr(SecurityEventDB, "runtime_path_id")
    assert hasattr(SecurityEventDB, "matched_path")
    assert hasattr(SecurityEventDB, "match_status")


@pytest.mark.asyncio
async def test_fastapi_paths_api_return_path_ids(populated_test_graph: CapabilityGraph):
    """Verify FastAPI route /api/capabilities/paths returns persistent path_id fields."""
    mgr = DownstreamClientManager()
    mgr.capability_graph = populated_test_graph
    set_active_client_manager(mgr)
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            res_paths = await ac.get("/api/capabilities/paths")
            assert res_paths.status_code == 200
            paths = res_paths.json()
            assert isinstance(paths, list)
            assert len(paths) > 0
            for p in paths:
                assert "path_id" in p
                assert p["path_id"].startswith("path_")
    finally:
        set_active_client_manager(None)
