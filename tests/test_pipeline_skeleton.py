"""Tests verifying pipeline stage skeletons, contracts, and explainability formatting."""

import pytest
from mcpath.pipeline.pipeline_runner import PipelineRunner
from mcpath.pipeline.stage import PipelineContext
from mcpath.pipeline.stages.stage1_hash import compute_tool_hash, canonicalize_tool_definition
from mcpath.risk_engine.engine import RiskEngine
from mcpath.risk_engine.models import EnforcementDecision, RiskScores, SecurityEventRecord
from mcpath.risk_engine.explainability import format_explanation


def test_canonicalize_and_hash():
    """Verify tool definition canonicalization produces deterministic SHA-256 hashes."""
    def1 = {"name": "read_customer", "description": "Read PII", "inputSchema": {"type": "object"}}
    def2 = {"inputSchema": {"type": "object"}, "description": "Read PII", "name": "read_customer"}

    assert canonicalize_tool_definition(def1) == canonicalize_tool_definition(def2)
    hash1 = compute_tool_hash(def1)
    hash2 = compute_tool_hash(def2)
    assert hash1 == hash2
    assert len(hash1) == 64  # SHA-256 hex string


@pytest.mark.asyncio
async def test_pipeline_runner_passthrough():
    """Verify Day 1 pipeline runner processes context and allows valid calls."""
    runner = PipelineRunner()
    event = SecurityEventRecord(
        timestamp="2026-09-17T12:00:00Z",
        server_name="test-server",
        tool_name="echo",
        arguments={"message": "hello"}
    )
    ctx = PipelineContext(
        server_name="test-server",
        tool_name="echo",
        arguments={"message": "hello"},
        event_record=event
    )

    pre_eval = await runner.run_pre_call(ctx)
    assert pre_eval.decision == EnforcementDecision.ALLOW

    post_eval = await runner.run_post_call(ctx)
    assert post_eval.decision == EnforcementDecision.ALLOW


def test_explainability_format():
    """Verify Section 7 explainability formatter matches specification layout."""
    event = SecurityEventRecord(
        timestamp="2026-09-17T12:00:00Z",
        server_name="test-server",
        tool_name="send_email",
        arguments={"recipient": "attacker@external.com"},
        expected_hash="a45d83",
        observed_hash="9f2a1c",
        scores=RiskScores(capability_risk=71.0, intent_risk=12.0, behaviour_risk=8.0, response_risk=4.0),
        decision=EnforcementDecision.BLOCK,
        reason="Tool definition changed",
        hard_gate_triggered="hash mismatch",
        action_taken="Tool call not forwarded"
    )

    explanation = format_explanation(event)
    assert "EXECUTION BLOCKED" in explanation
    assert "Reason: Tool definition changed" in explanation
    assert "Expected Hash: a45d83" in explanation
    assert "Observed Hash: 9f2a1c" in explanation
    assert "Capability Risk: 71.0" in explanation
    assert "Intent Risk: 12.0" in explanation
    assert "Behaviour Risk: 8.0" in explanation
    assert "Response Risk: 4.0" in explanation
    assert "Overall Risk: BLOCK (hard gate: hash mismatch)" in explanation
    assert "Action: Tool call not forwarded" in explanation
