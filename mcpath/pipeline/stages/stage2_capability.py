"""Stage 2: Capability Risk.

Question: "Could this call, or the path it's part of, reach somewhere dangerous?"
Specification:
- Causal capability graph: Agent -> Tool -> Data/Resource -> Action -> External Destination
- Scored on explicit attributes: data sensitivity, action sensitivity, external exposure, chain risk
- Critical path override: Sensitive Data -> External Action -> External Destination -> HIGH
- Runtime sequence mapping: matches actual tool-call sequence against compatible graph paths
- Unknown / unmodeled paths report elevated risk
- Strictly deterministic: produces capability result; Risk Engine remains enforcement authority
"""

import logging
from typing import Any, Dict, List, Optional
from mcpath.graph.capability_graph import CapabilityGraph, PathScoringResult
from mcpath.pipeline.stage import BasePipelineStage, PipelineContext, StageResult

logger = logging.getLogger("mcpath.pipeline.stage2")


class Stage2CapabilityRisk(BasePipelineStage):
    """Stage 2: Capability Graph Risk Scorer."""

    def __init__(self, graph: Optional[CapabilityGraph] = None):
        super().__init__("Stage 2 - Capability Risk")
        self.graph = graph or CapabilityGraph()

    async def process_request(self, context: PipelineContext) -> StageResult:
        """Evaluate capability risk based on graph path attributes and call sequence."""
        tool_name = context.tool_name
        history = list(context.call_history) if context.call_history else [tool_name]
        if not history or history[-1] != tool_name:
            history.append(tool_name)

        # Ingest tool dynamically if definition is available in context and not yet registered
        if (
            tool_name not in self.graph.tool_capabilities
            and context.tool_definition
            and isinstance(context.tool_definition, dict)
            and context.tool_definition.get("name")
        ):
            self.graph.add_tool(context.server_name, context.tool_definition)

        # Map actual tool call sequence against compatible graph paths
        result: PathScoringResult = self.graph.evaluate_runtime_call(
            tool_name=tool_name,
            call_history=history
        )

        # Produce capability result for Risk Engine evaluation
        context.event_record.scores.capability_risk = result.path_risk_score

        # Runtime matching identification fields
        runtime_path_id = result.metadata.get("runtime_path_id") or result.path_id
        matched_path = result.metadata.get("matched_path", bool(result.path_id))
        match_status = result.metadata.get("match_status", "MATCHED" if matched_path else "UNKNOWN")
        selection_reason = result.metadata.get("selection_reason", "")

        context.event_record.runtime_path_id = runtime_path_id
        context.event_record.matched_path = matched_path
        context.event_record.match_status = match_status

        logger.info(
            "Capability runtime evaluation: tool_name=%s matched_path=%s match_status=%s runtime_path_id=%s risk_score=%.1f classification=%s selection_reason=%s",
            tool_name,
            matched_path,
            match_status,
            runtime_path_id,
            result.path_risk_score,
            result.classification,
            selection_reason
        )

        # Collect all candidate paths for this tool to include in metadata
        all_candidate_paths = [
            p.to_dict() for p in self.graph.get_paths_for_tool(tool_name)
        ]

        metadata = {
            "policy_version": result.policy_version,
            "path_id": result.path_id,
            "runtime_path_id": runtime_path_id,
            "matched_path": matched_path,
            "match_status": match_status,
            "selection_reason": selection_reason,
            "path_nodes": result.path_nodes,
            "path_edges": result.path_edges,
            "data_sensitivity": result.data_sensitivity,
            "action_sensitivity": result.action_sensitivity,
            "external_exposure": result.external_exposure,
            "chain_risk": result.chain_risk,
            "classification": result.classification,
            "is_critical_override": result.is_critical_override,
            "total_candidate_paths": len(all_candidate_paths),
            "candidate_paths": all_candidate_paths,
            **result.metadata
        }

        # Note: Risk Engine remains the sole deterministic enforcement authority
        passed = result.classification != "HIGH"

        return StageResult(
            stage_name=self.name,
            score=result.path_risk_score,
            hard_block=False,
            passed=passed,
            explanation=result.explanation,
            metadata=metadata
        )
