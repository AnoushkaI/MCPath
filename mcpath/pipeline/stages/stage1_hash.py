"""Stage 1: Tool Integrity Hash Check.

Question: "Has this tool's definition changed since it was approved?"
Specification:
- On first approval, canonicalize definition (sorted-key JSON) and compute SHA-256 hash.
- On every later call, recompute hash from live definition.
- A mismatch is an immediate hard block with explanation — no score is computed,
  and the call does not proceed to any later stage.
"""

import hashlib
import json
from typing import Any, Dict
from mcpath.pipeline.stage import BasePipelineStage, PipelineContext, StageResult


def canonicalize_tool_definition(definition: Dict[str, Any]) -> str:
    """Canonicalize a tool definition JSON by sorting keys recursively."""
    return json.dumps(definition, sort_keys=True, separators=(",", ":"))


def compute_tool_hash(definition: Dict[str, Any]) -> str:
    """Compute SHA-256 hash of canonicalized tool definition."""
    canonical_json = canonicalize_tool_definition(definition)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


class Stage1HashCheck(BasePipelineStage):
    """Stage 1: Runtime Tool Integrity Hash Check."""

    def __init__(self):
        super().__init__("Stage 1 - Hash Check")

    async def process_request(self, context: PipelineContext) -> StageResult:
        """Verify tool definition against approved hash.

        [TODO Day 3-4: Retrieve approved hash from database and enforce hard-block on mismatch]
        For Day 1, operates in passthrough mode.
        """
        # If tool definition is provided in context, compute live hash
        observed_hash = None
        if context.tool_definition:
            observed_hash = compute_tool_hash(context.tool_definition)
            context.event_record.observed_hash = observed_hash

        # For Day 1 passthrough: assume hash verified or record initial baseline
        context.event_record.hash_matched = True

        return StageResult(
            stage_name=self.name,
            hard_block=False,
            passed=True,
            explanation="Stage 1 passthrough mode active (Day 1)",
            metadata={"observed_hash": observed_hash}
        )
