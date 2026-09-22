"""Stage 1: Tool Integrity Hash Check.

Question: "Has this tool's definition changed since it was approved?"
Specification:
- On initial trusted registration, extract security-relevant definition (name, description, inputSchema),
  canonicalize definition (recursively sorted dictionary keys) and compute SHA-256 hash.
- Store approved baseline hash in PostgreSQL.
- On every runtime call:
    1. Identify server + tool
    2. Retrieve current tool definition from cache/discovery
    3. Extract security-relevant definition -> Canonicalize -> Compute observed SHA-256
    4. Retrieve active approved baseline hash from PostgreSQL
    5. Compare:
        - Mismatch -> BLOCK immediately, no downstream call, persist security event
        - Missing Baseline -> Fail-closed BLOCK (NO_APPROVED_BASELINE)
        - Match -> PASS, persist result, continue pipeline
"""

import hashlib
import json
import logging
from typing import Any, Dict, Optional, Tuple
from mcpath.backend.persistence.database import get_approved_hash
from mcpath.pipeline.stage import BasePipelineStage, PipelineContext, StageResult

logger = logging.getLogger("mcpath.pipeline.stage1_hash")


def extract_security_relevant_definition(raw_def: Dict[str, Any]) -> Dict[str, Any]:
    """Extract only the security-relevant tool definition fields (name, description, inputSchema)."""
    name = raw_def.get("name", "")
    description = raw_def.get("description", "") or ""
    # Support both MCP SDK camelCase and snake_case input schema naming
    schema = raw_def.get("inputSchema")
    if schema is None:
        schema = raw_def.get("input_schema", {})
    if schema is None:
        schema = {}

    return {
        "name": name,
        "description": description,
        "inputSchema": schema,
    }


def _sort_recursively(obj: Any) -> Any:
    """Recursively sort dictionary keys while preserving list element ordering."""
    if isinstance(obj, dict):
        return {k: _sort_recursively(v) for k, v in sorted(obj.items())}
    elif isinstance(obj, list):
        return [_sort_recursively(item) for item in obj]
    return obj


def canonicalize_tool_definition(definition: Dict[str, Any]) -> str:
    """Canonicalize a tool definition JSON by recursively sorting dictionary keys."""
    sorted_obj = _sort_recursively(definition)
    return json.dumps(sorted_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_tool_hash(definition: Dict[str, Any]) -> str:
    """Compute SHA-256 hex digest of canonicalized security-relevant tool definition."""
    sec_def = extract_security_relevant_definition(definition)
    canonical_json = canonicalize_tool_definition(sec_def)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def canonicalize_and_hash(definition: Dict[str, Any]) -> Tuple[str, str]:
    """Return both canonical JSON string and SHA-256 hash for security-relevant tool definition."""
    sec_def = extract_security_relevant_definition(definition)
    canonical_json = canonicalize_tool_definition(sec_def)
    sha256_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    return canonical_json, sha256_hash


class Stage1HashCheck(BasePipelineStage):
    """Stage 1: Runtime Tool Integrity Hash Check with PostgreSQL baseline verification."""

    def __init__(self, hash_provider=None):
        super().__init__("Stage 1 - Hash Check")
        self._hash_provider = hash_provider  # Optional mock/override provider for unit testing

    async def process_request(self, context: PipelineContext) -> StageResult:
        """Verify live tool definition against PostgreSQL approved baseline hash."""
        server_name = context.server_name
        tool_name = context.tool_name
        tool_def = context.tool_definition

        # 1. Fail-closed if tool definition is missing entirely
        if not tool_def:
            logger.error("Stage 1 Fail-Closed (NO_TOOL_DEFINITION): Missing definition for '%s' on server '%s'", tool_name, server_name)
            context.event_record.hash_matched = False
            return StageResult(
                stage_name=self.name,
                passed=False,
                hard_block=True,
                explanation=f"Stage 1 Fail-Closed (NO_APPROVED_BASELINE): Tool definition not found for '{tool_name}'",
                metadata={"reason": "NO_APPROVED_BASELINE", "error": "missing_tool_definition"}
            )

        # 2. Compute live canonical SHA-256 hash
        try:
            observed_canonical, observed_hash = canonicalize_and_hash(tool_def)
            context.event_record.observed_hash = observed_hash
        except Exception as e:
            logger.error("Stage 1 Fail-Closed: Failed to canonicalize tool definition: %s", e)
            context.event_record.hash_matched = False
            return StageResult(
                stage_name=self.name,
                passed=False,
                hard_block=True,
                explanation=f"Stage 1 Fail-Closed: Could not canonicalize tool definition for '{tool_name}': {e}",
                metadata={"error": str(e)}
            )

        # 3. Retrieve approved hash from PostgreSQL
        try:
            if self._hash_provider is not None:
                expected_hash = await self._hash_provider(server_name, tool_name)
            else:
                expected_hash = await get_approved_hash(server_name, tool_name)
        except Exception as e:
            logger.error("Stage 1 Fail-Closed: Database query failed while retrieving approved hash: %s", e)
            context.event_record.hash_matched = False
            return StageResult(
                stage_name=self.name,
                passed=False,
                hard_block=True,
                explanation=f"Stage 1 Fail-Closed: Database unavailable or integrity hash query error for '{tool_name}': {e}",
                metadata={"error": str(e), "observed_hash": observed_hash}
            )

        context.event_record.expected_hash = expected_hash

        # 4. Fail-closed if no approved hash is recorded in DB (NO_APPROVED_BASELINE)
        if not expected_hash:
            logger.warning("Stage 1 Fail-Closed: NO_APPROVED_BASELINE for '%s:%s'", server_name, tool_name)
            context.event_record.hash_matched = False
            return StageResult(
                stage_name=self.name,
                passed=False,
                hard_block=True,
                explanation=f"Stage 1 Fail-Closed (NO_APPROVED_BASELINE): Tool '{tool_name}' has no active approved baseline in PostgreSQL database. Please run trusted registration before calling.",
                metadata={"observed_hash": observed_hash, "expected_hash": None, "reason": "NO_APPROVED_BASELINE"}
            )

        # 5. Compare hashes (Rug Pull detection)
        if observed_hash != expected_hash:
            logger.warning(
                "Stage 1 Rug Pull Detected for '%s:%s'! Expected=%s, Observed=%s",
                server_name, tool_name, expected_hash, observed_hash
            )
            context.event_record.hash_matched = False
            return StageResult(
                stage_name=self.name,
                passed=False,
                hard_block=True,
                explanation=f"Stage 1 Rug Pull Detected: Tool definition for '{tool_name}' changed after approval. Expected SHA-256: {expected_hash}, Observed: {observed_hash}",
                metadata={"expected_hash": expected_hash, "observed_hash": observed_hash, "reason": "HASH_MISMATCH"}
            )

        # 6. Hash match -> PASS
        logger.info("Stage 1 Hash Check PASSED for '%s:%s' (SHA-256: %s)", server_name, tool_name, observed_hash[:12])
        context.event_record.hash_matched = True
        return StageResult(
            stage_name=self.name,
            passed=True,
            hard_block=False,
            explanation=f"Stage 1 Hash Check Passed: SHA-256 integrity hash matched approved baseline ({observed_hash[:12]}...)",
            metadata={"expected_hash": expected_hash, "observed_hash": observed_hash}
        )
