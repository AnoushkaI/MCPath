"""Deterministic Capability Inference Engine.

Derives capability metadata deterministically from tool definitions (name, description,
inputSchema) and configured server contexts according to config/capability_policy.json.
Invariants:
- Strictly deterministic: no LLM or heuristics outside versioned policy rules.
- Conservative: never invent capabilities unsupported by manifest or configuration.
- Separation of policy from logic: all thresholds, weights, and mappings reside in policy.
- Evidence priority: explicit rule -> description -> schema -> tool name -> conservative fallback.
"""

from dataclasses import dataclass, field
import json
import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple
from mcpath.config.settings import PROJECT_ROOT

logger = logging.getLogger("mcpath.graph.inference")

DEFAULT_POLICY_PATH = PROJECT_ROOT / "config" / "capability_policy.json"


@dataclass
class ToolCapability:
    """Classified capability metadata for a single tool."""
    tool_name: str
    server_name: str
    data_target: str
    operation: str  # READ or WRITE
    action_type: str
    data_sensitivity: float
    action_sensitivity: float
    external_exposure: float
    external_destination: Optional[str] = None
    consumed_data_types: List[str] = field(default_factory=list)
    policy_version: str = "1.0.0"
    raw_metadata: Dict[str, Any] = field(default_factory=dict)


class CapabilityClassifier:
    """Loads versioned policy and deterministically classifies tool manifests."""

    def __init__(self, policy_path: Optional[Path] = None):
        self.policy_path = policy_path or DEFAULT_POLICY_PATH
        self.policy: Dict[str, Any] = {}
        self.load_policy()

    def load_policy(self) -> None:
        """Load and parse the JSON capability policy."""
        try:
            if self.policy_path.exists():
                with open(self.policy_path, "r", encoding="utf-8") as f:
                    self.policy = json.load(f)
                logger.info(
                    "Loaded capability policy v%s from %s",
                    self.policy.get("policy_version", "unknown"),
                    self.policy_path
                )
            else:
                logger.warning("Capability policy file not found at %s. Using minimal defaults.", self.policy_path)
                self.policy = {
                    "policy_version": "1.0.0",
                    "weights": {"data_sensitivity": 0.30, "action_sensitivity": 0.25, "external_exposure": 0.20, "chain_risk": 0.25},
                    "scale_max": 3.0,
                    "critical_path_override": {"enabled": True, "min_data_sensitivity": 2.0, "require_external_action": True, "require_external_destination": True, "classification": "HIGH", "override_score": 85.0},
                    "unknown_path_handling": {"score": 75.0, "classification": "HIGH", "explanation": "CAPABILITY PATH: UNKNOWN / UNMODELED"},
                    "explicit_tool_rules": {},
                    "pattern_inference_rules": {},
                    "default_classification": {"data_target": "generic_resource", "operation": "READ", "action_type": "internal_operation", "data_sensitivity": 0.0, "action_sensitivity": 0.0, "external_exposure": 0.0, "external_destination": None, "consumed_data_types": []}
                }
        except Exception as e:
            logger.error("Error reading capability policy from %s: %s", self.policy_path, e)
            raise

    @property
    def version(self) -> str:
        """Return the policy version."""
        return self.policy.get("policy_version", "1.0.0")

    @staticmethod
    def _word_match(pattern_str: str, text: str) -> Optional[re.Match]:
        """Match regex pattern strictly on word boundaries to avoid substring false-positives."""
        if not text:
            return None
        pat = pattern_str
        if pat.startswith("(?i)"):
            pat = pat[4:]
        if not pat.startswith(r"\b"):
            bound_pat = r"\b(?:" + pat + r")\b"
        else:
            bound_pat = pat
        return re.search(bound_pat, text, re.IGNORECASE)

    @classmethod
    def _match_rules(cls, rules_list: List[Dict[str, Any]], text: str) -> Optional[Tuple[Dict[str, Any], str]]:
        """Evaluate a list of regex pattern rules against text using word-boundary matching."""
        if not text:
            return None
        for rule in rules_list:
            pat = rule.get("pattern", "")
            m = cls._word_match(pat, text)
            if m:
                return rule, m.group(0)
        return None

    def classify_tool(self, server_name: str, tool_def: Dict[str, Any]) -> ToolCapability:
        """Classify a single discovered tool with evidence-based priority and explainability.

        Priority order:
        explicit rule -> description -> schema -> tool name -> conservative fallback.
        """
        raw_name = tool_def.get("name", "")
        tool_name = raw_name
        description = (tool_def.get("description", "") or "").strip()
        input_schema = tool_def.get("inputSchema") or tool_def.get("input_schema") or {}
        if not isinstance(input_schema, dict):
            input_schema = {}

        schema_props = input_schema.get("properties", {})
        if not isinstance(schema_props, dict):
            schema_props = {}
        prop_names = " ".join(schema_props.keys())

        # Strip server prefixes from tool name to prevent keyword contamination (e.g. postgres_ -> post)
        clean_name = tool_name
        for pfx in [f"{server_name}_", f"{server_name}-", f"{server_name.replace('-', '_')}_"]:
            if clean_name.lower().startswith(pfx.lower()):
                clean_name = clean_name[len(pfx):]
                break
        if server_name.lower() in ("postgres-mcp", "postgres"):
            for pfx in ("postgres_mcp_", "postgres_"):
                if clean_name.lower().startswith(pfx):
                    clean_name = clean_name[len(pfx):]
                    break
        elif server_name.lower() == "git" and clean_name.lower().startswith("git_"):
            clean_name = clean_name[4:]
        elif server_name.lower() == "filesystem" and clean_name.lower().startswith("fs_"):
            clean_name = clean_name[3:]

        # 1. Check explicit tool rules (direct match on tool_name, clean_name, or suffix after server prefix)
        explicit_rules = self.policy.get("explicit_tool_rules", {})
        matched_rule = None
        matched_key = None
        if tool_name in explicit_rules:
            matched_rule = explicit_rules[tool_name]
            matched_key = tool_name
        elif clean_name in explicit_rules:
            matched_rule = explicit_rules[clean_name]
            matched_key = clean_name
        elif "_" in tool_name:
            parts = tool_name.split("_", 1)
            if parts[1] in explicit_rules:
                matched_rule = explicit_rules[parts[1]]
                matched_key = parts[1]

        if matched_rule:
            consumed = list(matched_rule.get("consumed_data_types", []))
            evidence = {
                "operation": {"source": "explicit_rule", "matched": matched_key},
                "action_type": {"source": "explicit_rule", "matched": matched_key},
                "data_target": {"source": "explicit_rule", "matched": matched_key},
                "data_sensitivity": {"source": "explicit_rule", "matched": matched_key},
                "action_sensitivity": {"source": "explicit_rule", "matched": matched_key},
                "external_exposure": {"source": "explicit_rule", "matched": matched_key},
                "consumed_data_types": {"source": "explicit_rule", "matched": matched_key}
            }
            return ToolCapability(
                tool_name=tool_name,
                server_name=server_name,
                data_target=matched_rule["data_target"],
                operation=matched_rule.get("operation", "READ"),
                action_type=matched_rule.get("action_type", "operation"),
                data_sensitivity=float(matched_rule.get("data_sensitivity", 0.0)),
                action_sensitivity=float(matched_rule.get("action_sensitivity", 0.0)),
                external_exposure=float(matched_rule.get("external_exposure", 0.0)),
                external_destination=matched_rule.get("external_destination"),
                consumed_data_types=consumed,
                policy_version=self.version,
                raw_metadata={
                    "rule_source": "explicit",
                    "matched_key": matched_key,
                    "evidence": evidence
                }
            )

        # 2. Evidence-based pattern inference
        patterns = self.policy.get("pattern_inference_rules", {})
        defaults = self.policy.get("default_classification", {})

        evidence: Dict[str, Dict[str, str]] = {}

        # -------------------------------------------------------------------
        # Dimension A: Operation (READ vs WRITE)
        # Priority: description -> schema -> clean_name -> fallback (default READ)
        # -------------------------------------------------------------------
        op_rules = patterns.get("operation_patterns", [])
        operation = defaults.get("operation", "READ")
        
        # Check description first
        m_desc = self._match_rules(op_rules, description)
        if m_desc:
            operation = m_desc[0]["operation"]
            evidence["operation"] = {"source": "description", "matched": m_desc[1]}
        else:
            # Check schema property names
            m_schema = self._match_rules(op_rules, prop_names)
            if m_schema:
                operation = m_schema[0]["operation"]
                evidence["operation"] = {"source": "schema", "matched": m_schema[1]}
            else:
                # Check tool name
                m_name = self._match_rules(op_rules, clean_name)
                if m_name:
                    operation = m_name[0]["operation"]
                    evidence["operation"] = {"source": "name", "matched": m_name[1]}
                elif clean_name.lower() in ("commit", "save", "edit", "purge", "rmdir"):
                    operation = "WRITE"
                    evidence["operation"] = {"source": "name", "matched": clean_name}
                else:
                    operation = defaults.get("operation", "READ")
                    evidence["operation"] = {"source": "fallback", "matched": "default_read"}

        # -------------------------------------------------------------------
        # Dimension B: Action Sensitivity & Action Type
        # Priority: description -> schema -> clean_name -> fallback
        # -------------------------------------------------------------------
        act_rules = patterns.get("action_sensitivity_patterns", [])
        action_sensitivity = float(defaults.get("action_sensitivity", 0.0))
        action_type = defaults.get("action_type", "internal_operation")

        m_act = (
            self._match_rules(act_rules, description)
            or self._match_rules(act_rules, prop_names)
            or self._match_rules(act_rules, clean_name)
        )
        if m_act:
            rule, matched_str = m_act
            action_sensitivity = float(rule.get("action_sensitivity", action_sensitivity))
            action_type = rule.get("action_type", action_type)
            # Find which source matched
            if self._word_match(rule.get("pattern", ""), description):
                src = "description"
            elif self._word_match(rule.get("pattern", ""), prop_names):
                src = "schema"
            else:
                src = "name"
            evidence["action_type"] = {"source": src, "matched": matched_str}
            evidence["action_sensitivity"] = {"source": src, "matched": matched_str}
        else:
            evidence["action_type"] = {"source": "fallback", "matched": action_type}
            evidence["action_sensitivity"] = {"source": "fallback", "matched": str(action_sensitivity)}

        # -------------------------------------------------------------------
        # Dimension C: Data Target & Data Sensitivity
        # Priority: high-severity sensitive patterns -> server context -> general patterns -> fallback
        # -------------------------------------------------------------------
        sens_rules = patterns.get("sensitive_data_patterns", [])
        data_sensitivity = float(defaults.get("data_sensitivity", 0.0))
        data_target = defaults.get("data_target", "generic_resource")

        # 1. High-severity sensitive data check (PII, credentials, secrets, financial/customer records)
        high_sens_rules = [
            r for r in sens_rules
            if float(r.get("data_sensitivity", 0.0)) >= 2.5
        ]
        m_high = (
            self._match_rules(high_sens_rules, description)
            or self._match_rules(high_sens_rules, prop_names)
            or self._match_rules(high_sens_rules, clean_name)
        )
        if m_high:
            rule, matched_str = m_high
            data_sensitivity = float(rule.get("data_sensitivity", data_sensitivity))
            data_target = rule.get("data_target", data_target)
            src = "description" if self._word_match(rule.get("pattern", ""), description) else ("schema" if self._word_match(rule.get("pattern", ""), prop_names) else "name")
            evidence["data_target"] = {"source": src, "matched": matched_str}
            evidence["data_sensitivity"] = {"source": src, "matched": matched_str}
        else:
            # 2. Check server context for native resource target
            s_lower = server_name.lower()
            if s_lower in ("postgres-mcp", "postgres"):
                data_target = "database_records"
                data_sensitivity = 2.0
                evidence["data_target"] = {"source": "server_context", "matched": server_name}
                evidence["data_sensitivity"] = {"source": "server_context", "matched": server_name}
            elif s_lower == "filesystem":
                data_target = "filesystem_data"
                data_sensitivity = 1.5
                evidence["data_target"] = {"source": "server_context", "matched": server_name}
                evidence["data_sensitivity"] = {"source": "server_context", "matched": server_name}
            elif s_lower == "git":
                data_target = "git_repository"
                data_sensitivity = 1.0
                evidence["data_target"] = {"source": "server_context", "matched": server_name}
                evidence["data_sensitivity"] = {"source": "server_context", "matched": server_name}
            else:
                # 3. Check general sensitive data patterns
                m_gen = (
                    self._match_rules(sens_rules, description)
                    or self._match_rules(sens_rules, prop_names)
                    or self._match_rules(sens_rules, clean_name)
                )
                if m_gen:
                    rule, matched_str = m_gen
                    data_sensitivity = float(rule.get("data_sensitivity", data_sensitivity))
                    data_target = rule.get("data_target", data_target)
                    src = "description" if self._word_match(rule.get("pattern", ""), description) else ("schema" if self._word_match(rule.get("pattern", ""), prop_names) else "name")
                    evidence["data_target"] = {"source": src, "matched": matched_str}
                    evidence["data_sensitivity"] = {"source": src, "matched": matched_str}
                else:
                    evidence["data_target"] = {"source": "fallback", "matched": data_target}
                    evidence["data_sensitivity"] = {"source": "fallback", "matched": str(data_sensitivity)}

        # -------------------------------------------------------------------
        # Dimension D: External Exposure
        # Local filesystem/git/postgres tools default to external_exposure=0.
        # Words such as fetch/message/commit must not imply external exposure.
        # -------------------------------------------------------------------
        is_local_server = server_name.lower() in ("filesystem", "git", "postgres", "postgres-mcp", "sqlite", "local")
        external_exposure = 0.0
        external_destination = None

        if is_local_server:
            evidence["external_exposure"] = {
                "source": "server_context",
                "matched": f"local_server:{server_name}"
            }
        else:
            ext_rules = patterns.get("external_exposure_patterns", [])
            ext_match = None
            for target_text, src_name in [(description, "description"), (prop_names, "schema"), (clean_name, "name")]:
                res = self._match_rules(ext_rules, target_text)
                if res:
                    rule, matched_str = res
                    # Benign generic keywords must not imply external exposure
                    if matched_str.lower() in ("fetch", "message", "commit"):
                        continue
                    ext_match = (rule, matched_str, src_name)
                    break

            if ext_match:
                rule, matched_str, src_name = ext_match
                external_exposure = float(rule.get("external_exposure", 0.0))
                external_destination = rule.get("external_destination")
                if "action_type" in rule:
                    action_type = rule["action_type"]
                evidence["external_exposure"] = {"source": src_name, "matched": matched_str}
            else:
                evidence["external_exposure"] = {"source": "fallback", "matched": "default_internal"}

        # -------------------------------------------------------------------
        # Dimension E: Consumed Data Types
        # Never assign blanket customer_pii / filesystem_data / database_records / generic_data.
        # Self-contained tools consume only their proven data_target.
        # Extend only when schema properties explicitly prove data acceptance.
        # -------------------------------------------------------------------
        consumed_data_types = [data_target]
        proven_consumed_types: List[str] = []

        # Check input schema properties for evidence of consuming other resources
        schema_keys = set(schema_props.keys())
        if schema_keys.intersection({"sql", "query", "sql_query"}) and data_target != "database_records":
            consumed_data_types.append("database_records")
            proven_consumed_types.append("database_records")
        if schema_keys.intersection({"file_path", "filepath", "path", "file_content", "contents"}) and data_target != "filesystem_data":
            consumed_data_types.append("filesystem_data")
            proven_consumed_types.append("filesystem_data")

        evidence["consumed_data_types"] = {
            "source": "schema" if proven_consumed_types else "self_contained",
            "matched": proven_consumed_types if proven_consumed_types else [data_target]
        }

        return ToolCapability(
            tool_name=tool_name,
            server_name=server_name,
            data_target=data_target,
            operation=operation,
            action_type=action_type,
            data_sensitivity=data_sensitivity,
            action_sensitivity=action_sensitivity,
            external_exposure=external_exposure,
            external_destination=external_destination,
            consumed_data_types=consumed_data_types,
            policy_version=self.version,
            raw_metadata={
                "rule_source": "pattern_inference",
                "clean_name": clean_name,
                "proven_consumed_types": proven_consumed_types,
                "evidence": evidence
            }
        )
