"""Dynamic NetworkX Causal Capability Graph and Path Scoring Engine.

Represents connected MCP servers, tools, data resources, actions, and destinations.
Nodes:
- Agent
- Tool
- Data/Resource
- Action
- External Destination

Typed Edges:
- CAN_CALL (Agent -> Tool)
- READS (Tool -> Data/Resource)
- WRITES (Tool -> Data/Resource)
- FLOWS_TO (Data/Resource -> Action)
- SENDS_TO (Action -> External Destination)
"""

from dataclasses import asdict, dataclass, field, replace as dc_replace
import hashlib
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import re
import networkx as nx

from mcpath.graph.capability_inference import CapabilityClassifier, ToolCapability

logger = logging.getLogger("mcpath.graph.capability_graph")


def generate_path_id(path_nodes: List[str]) -> str:
    """Generate a unique, persistent identifier for a capability path.
    
    Stable across graph rebuilds when the underlying path nodes have not changed.
    Format: path_{tool_name}_{sha256(path_nodes)[:8]}
    """
    tool_token = "generic"
    for n in path_nodes:
        if n.startswith("Tool:"):
            raw_tool = n.split("Tool:", 1)[1]
            tool_token = raw_tool.replace(":", "_").replace("-", "_")
            break
    node_str = "->".join(path_nodes)
    digest = hashlib.sha256(node_str.encode("utf-8")).hexdigest()[:8]
    return f"path_{tool_token}_{digest}"


@dataclass
class PathScoringResult:
    """Detailed score and explainability record for a complete graph path."""
    path_nodes: List[str]
    path_edges: List[str]
    data_sensitivity: float
    action_sensitivity: float
    external_exposure: float
    chain_risk: float
    path_risk_score: float
    classification: str  # LOW, MEDIUM, HIGH
    is_critical_override: bool
    explanation: str
    policy_version: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    path_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if not d.get("path_id") and self.path_nodes and "Unknown/Unmodeled" not in self.path_nodes:
            d["path_id"] = generate_path_id(self.path_nodes)
        return d


class CapabilityGraph:
    """Dynamic causal capability graph for connected MCP tools and multi-server environments."""

    def __init__(self, classifier: Optional[CapabilityClassifier] = None):
        self.classifier = classifier or CapabilityClassifier()
        self.graph = nx.DiGraph()
        self.tool_capabilities: Dict[str, ToolCapability] = {}
        self._computed_paths: Dict[str, List[PathScoringResult]] = {}
        self._init_root()

    def _init_root(self) -> None:
        """Initialize the root Agent node."""
        self.graph.add_node("Agent", type="Agent", label="Agent", server="mcpath")

    @property
    def policy(self) -> Dict[str, Any]:
        return self.classifier.policy

    @property
    def policy_version(self) -> str:
        return self.classifier.version

    def rebuild_for_all_servers(self, server_tools: Dict[str, List[Dict[str, Any]]]) -> None:
        """Rebuild capability graph dynamically representing all currently configured servers.

        Tool identity uses the same collision-namespacing as
        DownstreamClientManager.recompute_exposed_tools(): when the same raw
        tool name appears in more than one server the canonical name becomes
        ``{server_name}_{tool_name}``; unique names are kept as-is.
        """
        self.graph.clear()
        self.tool_capabilities.clear()
        self._computed_paths.clear()
        self._init_root()

        # 1a. First pass – count raw tool-name occurrences across all servers
        #     (mirrors the name_counts logic in recompute_exposed_tools)
        name_counts: Dict[str, int] = {}
        for tools in server_tools.values():
            for tool_def in tools:
                raw = tool_def.get("name", "")
                name_counts[raw] = name_counts.get(raw, 0) + 1

        # 1b. Classify all discovered tools, stamping the canonical name
        for server_name, tools in server_tools.items():
            for tool_def in tools:
                cap = self.classifier.classify_tool(server_name, tool_def)
                # Apply the same namespacing as the exposed-tools catalog
                if name_counts.get(cap.tool_name, 1) > 1:
                    canonical_name = f"{server_name}_{cap.tool_name}"
                else:
                    canonical_name = cap.tool_name
                if canonical_name != cap.tool_name:
                    cap = dc_replace(cap, tool_name=canonical_name)
                self.tool_capabilities[canonical_name] = cap

        # 2. Populate nodes and intra-tool edges
        for tool_name, cap in self.tool_capabilities.items():
            # EXACTLY ONE canonical Tool node per tool: Tool:{tool_name}
            tool_node_id = f"Tool:{cap.tool_name}"
            self.graph.add_node(
                tool_node_id,
                type="Tool",
                label=cap.tool_name,
                server=cap.server_name,
                operation=cap.operation,
                action_type=cap.action_type
            )
            # Exactly ONE CAN_CALL edge from Agent
            self.graph.add_edge("Agent", tool_node_id, relation="CAN_CALL")

            # Data/Resource Node
            resource_node_id = f"Resource:{cap.data_target}"
            if not self.graph.has_node(resource_node_id):
                self.graph.add_node(
                    resource_node_id,
                    type="Data/Resource",
                    label=cap.data_target,
                    data_sensitivity=cap.data_sensitivity,
                    server=cap.server_name
                )
            else:
                # Keep highest data sensitivity if shared
                curr_sens = self.graph.nodes[resource_node_id].get("data_sensitivity", 0.0)
                self.graph.nodes[resource_node_id]["data_sensitivity"] = max(curr_sens, cap.data_sensitivity)

            # Tool -> Data/Resource edge (READS or WRITES)
            if cap.operation == "READ":
                self.graph.add_edge(tool_node_id, resource_node_id, relation="READS")
            else:
                self.graph.add_edge(tool_node_id, resource_node_id, relation="WRITES")

            # Action Node
            action_node_id = f"Action:{cap.tool_name}:{cap.action_type}"
            self.graph.add_node(
                action_node_id,
                type="Action",
                label=cap.action_type,
                action_sensitivity=cap.action_sensitivity,
                action_type=cap.action_type,
                server=cap.server_name,
                tool_name=cap.tool_name
            )

            # Tool's own data flows to its action (proven intra-tool connection)
            self.graph.add_edge(resource_node_id, action_node_id, relation="FLOWS_TO")

            # External Destination Node & SENDS_TO edge
            if cap.external_destination:
                dest_node_id = f"Destination:{cap.external_destination}"
                if not self.graph.has_node(dest_node_id):
                    self.graph.add_node(
                        dest_node_id,
                        type="External Destination",
                        label=cap.external_destination,
                        external_exposure=cap.external_exposure,
                        server=cap.server_name
                    )
                self.graph.add_edge(action_node_id, dest_node_id, relation="SENDS_TO")

        # 3. Inter-tool compatible data flows (FLOWS_TO edges)
        # Create Resource:R -> Action:T:A ONLY when evidence proves T can consume/use R
        explicit_rules = self.policy.get("explicit_tool_rules", {})
        compat_policy = self.policy.get("compatibility_rules", {})
        allowed_transitions = compat_policy.get("allowed_resource_actions", {})

        for tool_name, cap in self.tool_capabilities.items():
            action_node_id = f"Action:{cap.tool_name}:{cap.action_type}"
            for res_type in cap.consumed_data_types:
                if res_type == cap.data_target:
                    continue  # Already connected above

                target_res_id = f"Resource:{res_type}"
                if not self.graph.has_node(target_res_id):
                    continue

                # Evidence checks:
                # a. explicit_tool_rules.consumed_data_types contains res_type
                has_explicit_rule = False
                if tool_name in explicit_rules and res_type in explicit_rules[tool_name].get("consumed_data_types", []):
                    has_explicit_rule = True
                elif "_" in tool_name:
                    suffix = tool_name.split("_", 1)[1]
                    if suffix in explicit_rules and res_type in explicit_rules[suffix].get("consumed_data_types", []):
                        has_explicit_rule = True

                # b. explicit compatibility rule permits res_type -> action_type or tool_name
                has_compat_rule = (
                    res_type in allowed_transitions.get(cap.action_type, []) or
                    res_type in allowed_transitions.get(tool_name, [])
                )

                # c. tool schema / proven consumed types
                has_schema_evidence = False
                raw_meta = cap.raw_metadata or {}
                if res_type in raw_meta.get("proven_consumed_types", []):
                    has_schema_evidence = True

                # NEVER create FLOWS_TO merely because tools share a server, resource class, or exist in the same graph
                if has_explicit_rule or has_compat_rule or has_schema_evidence:
                    if not self.graph.has_edge(target_res_id, action_node_id):
                        self.graph.add_edge(target_res_id, action_node_id, relation="FLOWS_TO")

        # 4. Enumerate and precompute compatible paths
        self._enumerate_all_paths()
        logger.info(
            "Capability graph rebuilt: %d nodes, %d edges, %d tools across %d servers",
            self.graph.number_of_nodes(),
            self.graph.number_of_edges(),
            len(self.tool_capabilities),
            len(server_tools)
        )

    def add_tool(self, server_name: str, tool_def: Dict[str, Any]) -> None:
        """Dynamically add and classify a tool into the graph on-the-fly.

        Uses the same collision-namespacing rule as rebuild_for_all_servers:
        if a different server has already registered the same raw tool name the
        canonical name becomes ``{server_name}_{tool_name}``.
        """
        cap = self.classifier.classify_tool(server_name, tool_def)
        # Detect collision: same raw name already registered from a DIFFERENT server
        raw_name = cap.tool_name
        existing = self.tool_capabilities.get(raw_name)
        collision = existing is not None and existing.server_name != server_name
        if collision:
            # The pre-existing entry also needs to be re-keyed (mirrors rebuild behaviour)
            old_cap = self.tool_capabilities.pop(raw_name)
            old_canonical = f"{old_cap.server_name}_{raw_name}"
            old_cap = dc_replace(old_cap, tool_name=old_canonical)
            self.tool_capabilities[old_canonical] = old_cap
            canonical_name = f"{server_name}_{raw_name}"

            # Rename the pre-existing graph nodes so _enumerate_all_paths can find them
            old_tool_node = f"Tool:{raw_name}"
            new_tool_node = f"Tool:{old_canonical}"
            old_action_prefix = f"Action:{raw_name}:"
            rename_map: Dict[str, str] = {}
            for node in list(self.graph.nodes()):
                if node == old_tool_node:
                    rename_map[node] = new_tool_node
                elif node.startswith(old_action_prefix):
                    suffix = node[len(old_action_prefix):]
                    rename_map[node] = f"Action:{old_canonical}:{suffix}"
            if rename_map:
                nx.relabel_nodes(self.graph, rename_map, copy=False)
        else:
            canonical_name = raw_name
        if canonical_name != cap.tool_name:
            cap = dc_replace(cap, tool_name=canonical_name)
        self.tool_capabilities[canonical_name] = cap


        # EXACTLY ONE canonical Tool node per tool: Tool:{tool_name}
        tool_node_id = f"Tool:{cap.tool_name}"
        self.graph.add_node(
            tool_node_id,
            type="Tool",
            label=cap.tool_name,
            server=cap.server_name,
            operation=cap.operation,
            action_type=cap.action_type
        )
        self.graph.add_edge("Agent", tool_node_id, relation="CAN_CALL")

        resource_node_id = f"Resource:{cap.data_target}"
        if not self.graph.has_node(resource_node_id):
            self.graph.add_node(
                resource_node_id,
                type="Data/Resource",
                label=cap.data_target,
                data_sensitivity=cap.data_sensitivity,
                server=cap.server_name
            )
        else:
            curr_sens = self.graph.nodes[resource_node_id].get("data_sensitivity", 0.0)
            self.graph.nodes[resource_node_id]["data_sensitivity"] = max(curr_sens, cap.data_sensitivity)

        if cap.operation == "READ":
            self.graph.add_edge(tool_node_id, resource_node_id, relation="READS")
        else:
            self.graph.add_edge(tool_node_id, resource_node_id, relation="WRITES")

        action_node_id = f"Action:{cap.tool_name}:{cap.action_type}"
        self.graph.add_node(
            action_node_id,
            type="Action",
            label=cap.action_type,
            action_sensitivity=cap.action_sensitivity,
            action_type=cap.action_type,
            server=cap.server_name,
            tool_name=cap.tool_name
        )
        self.graph.add_edge(resource_node_id, action_node_id, relation="FLOWS_TO")

        if cap.external_destination:
            dest_node_id = f"Destination:{cap.external_destination}"
            if not self.graph.has_node(dest_node_id):
                self.graph.add_node(
                    dest_node_id,
                    type="External Destination",
                    label=cap.external_destination,
                    external_exposure=cap.external_exposure,
                    server=cap.server_name
                )
            self.graph.add_edge(action_node_id, dest_node_id, relation="SENDS_TO")

        # Inter-tool compatible data flows
        explicit_rules = self.policy.get("explicit_tool_rules", {})
        compat_policy = self.policy.get("compatibility_rules", {})
        allowed_transitions = compat_policy.get("allowed_resource_actions", {})

        for res_type in cap.consumed_data_types:
            if res_type == cap.data_target:
                continue
            target_res_id = f"Resource:{res_type}"
            if not self.graph.has_node(target_res_id):
                continue

            has_explicit_rule = False
            if cap.tool_name in explicit_rules and res_type in explicit_rules[cap.tool_name].get("consumed_data_types", []):
                has_explicit_rule = True
            elif "_" in cap.tool_name:
                suffix = cap.tool_name.split("_", 1)[1]
                if suffix in explicit_rules and res_type in explicit_rules[suffix].get("consumed_data_types", []):
                    has_explicit_rule = True

            has_compat_rule = (
                res_type in allowed_transitions.get(cap.action_type, []) or
                res_type in allowed_transitions.get(cap.tool_name, [])
            )
            has_schema_evidence = False
            raw_meta = cap.raw_metadata or {}
            if res_type in raw_meta.get("proven_consumed_types", []):
                has_schema_evidence = True

            if has_explicit_rule or has_compat_rule or has_schema_evidence:
                if not self.graph.has_edge(target_res_id, action_node_id):
                    self.graph.add_edge(target_res_id, action_node_id, relation="FLOWS_TO")

        self._enumerate_all_paths()

    def remove_server(self, server_name: str) -> None:
        """Remove all tools and nodes associated with a removed server."""
        tools_to_remove = [
            t_name for t_name, cap in self.tool_capabilities.items()
            if cap.server_name == server_name
        ]
        for t_name in tools_to_remove:
            self.tool_capabilities.pop(t_name, None)

        nodes_to_remove = [
            n for n, data in self.graph.nodes(data=True)
            if data.get("server") == server_name and n != "Agent"
        ]
        self.graph.remove_nodes_from(nodes_to_remove)
        self._enumerate_all_paths()

    def _enumerate_all_paths(self) -> None:
        """Enumerate all valid directed paths adhering to typed-edge compatibility rules."""
        self._computed_paths.clear()

        # Find all terminal action or destination sink nodes in the causal DAG
        dest_nodes = [
            n for n, d in self.graph.nodes(data=True)
            if self.graph.out_degree(n) == 0 and d.get("type") in ("Action", "External Destination")
        ]

        for tool_name, cap in self.tool_capabilities.items():
            tool_node_id = f"Tool:{cap.tool_name}"
            tool_paths: List[PathScoringResult] = []

            for end_node in dest_nodes:
                if not nx.has_path(self.graph, tool_node_id, end_node):
                    continue

                for raw_path in nx.all_simple_paths(self.graph, tool_node_id, end_node, cutoff=6):
                    # Verify path compatibility: Agent/Tool -> Resource -> Action (-> Destination)
                    if self._is_compatible_path(raw_path):
                        # Prepend Agent to represent the full causal path
                        full_path = ["Agent"] + raw_path
                        scored = self.score_path(full_path)
                        tool_paths.append(scored)

            # Deduplicate paths by node sequence
            unique_paths: Dict[Tuple[str, ...], PathScoringResult] = {}
            for p in tool_paths:
                key = tuple(p.path_nodes)
                if key not in unique_paths:
                    unique_paths[key] = p
                else:
                    # Keep path with higher risk score
                    if p.path_risk_score > unique_paths[key].path_risk_score:
                        unique_paths[key] = p

            self._computed_paths[tool_name] = list(unique_paths.values())

    def _is_compatible_path(self, path: List[str]) -> bool:
        """Strictly verify typed edge compatibility along directed path."""
        for i in range(len(path) - 1):
            u, v = path[i], path[i + 1]
            if not self.graph.has_edge(u, v):
                return False
            edge_rel = self.graph[u][v].get("relation")
            u_type = self.graph.nodes[u].get("type")
            v_type = self.graph.nodes[v].get("type")

            # Check edge type compatibility
            if u_type == "Agent" and not (v_type == "Tool" and edge_rel == "CAN_CALL"):
                return False
            elif u_type == "Tool" and not (v_type == "Data/Resource" and edge_rel in ("READS", "WRITES")):
                return False
            elif u_type == "Data/Resource" and not (v_type == "Action" and edge_rel == "FLOWS_TO"):
                return False
            elif u_type == "Action" and not (v_type == "External Destination" and edge_rel == "SENDS_TO"):
                return False

        return True

    def calculate_chain_risk(self, path_nodes: List[str]) -> float:
        """Calculate deterministic chain risk based on security significance of compatible transitions."""
        chain_policy = self.policy.get("chain_risk_policy", {})
        transitions_cfg = chain_policy.get("transitions", {})
        sensitive_thresh = float(chain_policy.get("sensitive_threshold", 2.0))
        base_risk = float(chain_policy.get("base_risk", 0.2))

        highest_transition_risk = base_risk
        prev_server = None
        has_cross_server_hop = False

        for i in range(len(path_nodes) - 1):
            u = path_nodes[i]
            v = path_nodes[i + 1]
            u_node = self.graph.nodes.get(u, {})
            v_node = self.graph.nodes.get(v, {})

            u_type = u_node.get("type")
            v_type = v_node.get("type")
            u_server = u_node.get("server")
            v_server = v_node.get("server")

            # Track cross-server transitions
            if u_server and v_server and u_server != v_server and u_server != "mcpath" and v_server != "mcpath":
                has_cross_server_hop = True

            # 1. Data/Resource -> Action transition
            if u_type == "Data/Resource" and v_type == "Action":
                data_sens = float(u_node.get("data_sensitivity", 0.0))
                act_type = str(v_node.get("action_type", ""))
                is_external_act = any(ext_kw in act_type for ext_kw in ("external", "send", "network", "communication"))

                if data_sens >= sensitive_thresh and is_external_act:
                    t_risk = float(transitions_cfg.get("sensitive_data_to_external_action", 3.0))
                elif data_sens >= sensitive_thresh and any(w_kw in act_type for w_kw in ("write", "modify", "delete")):
                    t_risk = float(transitions_cfg.get("sensitive_data_to_write_action", 2.0))
                elif data_sens >= sensitive_thresh:
                    t_risk = float(transitions_cfg.get("sensitive_data_to_read_action", 1.0))
                elif is_external_act:
                    t_risk = float(transitions_cfg.get("standard_data_to_external_action", 2.0))
                else:
                    t_risk = float(transitions_cfg.get("benign_data_to_benign_action", 0.1))

                highest_transition_risk = max(highest_transition_risk, t_risk)

            # 2. Action -> External Destination transition
            elif u_type == "Action" and v_type == "External Destination":
                t_risk = float(transitions_cfg.get("action_to_external_destination", 2.5))
                highest_transition_risk = max(highest_transition_risk, t_risk)

        if has_cross_server_hop:
            highest_transition_risk = min(
                3.0,
                highest_transition_risk + float(transitions_cfg.get("cross_server_boundary_hop", 0.5))
            )

        scale_max = float(self.policy.get("scale_max", 3.0))
        return min(scale_max, round(highest_transition_risk, 2))

    def score_path(self, path_nodes: List[str]) -> PathScoringResult:
        """Compute deterministic path risk score: 0.30*Data + 0.25*Action + 0.20*Exposure + 0.25*Chain."""
        weights = self.policy.get("weights", {
            "data_sensitivity": 0.30,
            "action_sensitivity": 0.25,
            "external_exposure": 0.20,
            "chain_risk": 0.25
        })
        scale_max = float(self.policy.get("scale_max", 3.0))

        # Extract attributes from nodes along the path
        data_sens = 0.0
        action_sens = 0.0
        ext_exposure = 0.0
        path_edges: List[str] = []

        for i in range(len(path_nodes)):
            node_name = path_nodes[i]
            node_data = self.graph.nodes.get(node_name, {})
            node_type = node_data.get("type")

            if node_type == "Data/Resource":
                data_sens = max(data_sens, float(node_data.get("data_sensitivity", 0.0)))
            elif node_type == "Action":
                action_sens = max(action_sens, float(node_data.get("action_sensitivity", 0.0)))
            elif node_type == "External Destination":
                ext_exposure = max(ext_exposure, float(node_data.get("external_exposure", 0.0)))

            if i < len(path_nodes) - 1:
                next_node = path_nodes[i + 1]
                edge_rel = self.graph[node_name][next_node].get("relation", "CONNECTED")
                path_edges.append(edge_rel)

        chain_risk = self.calculate_chain_risk(path_nodes)

        # Standard weighted score
        w_data = float(weights.get("data_sensitivity", 0.30))
        w_act = float(weights.get("action_sensitivity", 0.25))
        w_exp = float(weights.get("external_exposure", 0.20))
        w_chain = float(weights.get("chain_risk", 0.25))

        weighted_sum = (
            (w_data * data_sens) +
            (w_act * action_sens) +
            (w_exp * ext_exposure) +
            (w_chain * chain_risk)
        )
        base_score = round((weighted_sum / scale_max) * 100.0, 2)

        # Determine default severity classification
        if base_score >= 70.0:
            classification = "HIGH"
        elif base_score >= 30.0:
            classification = "MEDIUM"
        else:
            classification = "LOW"

        # Critical Path Override Check (configurable in policy, independent of weighted score)
        override_cfg = self.policy.get("critical_path_override", {})
        is_override = False
        final_score = base_score
        explanation = (
            f"Path Risk Score: {base_score:.1f}/100 "
            f"(DataSens: {data_sens:.1f}, ActSens: {action_sens:.1f}, ExtExp: {ext_exposure:.1f}, ChainRisk: {chain_risk:.1f})"
        )

        if override_cfg.get("enabled", True):
            min_data_sens = float(override_cfg.get("min_data_sensitivity", 2.0))
            req_ext_action = override_cfg.get("require_external_action", True)
            req_ext_dest = override_cfg.get("require_external_destination", True)

            has_ext_action = any(
                self.graph.nodes[n].get("type") == "Action" and
                any(kw in self.graph.nodes[n].get("action_type", "") for kw in ("external", "send", "network", "communication"))
                for n in path_nodes
            )
            has_ext_dest = any(self.graph.nodes[n].get("type") == "External Destination" for n in path_nodes)

            matches_override = data_sens >= min_data_sens
            if req_ext_action:
                matches_override = matches_override and has_ext_action
            if req_ext_dest:
                matches_override = matches_override and has_ext_dest

            if matches_override:
                is_override = True
                classification = override_cfg.get("classification", "HIGH")
                override_score = float(override_cfg.get("override_score", 85.0))
                final_score = max(base_score, override_score)
                explanation = override_cfg.get(
                    "explanation",
                    "CRITICAL PATH OVERRIDE: Sensitive Data flows to External Action and Destination"
                ) + f" (Elevated to {final_score:.1f}, classification={classification})"

        path_id = generate_path_id(path_nodes)
        return PathScoringResult(
            path_nodes=path_nodes,
            path_edges=path_edges,
            data_sensitivity=data_sens,
            action_sensitivity=action_sens,
            external_exposure=ext_exposure,
            chain_risk=chain_risk,
            path_risk_score=final_score,
            classification=classification,
            is_critical_override=is_override,
            explanation=explanation,
            policy_version=self.policy_version,
            metadata={
                "base_score": base_score,
                "weighted_sum": round(weighted_sum, 3),
                "scale_max": scale_max,
                "path_id": path_id,
                "path_type": "PRECOMPUTED_POSSIBLE"
            },
            path_id=path_id
        )

    def _is_direct_path(self, path_nodes: List[str], tool_name: str) -> bool:
        """Determine whether a path represents a direct action of the specified tool."""
        act_nodes = [n for n in path_nodes if n.startswith("Action:")]
        if not act_nodes:
            return False
        act_node_id = act_nodes[0]
        act_tool = self.graph.nodes.get(act_node_id, {}).get("tool_name")
        if not act_tool:
            parts = act_node_id.split(":", 2)
            act_tool = parts[1] if len(parts) > 1 else ""
        if act_tool == tool_name:
            return True
        def clean(t: str) -> str:
            for pfx in ("postgres_mcp_", "postgres_", "git_", "fs_", "filesystem_", "rugpull-test_", "rugpull_test_", "email_server_", "email-server_"):
                if t.lower().startswith(pfx):
                    return t[len(pfx):]
            return t
        return clean(act_tool) == clean(tool_name)

    def evaluate_runtime_call(
        self,
        tool_name: str,
        call_history: Optional[List[str]] = None,
        arguments: Optional[Dict[str, Any]] = None
    ) -> PathScoringResult:
        """Map actual tool-call sequence against compatible graph paths.
        
        Evaluates actual runtime activity, not theoretical future attack paths.
        Direct paths are evaluated for isolated calls, while multi-step call histories
        correlate observed cross-tool data flows (e.g. read followed by external email).
        Uninvoked potential paths remain visible in the graph topology for threat modeling
        without triggering unwarranted pre-emptive blocks.
        """
        # 1. Normalize tool name
        matched_cap = self.tool_capabilities.get(tool_name)
        if not matched_cap and "_" in tool_name:
            suffix = tool_name.split("_", 1)[1]
            matched_cap = self.tool_capabilities.get(suffix)

        paths = self._computed_paths.get(tool_name) or []
        if not paths and matched_cap:
            paths = self._computed_paths.get(matched_cap.tool_name) or []

        canonical_name = matched_cap.tool_name if matched_cap else tool_name

        direct_paths: List[PathScoringResult] = []
        potential_cross_tool_paths: List[PathScoringResult] = []
        for p in paths:
            if self._is_direct_path(p.path_nodes, tool_name) or self._is_direct_path(p.path_nodes, canonical_name):
                direct_paths.append(p)
            else:
                potential_cross_tool_paths.append(p)

        data_access_cfg = self.policy.get("data_access_policy", {})

        # 2. Check call history for multi-step sequence mapping
        if call_history and len(call_history) > 1:
            matching_history_paths: List[PathScoringResult] = []
            for prev_tool in call_history[:-1]:
                prev_paths = self._computed_paths.get(prev_tool, [])
                if not prev_paths and "_" in prev_tool:
                    prev_suffix = prev_tool.split("_", 1)[1]
                    prev_paths = self._computed_paths.get(prev_suffix, [])
                for p in prev_paths:
                    # Check if this path involves the current tool's action
                    has_current_action = any(
                        f":{tool_name}:" in n
                        or f":{canonical_name}:" in n
                        for n in p.path_nodes
                    )
                    if not has_current_action:
                        continue

                    # Multi-step chains represent observed exfiltration or external transmission.
                    # Ordinary, authorized read-only operations (e.g. read_file, list_directory) must
                    # NOT be classified as attack chains merely because other tools were called previously.
                    is_external_or_exfil = (
                        p.is_critical_override
                        or p.external_exposure > 0
                        or any(self.graph.nodes.get(n, {}).get("type") == "External Destination" for n in p.path_nodes)
                        or any(ext_kw in n.lower() for n in p.path_nodes for ext_kw in (":external", ":send", ":upload", ":webhook", ":transmit", ":email"))
                    )
                    if is_external_or_exfil:
                        matching_history_paths.append(p)

            if matching_history_paths:
                # Check for authorized recipient in communication actions
                recipient_val = ""
                if isinstance(arguments, dict):
                    recipient_val = str(arguments.get("recipient") or arguments.get("to") or "")
                auth_recipients = data_access_cfg.get("authorized_email_recipients", [])
                is_authorized_recipient = any(domain in recipient_val for domain in auth_recipients) if (recipient_val and auth_recipients) else False

                matching_history_paths.sort(key=lambda p: p.path_risk_score, reverse=True)
                selected = matching_history_paths[0]

                if is_authorized_recipient:
                    # Authorized recipient: destination is internal/trusted
                    selected_score = min(selected.path_risk_score, 25.0)
                    selected_class = "LOW"
                    selection_reason = (
                        f"Multi-step sequence match: Correlated tool '{tool_name}' with call history {call_history[:-1]}. "
                        f"Recipient '{recipient_val}' is authorized under data-access policy (score={selected_score:.1f}, {selected_class})."
                    )
                    meta = dict(selected.metadata)
                    meta.update({
                        "runtime_path_id": selected.path_id,
                        "matched_path": True,
                        "match_status": "MATCHED",
                        "tool_name": tool_name,
                        "risk_score": selected_score,
                        "classification": selected_class,
                        "selection_reason": selection_reason,
                        "candidate_paths_count": len(matching_history_paths),
                        "candidate_path_ids": [p.path_id for p in matching_history_paths if p.path_id],
                        "path_type": "RUNTIME_MATCHED_SEQUENCE_AUTHORIZED",
                        "observed_chain": True,
                        "potential_attack_paths": [p.to_dict() for p in potential_cross_tool_paths],
                        "potential_paths_count": len(potential_cross_tool_paths)
                    })
                    return dc_replace(selected, path_risk_score=selected_score, classification=selected_class, is_critical_override=False, metadata=meta)

                selection_reason = (
                    f"Multi-step sequence match: Correlated tool '{tool_name}' with call history {call_history[:-1]}. "
                    f"Observed runtime chain from prior data access to external action selected '{selected.path_id}' "
                    f"(score={selected.path_risk_score:.1f}, {selected.classification})."
                )
                meta = dict(selected.metadata)
                meta.update({
                    "runtime_path_id": selected.path_id,
                    "matched_path": True,
                    "match_status": "MATCHED",
                    "tool_name": tool_name,
                    "risk_score": selected.path_risk_score,
                    "classification": selected.classification,
                    "selection_reason": selection_reason,
                    "candidate_paths_count": len(matching_history_paths),
                    "candidate_path_ids": [p.path_id for p in matching_history_paths if p.path_id],
                    "path_type": "RUNTIME_MATCHED_SEQUENCE",
                    "observed_chain": True,
                    "potential_attack_paths": [p.to_dict() for p in potential_cross_tool_paths],
                    "potential_paths_count": len(potential_cross_tool_paths)
                })
                return dc_replace(selected, metadata=meta)

        # 3. Direct execution evaluation for the current tool call
        # Check dynamic SQL context if tool is database query
        query_str = None
        if isinstance(arguments, dict):
            query_str = arguments.get("query") or arguments.get("sql")

        clean_tool = tool_name.lower()
        is_db_query_tool = any(kw in clean_tool for kw in ("postgres_mcp_query", "query", "sql_query"))
        if is_db_query_tool and query_str and isinstance(query_str, str):
            clean_q = query_str.strip()
            is_read_query = bool(re.match(r"(?i)^\s*(SELECT|EXPLAIN|SHOW|WITH)\b", clean_q))
            if is_read_query:
                restricted_pats = data_access_cfg.get("restricted_patterns", [
                    r"(?i)(password|secret|credential|auth_token|credit_card|private_key|api_key|ssn)"
                ])
                violates_policy = any(re.search(pat, clean_q) for pat in restricted_pats)
                if not violates_policy:
                    # Authorized read operation within configured data-access policy
                    authorized_sens = float(data_access_cfg.get("authorized_read_data_sensitivity", 1.0))
                    weights = self.policy.get("weights", {"data_sensitivity": 0.30, "action_sensitivity": 0.25, "external_exposure": 0.20, "chain_risk": 0.25})
                    scale_max = float(self.policy.get("scale_max", 3.0))
                    w_sum = (float(weights.get("data_sensitivity", 0.30)) * authorized_sens) + \
                            (float(weights.get("action_sensitivity", 0.25)) * 1.0) + \
                            (float(weights.get("external_exposure", 0.20)) * 0.0) + \
                            (float(weights.get("chain_risk", 0.25)) * 0.2)
                    read_score = round((w_sum / scale_max) * 100.0, 2)
                    classification = "LOW" if read_score < 30.0 else ("MEDIUM" if read_score < 70.0 else "HIGH")
                    nodes = ["Agent", f"Tool:{tool_name}", "Resource:database_records", f"Action:{tool_name}:query_database"]
                    path_id = generate_path_id(nodes)
                    selection_reason = (
                        f"Authorized read-only database query within configured data-access policy. "
                        f"Evaluated as read operation with sensitivity {authorized_sens:.1f} (score={read_score:.1f}, {classification}). "
                        f"{len(potential_cross_tool_paths)} potential uninvoked cross-tool paths preserved for graph topology."
                    )
                    return PathScoringResult(
                        path_nodes=nodes,
                        path_edges=["CAN_CALL", "READS", "FLOWS_TO"],
                        data_sensitivity=authorized_sens,
                        action_sensitivity=1.0,
                        external_exposure=0.0,
                        chain_risk=0.2,
                        path_risk_score=read_score,
                        classification=classification,
                        is_critical_override=False,
                        explanation=f"Authorized read-only query within configured data-access policy (Score: {read_score:.1f}, {classification})",
                        policy_version=self.policy_version,
                        metadata={
                            "runtime_path_id": path_id,
                            "matched_path": True,
                            "match_status": "MATCHED",
                            "tool_name": tool_name,
                            "risk_score": read_score,
                            "classification": classification,
                            "selection_reason": selection_reason,
                            "observed_chain": False,
                            "path_type": "RUNTIME_OBSERVED_DIRECT_READ",
                            "potential_attack_paths": [p.to_dict() for p in potential_cross_tool_paths],
                            "potential_paths_count": len(potential_cross_tool_paths)
                        },
                        path_id=path_id
                    )

        # Check dynamic filesystem context if tool is filesystem read
        fs_read_tools = {
            "read_file", "read_text_file", "read_media_file", "read_multiple_files",
            "list_directory", "list_directory_with_sizes", "directory_tree",
            "get_file_info", "search_files", "list_allowed_directories"
        }
        raw_fs_name = tool_name.lower()
        for pfx in ("filesystem_", "fs_"):
            if raw_fs_name.startswith(pfx):
                raw_fs_name = raw_fs_name[len(pfx):]
                break

        if raw_fs_name in fs_read_tools:
            raw_paths: List[str] = []
            if isinstance(arguments, dict):
                if "path" in arguments and isinstance(arguments["path"], str):
                    raw_paths.append(arguments["path"])
                elif "paths" in arguments and isinstance(arguments["paths"], list):
                    raw_paths.extend([str(p) for p in arguments["paths"]])
                elif "directory" in arguments and isinstance(arguments["directory"], str):
                    raw_paths.append(arguments["directory"])

            # Determine authorized directories from policy and settings
            auth_dirs: List[str] = list(data_access_cfg.get("authorized_directories", []))
            try:
                from mcpath.config.settings import settings
                cfg_allowed = getattr(settings, "filesystem_allowed_paths", "")
                if cfg_allowed:
                    for d in cfg_allowed.split(";" if ";" in cfg_allowed else ","):
                        d_clean = d.strip().replace("\\", "/").rstrip("/")
                        if d_clean and d_clean not in auth_dirs:
                            auth_dirs.append(d_clean)
            except Exception:
                pass

            restricted_pats = data_access_cfg.get("restricted_file_patterns", [
                r"(?i)(\.env|id_rsa|id_ed25519|passwd|shadow|credentials|secret|token|\.ssh|\.gnupg|password)"
            ])

            is_restricted = False
            is_unauthorized = False
            eval_reason = ""

            for p_str in raw_paths:
                p_norm = p_str.replace("\\", "/")
                # Check path traversal
                if "../" in p_norm or "/.." in p_norm or p_norm.startswith(".."):
                    is_unauthorized = True
                    eval_reason = f"Path traversal attempt outside authorized directories: '{p_str}'"
                    break

                # Check known sensitive operating system root paths
                if re.match(r"(?i)^([a-z]:/|/)(windows|system32|etc|var|root|boot|sys)", p_norm):
                    is_unauthorized = True
                    eval_reason = f"Attempted access to unauthorized system directory: '{p_str}'"
                    break

                # Check restricted/credential pattern
                if any(re.search(pat, p_norm) for pat in restricted_pats):
                    is_restricted = True
                    eval_reason = f"Access to restricted or credential file pattern in path: '{p_str}'"
                    break

                # If absolute path, verify it falls under an authorized directory
                if re.match(r"(?i)^([a-z]:/|/)", p_norm):
                    in_auth = any(
                        p_norm.lower().startswith(ad.lower().rstrip("/") + "/") or p_norm.lower() == ad.lower().rstrip("/")
                        for ad in auth_dirs
                    )
                    if not in_auth and auth_dirs:
                        is_unauthorized = True
                        eval_reason = f"Path '{p_str}' is outside authorized directories: {auth_dirs}"
                        break

            weights = self.policy.get("weights", {"data_sensitivity": 0.30, "action_sensitivity": 0.25, "external_exposure": 0.20, "chain_risk": 0.25})
            scale_max = float(self.policy.get("scale_max", 3.0))

            if is_unauthorized:
                # Unauthorized path / path traversal -> HIGH (BLOCK)
                data_sens = float(data_access_cfg.get("unauthorized_path_sensitivity", 3.0))
                action_sens = 2.0
                ext_exp = 1.0
                chain_risk = 2.0
                w_sum = (float(weights.get("data_sensitivity", 0.30)) * data_sens) + \
                        (float(weights.get("action_sensitivity", 0.25)) * action_sens) + \
                        (float(weights.get("external_exposure", 0.20)) * ext_exp) + \
                        (float(weights.get("chain_risk", 0.25)) * chain_risk)
                fs_score = min(100.0, round((w_sum / scale_max) * 100.0, 2))
                classification = "HIGH"
                nodes = ["Agent", f"Tool:{tool_name}", "Resource:unauthorized_filesystem_data", f"Action:{tool_name}:unauthorized_access"]
                path_id = generate_path_id(nodes)
                return PathScoringResult(
                    path_nodes=nodes,
                    path_edges=["CAN_CALL", "ACCESSES", "FLOWS_TO"],
                    data_sensitivity=data_sens,
                    action_sensitivity=action_sens,
                    external_exposure=ext_exp,
                    chain_risk=chain_risk,
                    path_risk_score=fs_score,
                    classification=classification,
                    is_critical_override=True,
                    explanation=f"POLICY BLOCK: Unauthorized directory or traversal attempt: {eval_reason} (Score: {fs_score:.1f}, {classification})",
                    policy_version=self.policy_version,
                    metadata={
                        "runtime_path_id": path_id,
                        "matched_path": True,
                        "match_status": "MATCHED",
                        "tool_name": tool_name,
                        "risk_score": fs_score,
                        "classification": classification,
                        "selection_reason": eval_reason,
                        "observed_chain": False,
                        "path_type": "RUNTIME_OBSERVED_UNAUTHORIZED_PATH",
                        "potential_attack_paths": [p.to_dict() for p in potential_cross_tool_paths],
                        "potential_paths_count": len(potential_cross_tool_paths)
                    },
                    path_id=path_id
                )

            elif is_restricted:
                # Restricted credential / secret file -> MEDIUM (HOLD)
                data_sens = float(data_access_cfg.get("restricted_data_sensitivity", 3.0))
                action_sens = 1.0
                ext_exp = 0.0
                chain_risk = 1.0
                w_sum = (float(weights.get("data_sensitivity", 0.30)) * data_sens) + \
                        (float(weights.get("action_sensitivity", 0.25)) * action_sens) + \
                        (float(weights.get("external_exposure", 0.20)) * ext_exp) + \
                        (float(weights.get("chain_risk", 0.25)) * chain_risk)
                fs_score = round((w_sum / scale_max) * 100.0, 2)
                classification = "MEDIUM"
                nodes = ["Agent", f"Tool:{tool_name}", "Resource:restricted_credentials", f"Action:{tool_name}:read_filesystem"]
                path_id = generate_path_id(nodes)
                return PathScoringResult(
                    path_nodes=nodes,
                    path_edges=["CAN_CALL", "READS", "FLOWS_TO"],
                    data_sensitivity=data_sens,
                    action_sensitivity=action_sens,
                    external_exposure=ext_exp,
                    chain_risk=chain_risk,
                    path_risk_score=fs_score,
                    classification=classification,
                    is_critical_override=False,
                    explanation=f"POLICY HOLD: Sensitive credential file read requires review: {eval_reason} (Score: {fs_score:.1f}, {classification})",
                    policy_version=self.policy_version,
                    metadata={
                        "runtime_path_id": path_id,
                        "matched_path": True,
                        "match_status": "MATCHED",
                        "tool_name": tool_name,
                        "risk_score": fs_score,
                        "classification": classification,
                        "selection_reason": eval_reason,
                        "observed_chain": False,
                        "path_type": "RUNTIME_OBSERVED_RESTRICTED_READ",
                        "potential_attack_paths": [p.to_dict() for p in potential_cross_tool_paths],
                        "potential_paths_count": len(potential_cross_tool_paths)
                    },
                    path_id=path_id
                )

            else:
                # Authorized benign read or directory listing -> LOW (ALLOW)
                is_dir_listing = raw_fs_name in {
                    "list_directory", "list_directory_with_sizes", "directory_tree",
                    "get_file_info", "list_allowed_directories"
                }
                if is_dir_listing:
                    data_sens = float(data_access_cfg.get("authorized_dir_list_sensitivity", 0.5))
                    action_sens = 0.5
                    chain_risk = 0.1
                else:
                    data_sens = float(data_access_cfg.get("authorized_read_file_sensitivity", 1.0))
                    action_sens = 1.0
                    chain_risk = 0.1

                ext_exp = 0.0
                w_sum = (float(weights.get("data_sensitivity", 0.30)) * data_sens) + \
                        (float(weights.get("action_sensitivity", 0.25)) * action_sens) + \
                        (float(weights.get("external_exposure", 0.20)) * ext_exp) + \
                        (float(weights.get("chain_risk", 0.25)) * chain_risk)
                fs_score = round((w_sum / scale_max) * 100.0, 2)
                classification = "LOW"
                action_name = "inspect_metadata" if is_dir_listing else "read_filesystem"
                nodes = ["Agent", f"Tool:{tool_name}", "Resource:filesystem_data", f"Action:{tool_name}:{action_name}"]
                path_id = generate_path_id(nodes)
                selection_reason = (
                    f"Authorized read-only filesystem operation within permitted directories. "
                    f"Evaluated with data sensitivity {data_sens:.1f} and action sensitivity {action_sens:.1f} "
                    f"(score={fs_score:.1f}, {classification}). "
                    f"{len(potential_cross_tool_paths)} potential uninvoked cross-tool paths preserved for graph topology."
                )
                return PathScoringResult(
                    path_nodes=nodes,
                    path_edges=["CAN_CALL", "READS", "FLOWS_TO"],
                    data_sensitivity=data_sens,
                    action_sensitivity=action_sens,
                    external_exposure=ext_exp,
                    chain_risk=chain_risk,
                    path_risk_score=fs_score,
                    classification=classification,
                    is_critical_override=False,
                    explanation=f"Authorized read within permitted directory (Score: {fs_score:.1f}, {classification})",
                    policy_version=self.policy_version,
                    metadata={
                        "runtime_path_id": path_id,
                        "matched_path": True,
                        "match_status": "MATCHED",
                        "tool_name": tool_name,
                        "risk_score": fs_score,
                        "classification": classification,
                        "selection_reason": selection_reason,
                        "observed_chain": False,
                        "path_type": "RUNTIME_OBSERVED_DIRECT_READ",
                        "potential_attack_paths": [p.to_dict() for p in potential_cross_tool_paths],
                        "potential_paths_count": len(potential_cross_tool_paths)
                    },
                    path_id=path_id
                )

        # Evaluate against direct paths
        if direct_paths:
            sorted_direct = sorted(direct_paths, key=lambda p: p.path_risk_score, reverse=True)
            selected = sorted_direct[0]
            selection_reason = (
                f"Direct capability path '{selected.path_id}' matched for tool '{tool_name}' "
                f"(score={selected.path_risk_score:.1f}, {selected.classification}). "
                f"{len(potential_cross_tool_paths)} potential uninvoked cross-tool paths preserved for graph topology."
            )
            meta = dict(selected.metadata)
            meta.update({
                "runtime_path_id": selected.path_id,
                "matched_path": True,
                "match_status": "MATCHED",
                "tool_name": tool_name,
                "risk_score": selected.path_risk_score,
                "classification": selected.classification,
                "selection_reason": selection_reason,
                "candidate_paths_count": len(sorted_direct),
                "candidate_path_ids": [p.path_id for p in sorted_direct if p.path_id],
                "path_type": "RUNTIME_MATCHED_DIRECT",
                "observed_chain": False,
                "potential_attack_paths": [p.to_dict() for p in potential_cross_tool_paths],
                "potential_paths_count": len(potential_cross_tool_paths)
            })
            return dc_replace(selected, metadata=meta)

        # Fallback if only cross-tool paths were enumerated but no direct action sink was modeled
        if paths:
            matched = matched_cap or self.tool_capabilities.get(tool_name)
            if matched:
                nodes = ["Agent", f"Tool:{tool_name}", f"Resource:{matched.data_target}", f"Action:{tool_name}:{matched.action_type}"]
                if matched.external_destination:
                    nodes.append(f"Destination:{matched.external_destination}")
                direct_score = self.score_path(nodes)
                meta = dict(direct_score.metadata)
                meta.update({
                    "runtime_path_id": direct_score.path_id,
                    "matched_path": True,
                    "match_status": "MATCHED",
                    "tool_name": tool_name,
                    "risk_score": direct_score.path_risk_score,
                    "classification": direct_score.classification,
                    "selection_reason": f"Evaluated direct action for tool '{tool_name}' (score={direct_score.path_risk_score:.1f}).",
                    "observed_chain": False,
                    "path_type": "RUNTIME_MATCHED_DIRECT_SYNTHESIZED",
                    "potential_attack_paths": [p.to_dict() for p in paths],
                    "potential_paths_count": len(paths)
                })
                return dc_replace(direct_score, metadata=meta)

        # 4. Unknown / unmodeled path fallback (configurable in policy, never treated as safe)
        unknown_cfg = self.policy.get("unknown_path_handling", {
            "score": 75.0,
            "classification": "HIGH",
            "explanation": "CAPABILITY PATH: UNKNOWN / UNMODELED"
        })
        elevated_score = float(unknown_cfg.get("score", 75.0))
        classification = unknown_cfg.get("classification", "HIGH")
        explanation = unknown_cfg.get("explanation", "CAPABILITY PATH: UNKNOWN / UNMODELED")

        is_tool_known = matched_cap is not None or tool_name in self.tool_capabilities
        if is_tool_known:
            match_status = "UNMODELED"
            detail_expl = f"{explanation} (UNMODELED): Tool '{tool_name}' is registered but has no compatible causal path modeled in the graph"
            selection_reason = f"Tool '{tool_name}' is registered in server catalog, but no compatible graph path to a sink was enumerated. Fail-secure elevated score applied."
        else:
            match_status = "UNKNOWN"
            detail_expl = f"{explanation} (UNKNOWN): Tool '{tool_name}' is not recognized in the capability graph"
            selection_reason = f"Tool '{tool_name}' is completely unknown/unregistered in the capability graph. Fail-secure elevated score applied."

        return PathScoringResult(
            path_nodes=["Agent", f"Tool:{tool_name}", "Unknown/Unmodeled"],
            path_edges=["CAN_CALL", "UNKNOWN_RELATION"],
            data_sensitivity=3.0,
            action_sensitivity=3.0,
            external_exposure=3.0,
            chain_risk=3.0,
            path_risk_score=elevated_score,
            classification=classification,
            is_critical_override=False,
            explanation=f"{detail_expl} (Score: {elevated_score:.1f})",
            policy_version=self.policy_version,
            metadata={
                "status": match_status,
                "tool_name": tool_name,
                "runtime_path_id": None,
                "matched_path": False,
                "match_status": match_status,
                "risk_score": elevated_score,
                "classification": classification,
                "selection_reason": selection_reason,
                "path_type": "RUNTIME_OBSERVED_UNMODELED"
            },
            path_id=None
        )

    def get_paths_for_tool(self, tool_name: str) -> List[PathScoringResult]:
        """Return all compatible paths enumerated for a specific tool."""
        return self._computed_paths.get(tool_name, [])

    def export_graph(self) -> Dict[str, Any]:
        """Serialize nodes, typed edges, and compatible paths for API, DB, and UI."""
        nodes = [
            {"id": n, **d}
            for n, d in self.graph.nodes(data=True)
        ]
        edges = [
            {"source": u, "target": v, **d}
            for u, v, d in self.graph.edges(data=True)
        ]
        all_paths: List[Dict[str, Any]] = []
        for tool_name, paths in self._computed_paths.items():
            for p in paths:
                all_paths.append(p.to_dict())

        return {
            "policy_version": self.policy_version,
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "total_paths": len(all_paths),
            "nodes": nodes,
            "edges": edges,
            "paths": all_paths
        }
