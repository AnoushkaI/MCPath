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
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import networkx as nx

from mcpath.graph.capability_inference import CapabilityClassifier, ToolCapability

logger = logging.getLogger("mcpath.graph.capability_graph")


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

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


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
                "scale_max": scale_max
            }
        )

    def evaluate_runtime_call(
        self,
        tool_name: str,
        call_history: Optional[List[str]] = None
    ) -> PathScoringResult:
        """Map actual tool-call sequence against compatible graph paths.
        
        If known -> score the matched path.
        If no compatible path -> report 'CAPABILITY PATH: UNKNOWN / UNMODELED' and produce elevated result.
        """
        # 1. Normalize tool name
        matched_cap = self.tool_capabilities.get(tool_name)
        if not matched_cap and "_" in tool_name:
            suffix = tool_name.split("_", 1)[1]
            matched_cap = self.tool_capabilities.get(suffix)

        paths = self._computed_paths.get(tool_name) or []
        if not paths and matched_cap:
            paths = self._computed_paths.get(matched_cap.tool_name) or []

        # 2. Check call history for multi-step sequence mapping
        if call_history and len(call_history) > 1:
            matching_history_paths: List[PathScoringResult] = []
            for prev_tool in call_history[:-1]:
                prev_paths = self._computed_paths.get(prev_tool, [])
                for p in prev_paths:
                    # Check if this path involves the current tool's action
                    if any(f":{tool_name}:" in n for n in p.path_nodes):
                        matching_history_paths.append(p)
            if matching_history_paths:
                matching_history_paths.sort(key=lambda p: p.path_risk_score, reverse=True)
                return matching_history_paths[0]

        # 3. If paths exist for this single tool, return the highest-risk compatible path
        if paths:
            # Sort by risk score descending
            sorted_paths = sorted(paths, key=lambda p: p.path_risk_score, reverse=True)
            return sorted_paths[0]

        # 4. Unknown / unmodeled path fallback (configurable in policy, never treated as safe)
        unknown_cfg = self.policy.get("unknown_path_handling", {
            "score": 75.0,
            "classification": "HIGH",
            "explanation": "CAPABILITY PATH: UNKNOWN / UNMODELED"
        })
        elevated_score = float(unknown_cfg.get("score", 75.0))
        classification = unknown_cfg.get("classification", "HIGH")
        explanation = unknown_cfg.get("explanation", "CAPABILITY PATH: UNKNOWN / UNMODELED")

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
            explanation=f"{explanation}: Tool '{tool_name}' has no compatible path modeled in the capability graph",
            policy_version=self.policy_version,
            metadata={"status": "UNKNOWN_PATH", "tool_name": tool_name}
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
