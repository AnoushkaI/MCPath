"""Capability Graph representation using NetworkX.

Nodes:
- Agent
- Tool
- Data/Resource
- Action
- External Destination

Edges:
- CAN_CALL
- READS
- WRITES
- FLOWS_TO
- SENDS_TO

Represents possible capability or attack paths across connected MCP servers.
"""

from typing import Dict, List, Optional, Set
import networkx as nx


class CapabilityGraph:
    """Dynamic causal capability graph for connected MCP tools."""

    def __init__(self):
        self.graph = nx.DiGraph()
        self.graph.add_node("Agent", type="Agent")

    def rebuild_from_tools(self, server_name: str, tools: List[Dict]):
        """Rebuild capability graph dynamically from discovered tools.

        [TODO Day 5-6: Dynamic node and edge extraction from discovered tool schemas]
        """
        for tool in tools:
            name = tool.get("name", "")
            self.graph.add_node(name, type="Tool", server=server_name)
            self.graph.add_edge("Agent", name, relation="CAN_CALL")

    def rebuild_for_all_servers(self, server_tools: Dict[str, List[Dict]]):
        """Rebuild capability graph dynamically representing all currently configured servers."""
        self.graph.clear()
        self.graph.add_node("Agent", type="Agent")
        for server_name, tools in server_tools.items():
            self.rebuild_from_tools(server_name, tools)

    def remove_server(self, server_name: str):
        """Remove all tools associated with a disconnected or removed server."""
        nodes_to_remove = [
            n for n, data in self.graph.nodes(data=True)
            if data.get("server") == server_name
        ]
        self.graph.remove_nodes_from(nodes_to_remove)

    def get_paths_to_external(self, start_tool: str) -> List[List[str]]:
        """Find all causal paths from start_tool leading to an External Destination."""
        # Day 1 placeholder
        return []

    def calculate_path_risk(self, path: List[str]) -> float:
        """Compute path risk score based on sensitivity, exposure, and chain length."""
        # Day 1 placeholder
        return 0.0
