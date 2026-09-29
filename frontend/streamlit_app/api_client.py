"""MCPath Streamlit API Client.

CRITICAL ARCHITECTURAL BOUNDARY:
This client strictly communicates with the FastAPI backend over localhost HTTP.
It does NOT import or manipulate proxy Python objects, internal databases, or stdio streams.
Observability and administrative control only.
"""

from datetime import datetime
import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple
import requests

logger = logging.getLogger("mcpath.frontend.api_client")

DEFAULT_BACKEND_URL = os.getenv("MCPATH_BACKEND_URL", "http://127.0.0.1:8000")
TIMEOUT_SECONDS = 5.0


class MCPathAPIClient:
    """HTTP Client connecting to the MCPath FastAPI backend."""

    def __init__(self, base_url: Optional[str] = None):
        self.base_url = (base_url or DEFAULT_BACKEND_URL).rstrip("/")

    # -------------------------------------------------------------------------
    # Health & System
    # -------------------------------------------------------------------------

    def check_health(self) -> Dict[str, Any]:
        """Check if FastAPI backend is healthy and reachable."""
        try:
            resp = requests.get(f"{self.base_url}/health", timeout=TIMEOUT_SECONDS)
            if resp.status_code == 200:
                return {"online": True, "data": resp.json()}
            return {"online": False, "error": f"HTTP {resp.status_code}: {resp.text}"}
        except Exception as e:
            return {"online": False, "error": str(e)}

    # -------------------------------------------------------------------------
    # Security Overview
    # -------------------------------------------------------------------------

    def get_overview(self) -> Dict[str, Any]:
        """Fetch aggregated security metrics from /api/overview."""
        try:
            resp = requests.get(f"{self.base_url}/api/overview", timeout=TIMEOUT_SECONDS)
            if resp.status_code == 200:
                return resp.json()
            logger.warning("GET /api/overview failed: %s", resp.status_code)
            return {}
        except Exception as e:
            logger.error("Error connecting to /api/overview: %s", e)
            return {}

    # -------------------------------------------------------------------------
    # Security Events & Runtime Logs
    # -------------------------------------------------------------------------

    def get_events(
        self,
        limit: int = 50,
        server: Optional[str] = None,
        decision: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Fetch recent security events with optional filtering."""
        params: Dict[str, Any] = {"limit": limit}
        if server and server != "All":
            params["server"] = server
        if decision and decision != "All":
            params["decision"] = decision

        try:
            resp = requests.get(f"{self.base_url}/api/events", params=params, timeout=TIMEOUT_SECONDS)
            if resp.status_code == 200:
                return resp.json()
            return []
        except Exception as e:
            logger.error("Error fetching /api/events: %s", e)
            return []

    def get_event_detail(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Fetch full details for a single security event including stage results and intent eval."""
        try:
            resp = requests.get(f"{self.base_url}/api/events/{event_id}", timeout=TIMEOUT_SECONDS)
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as e:
            logger.error("Error fetching /api/events/%s: %s", event_id, e)
            return None

    def get_stage_results(
        self,
        event_id: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Fetch per-stage pipeline execution results."""
        params: Dict[str, Any] = {"limit": limit}
        if event_id:
            params["event_id"] = event_id

        try:
            resp = requests.get(f"{self.base_url}/api/stage-results", params=params, timeout=TIMEOUT_SECONDS)
            if resp.status_code == 200:
                return resp.json()
            return []
        except Exception as e:
            logger.error("Error fetching /api/stage-results: %s", e)
            return []

    # -------------------------------------------------------------------------
    # Capability Graph & Paths (Stage 2)
    # -------------------------------------------------------------------------

    def get_capability_graph(self) -> Dict[str, Any]:
        """Fetch dynamic capability graph nodes and edges."""
        try:
            resp = requests.get(f"{self.base_url}/api/capabilities/graph", timeout=TIMEOUT_SECONDS)
            if resp.status_code == 200:
                return resp.json()
            return {"nodes": [], "edges": [], "total_nodes": 0, "total_edges": 0}
        except Exception as e:
            logger.error("Error fetching /api/capabilities/graph: %s", e)
            return {"nodes": [], "edges": [], "total_nodes": 0, "total_edges": 0}

    def get_capability_paths(
        self,
        tool_name: Optional[str] = None,
        path_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Fetch enumerated compatible paths with risk scores, classifications, and unique path IDs."""
        params: Dict[str, Any] = {}
        if tool_name and tool_name != "All":
            params["tool_name"] = tool_name
        if path_id:
            params["path_id"] = path_id

        try:
            resp = requests.get(f"{self.base_url}/api/capabilities/paths", params=params, timeout=TIMEOUT_SECONDS)
            if resp.status_code == 200:
                return resp.json()
            return []
        except Exception as e:
            logger.error("Error fetching /api/capabilities/paths: %s", e)
            return []

    def get_tool_capabilities(self) -> List[Dict[str, Any]]:
        """Fetch classified tool capabilities metadata."""
        try:
            resp = requests.get(f"{self.base_url}/api/capabilities/tools", timeout=TIMEOUT_SECONDS)
            if resp.status_code == 200:
                return resp.json()
            return []
        except Exception as e:
            logger.error("Error fetching /api/capabilities/tools: %s", e)
            return []

    def get_capability_policy(self) -> Dict[str, Any]:
        """Fetch active capability policy version and inference weights."""
        try:
            resp = requests.get(f"{self.base_url}/api/capabilities/policy", timeout=TIMEOUT_SECONDS)
            if resp.status_code == 200:
                return resp.json()
            return {}
        except Exception as e:
            logger.error("Error fetching /api/capabilities/policy: %s", e)
            return {}

    # -------------------------------------------------------------------------
    # MCP Server Lifecycle & Inventory
    # -------------------------------------------------------------------------

    def get_servers(self, format: Optional[str] = None) -> Any:
        """Fetch inventory of downstream MCP servers."""
        params = {}
        if format:
            params["format"] = format
        try:
            resp = requests.get(f"{self.base_url}/api/servers", params=params, timeout=TIMEOUT_SECONDS)
            if resp.status_code == 200:
                return resp.json()
            return [] if not format else {}
        except Exception as e:
            logger.error("Error fetching /api/servers: %s", e)
            return [] if not format else {}

    def get_server_detail(self, server_name: str) -> Optional[Dict[str, Any]]:
        """Fetch status and tool metrics for a single server."""
        try:
            resp = requests.get(f"{self.base_url}/api/servers/{server_name}", timeout=TIMEOUT_SECONDS)
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as e:
            logger.error("Error fetching /api/servers/%s: %s", server_name, e)
            return None

    def get_server_tools(self, server_name: str) -> List[Dict[str, Any]]:
        """Fetch discovered tool definitions for a specific server."""
        try:
            resp = requests.get(f"{self.base_url}/api/servers/{server_name}/tools", timeout=TIMEOUT_SECONDS)
            if resp.status_code == 200:
                return resp.json()
            return []
        except Exception as e:
            logger.error("Error fetching /api/servers/%s/tools: %s", server_name, e)
            return []

    def add_server(
        self,
        name: str,
        command: str,
        args: Optional[List[str]] = None,
        env: Optional[Dict[str, str]] = None,
        transport: str = "stdio"
    ) -> Tuple[bool, Any]:
        """Add and discover a new MCP server (Security Model: ADDING != TRUSTING).

        Newly added servers are UNTRUSTED with NO_APPROVED_BASELINE.
        """
        payload = {
            "name": name.strip(),
            "command": command.strip(),
            "args": args or [],
            "env": env or {},
            "transport": transport
        }
        try:
            resp = requests.post(f"{self.base_url}/api/servers/add", json=payload, timeout=10.0)
            if resp.status_code in (200, 201):
                return True, resp.json()
            return False, resp.json().get("detail", resp.text)
        except Exception as e:
            return False, str(e)

    def activate_server(self, server_name: str) -> Tuple[bool, Any]:
        """Activate an existing server (reconnect, rediscover tools, does NOT create baseline)."""
        try:
            resp = requests.post(f"{self.base_url}/api/servers/{server_name}/activate", timeout=10.0)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", resp.text)
        except Exception as e:
            return False, str(e)

    def deactivate_server(self, server_name: str) -> Tuple[bool, Any]:
        """Deactivate an MCP server (disconnect session, remove from catalog, preserve history)."""
        try:
            resp = requests.post(f"{self.base_url}/api/servers/{server_name}/deactivate", timeout=10.0)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", resp.text)
        except Exception as e:
            return False, str(e)

    def trust_server(self, server_name: str) -> Tuple[bool, Any]:
        """Explicitly Trust & Register server tools, creating the approved Stage 1 SHA-256 baseline."""
        try:
            resp = requests.post(f"{self.base_url}/api/servers/{server_name}/trust", timeout=10.0)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", resp.text)
        except Exception as e:
            return False, str(e)

    def reload_servers(self) -> Tuple[bool, Any]:
        """Dynamically reload MCP server configurations and synchronize database."""
        try:
            resp = requests.post(f"{self.base_url}/api/servers/reload", timeout=10.0)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", resp.text)
        except Exception as e:
            return False, str(e)

    # -------------------------------------------------------------------------
    # Tool / Baseline Inspector (Stage 1)
    # -------------------------------------------------------------------------

    def get_tool_baseline_inspector(self, server_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Fetch all discovered tools with current vs approved hashes, match status, and trust state."""
        params = {}
        if server_name and server_name != "All":
            params["server_name"] = server_name
        try:
            resp = requests.get(f"{self.base_url}/api/hashes/inspector", params=params, timeout=TIMEOUT_SECONDS)
            if resp.status_code == 200:
                return resp.json()
            return []
        except Exception as e:
            logger.error("Error fetching /api/hashes/inspector: %s", e)
            return []

    def get_approved_hashes(
        self,
        server_name: Optional[str] = None,
        tool_name: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Fetch approved tool hashes from PostgreSQL."""
        params = {}
        if server_name and server_name != "All":
            params["server_name"] = server_name
        if tool_name and tool_name != "All":
            params["tool_name"] = tool_name
        try:
            resp = requests.get(f"{self.base_url}/api/hashes", params=params, timeout=TIMEOUT_SECONDS)
            if resp.status_code == 200:
                return resp.json()
            return []
        except Exception as e:
            logger.error("Error fetching /api/hashes: %s", e)
            return []

    def approve_tool_hash(
        self,
        server_name: str,
        tool_name: str,
        tool_definition: Dict[str, Any],
        approved_by: str = "soc_analyst"
    ) -> Tuple[bool, Any]:
        """Approve a tool definition manually creating a new approved SHA-256 baseline."""
        payload = {
            "server_name": server_name,
            "tool_name": tool_name,
            "tool_definition": tool_definition,
            "approved_by": approved_by
        }
        try:
            resp = requests.post(f"{self.base_url}/api/hashes/approve", json=payload, timeout=TIMEOUT_SECONDS)
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", resp.text)
        except Exception as e:
            return False, str(e)

    # -------------------------------------------------------------------------
    # Administrator Approval Queue
    # -------------------------------------------------------------------------

    def get_approvals(self, status: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch approvals from /api/approvals."""
        params = {"limit": limit}
        if status and status != "All":
            params["status"] = status
        try:
            resp = requests.get(f"{self.base_url}/api/approvals", params=params, timeout=TIMEOUT_SECONDS)
            if resp.status_code == 200:
                return resp.json()
            return []
        except Exception as e:
            logger.error("Error fetching approvals: %s", e)
            return []

    def get_pending_approvals(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch pending approvals."""
        return self.get_approvals(status="PENDING", limit=limit)

    def approve_call(self, approval_id: str, resolver: str = "admin") -> Tuple[bool, Any]:
        """Approve a held tool invocation."""
        try:
            resp = requests.post(
                f"{self.base_url}/api/approvals/{approval_id}/approve",
                params={"resolver": resolver},
                timeout=TIMEOUT_SECONDS
            )
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", resp.text)
        except Exception as e:
            return False, str(e)

    def reject_call(self, approval_id: str, resolver: str = "admin") -> Tuple[bool, Any]:
        """Reject a held tool invocation."""
        try:
            resp = requests.post(
                f"{self.base_url}/api/approvals/{approval_id}/reject",
                params={"resolver": resolver},
                timeout=TIMEOUT_SECONDS
            )
            if resp.status_code == 200:
                return True, resp.json()
            return False, resp.json().get("detail", resp.text)
        except Exception as e:
            return False, str(e)


# Default singleton instance
client = MCPathAPIClient()

