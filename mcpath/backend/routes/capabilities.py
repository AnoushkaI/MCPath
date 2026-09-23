"""FastAPI route: Capability Graph, Paths, and Policy Observability.

CRITICAL ARCHITECTURAL BOUNDARY:
This router is strictly in the read-only observability path.
Provides inspectability for graph nodes, typed edges, compatible paths,
scores, severity, and the active versioned policy.
"""

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from mcpath.backend.persistence.database import (
    get_db,
    get_persisted_capability_graph,
    get_persisted_capability_paths,
)
from mcpath.proxy.client_manager import get_active_client_manager
from mcpath.graph.capability_inference import CapabilityClassifier

logger = logging.getLogger("mcpath.backend.capabilities")

router = APIRouter(prefix="/api/capabilities", tags=["Capabilities"])


@router.get("/policy")
async def get_capability_policy():
    """Return the active versioned capability policy."""
    mgr = get_active_client_manager()
    if mgr and hasattr(mgr, "capability_graph") and mgr.capability_graph:
        return mgr.capability_graph.policy
    classifier = CapabilityClassifier()
    return classifier.policy


@router.get("/graph")
async def get_capability_graph(db: AsyncSession = Depends(get_db)):
    """Return dynamic capability graph nodes and typed edges."""
    mgr = get_active_client_manager()
    if mgr and hasattr(mgr, "capability_graph") and mgr.capability_graph:
        exported = mgr.capability_graph.export_graph()
        return {
            "policy_version": exported.get("policy_version", "1.0.0"),
            "total_nodes": exported.get("total_nodes", 0),
            "total_edges": exported.get("total_edges", 0),
            "nodes": exported.get("nodes", []),
            "edges": exported.get("edges", [])
        }

    # Fallback to database
    persisted = await get_persisted_capability_graph(session=db)
    return {
        "policy_version": "1.0.0",
        "total_nodes": len(persisted.get("nodes", [])),
        "total_edges": len(persisted.get("edges", [])),
        "nodes": persisted.get("nodes", []),
        "edges": persisted.get("edges", [])
    }


@router.get("/paths")
async def get_capability_paths(
    tool_name: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """Return compatible capability paths with scores, attributes, and severity."""
    mgr = get_active_client_manager()
    if mgr and hasattr(mgr, "capability_graph") and mgr.capability_graph:
        if tool_name:
            paths = [p.to_dict() for p in mgr.capability_graph.get_paths_for_tool(tool_name)]
        else:
            exported = mgr.capability_graph.export_graph()
            paths = exported.get("paths", [])
        return paths

    # Fallback to database
    persisted_paths = await get_persisted_capability_paths(tool_name=tool_name, session=db)
    return persisted_paths


@router.get("/tools")
async def list_tool_capabilities():
    """List deterministically classified tool capabilities."""
    mgr = get_active_client_manager()
    if mgr and hasattr(mgr, "capability_graph") and mgr.capability_graph:
        return [
            {
                "tool_name": cap.tool_name,
                "server_name": cap.server_name,
                "data_target": cap.data_target,
                "operation": cap.operation,
                "action_type": cap.action_type,
                "data_sensitivity": cap.data_sensitivity,
                "action_sensitivity": cap.action_sensitivity,
                "external_exposure": cap.external_exposure,
                "external_destination": cap.external_destination,
                "consumed_data_types": cap.consumed_data_types,
                "policy_version": cap.policy_version
            }
            for cap in mgr.capability_graph.tool_capabilities.values()
        ]
    return []
