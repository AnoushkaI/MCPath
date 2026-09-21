"""FastAPI route: MCP Server Inventory and Configuration Switching.

Supports:
- Inspecting active and available MCP servers
- Hot-switching active downstream MCP server configuration (Section 15.5)
"""

from typing import Any, Dict, List
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from mcpath.config.settings import settings

router = APIRouter(prefix="/api/servers", tags=["Servers"])


class SwitchServerRequest(BaseModel):
    server_name: str


@router.get("")
async def get_servers_info():
    """Return configured downstream MCP servers and active selection."""
    config = settings.get_server_config()
    return {
        "active_server": config.active_server,
        "servers": {k: v.model_dump() for k, v in config.servers.items()}
    }


@router.post("/switch")
async def switch_server(req: SwitchServerRequest):
    """Switch active downstream server configuration without pipeline changes."""
    config = settings.get_server_config()
    if req.server_name not in config.servers:
        raise HTTPException(
            status_code=404,
            detail=f"Server '{req.server_name}' not found. Available: {list(config.servers.keys())}"
        )
    # [TODO Day 12-13: Update runtime active server and trigger capability graph rebuild]
    return {"status": "success", "active_server": req.server_name}
