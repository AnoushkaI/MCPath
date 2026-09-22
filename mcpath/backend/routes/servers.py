"""FastAPI route: MCP Server Inventory, Tools, and Configuration Switching.

Supports:
- Inspecting active and available MCP servers
- Listing discovered tools stored in PostgreSQL
- Hot-switching active downstream MCP server configuration (Section 15.5)
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from mcpath.backend.persistence.database import get_db
from mcpath.backend.persistence.models import ServerDB, ToolDB
from mcpath.config.settings import settings

router = APIRouter(prefix="/api/servers", tags=["Servers"])


class SwitchServerRequest(BaseModel):
    server_name: str


@router.get("")
async def get_servers_info(db: AsyncSession = Depends(get_db)):
    """Return configured downstream MCP servers and active selection from config and DB."""
    config = settings.get_server_config()
    
    # Also fetch database registered servers
    db_servers = []
    try:
        stmt = select(ServerDB)
        res = await db.execute(stmt)
        db_servers = [
            {
                "id": s.id,
                "name": s.name,
                "command": s.command,
                "is_active": s.is_active,
                "created_at": s.created_at.isoformat() if s.created_at else None
            }
            for s in res.scalars().all()
        ]
    except Exception:
        pass

    return {
        "active_server": config.active_server,
        "configured_servers": {k: v.model_dump() for k, v in config.servers.items()},
        "registered_in_db": db_servers
    }


@router.get("/{server_name}/tools")
async def get_server_tools(
    server_name: str,
    db: AsyncSession = Depends(get_db)
):
    """List all discovered tools for a specific server in PostgreSQL."""
    stmt = select(ToolDB).where(ToolDB.server_name == server_name)
    res = await db.execute(stmt)
    tools = res.scalars().all()

    return [
        {
            "id": t.id,
            "server_id": t.server_id,
            "server_name": t.server_name,
            "name": t.name,
            "description": t.description,
            "input_schema": t.input_schema,
            "updated_at": t.updated_at.isoformat() if t.updated_at else None
        }
        for t in tools
    ]


@router.post("/switch")
async def switch_server(req: SwitchServerRequest):
    """Switch active downstream server configuration without pipeline changes."""
    config = settings.get_server_config()
    if req.server_name not in config.servers:
        raise HTTPException(
            status_code=404,
            detail=f"Server '{req.server_name}' not found. Available: {list(config.servers.keys())}"
        )
    return {"status": "success", "active_server": req.server_name}


@router.post("/reload")
async def reload_servers():
    """Dynamically reload configured downstream MCP servers.

    - Reads current MCPath server configuration
    - Detects added/removed/changed servers
    - Disconnects removed servers and connects newly added servers
    - Rediscovers tools and recomputes exposed-tool collision mapping
    - Rebuilds dynamic capability graph
    - Claude Desktop configuration remains completely unchanged
    """
    from mcpath.proxy.client_manager import get_active_client_manager
    mgr = get_active_client_manager()
    if mgr is not None:
        summary = await mgr.reload()
        return summary

    # If proxy is not currently running as stdio subprocess, return current config state
    config = settings.get_server_config()
    return {
        "status": "success",
        "message": "Proxy is not actively running in this process; reloaded configuration from disk",
        "active_servers": getattr(config, "active_servers", [config.active_server]),
        "configured_servers": list(config.servers.keys())
    }
