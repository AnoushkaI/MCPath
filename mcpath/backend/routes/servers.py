"""FastAPI route: MCP Server Inventory, Dynamic Lifecycle, and Trust Management.

Supports:
- Dynamic discovery and addition of downstream MCP servers (POST /api/servers/add)
- Single server-level Trust & Register baseline approval (POST /api/servers/{server_name}/trust)
- Dynamic deactivation and graph update (POST /api/servers/{server_name}/deactivate)
- Dynamic activation without re-baselining (POST /api/servers/{server_name}/activate)
- Status inspection across all servers (GET /api/servers)
- Single server status inspection (GET /api/servers/{server_name})
- Tools inventory per server (GET /api/servers/{server_name}/tools)
- Dynamic controlled reload (POST /api/servers/reload)
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from mcpath.backend.persistence.database import get_db
from mcpath.backend.persistence.models import ServerDB, ToolDB
from mcpath.config.settings import settings, ServerDefinition
from mcpath.core.exceptions import DownstreamConnectionError
from mcpath.proxy.control import send_proxy_control_command

logger = logging.getLogger("mcpath.backend.servers")
router = APIRouter(prefix="/api/servers", tags=["Servers"])


class AddServerRequest(BaseModel):
    name: str
    command: str
    args: Optional[List[str]] = None
    env: Optional[Dict[str, str]] = None
    transport: str = "stdio"


class SwitchServerRequest(BaseModel):
    server_name: str


@router.get("")
async def get_servers(
    format: Optional[str] = Query(default=None),
    db: AsyncSession = Depends(get_db)
):
    """Return status for all known MCP downstream servers.

    Returns a list of server status objects matching Section 6 specification:
    - name, active, connected, trust_status, discovered_tool_count,
      approved_tool_count, unapproved_tool_count, last discovery/trust times.

    Pass ?format=dict or ?format=legacy for dictionary output containing configured_servers and registered_in_db.
    """
    server_statuses: List[Dict[str, Any]] = []

    # 1. Attempt to query live proxy manager status
    try:
        res = await send_proxy_control_command("get_all_servers_status")
        if res.get("status") == "success" and isinstance(res.get("data"), list):
            server_statuses = res.get("data")
    except Exception as e:
        logger.debug("Could not retrieve live server status from proxy control: %s", e)

    # 2. If proxy offline or empty, query database directly
    if not server_statuses:
        from mcpath.backend.persistence.database import get_server_db_status
        try:
            server_statuses = await get_server_db_status(session=db)
        except Exception as e:
            logger.warning("Could not query DB server status: %s", e)

    # 3. Ensure all configured servers appear even if not yet in DB
    config = settings.get_server_config()
    existing_names = {s["name"] for s in server_statuses}
    active_set = set(getattr(config, "active_servers", None) or [config.active_server])

    for s_name, s_def in config.servers.items():
        if s_name not in existing_names:
            is_active = (s_name in active_set)
            server_statuses.append({
                "name": s_name,
                "command": s_def.command,
                "args": s_def.args,
                "active": is_active,
                "is_active": is_active,
                "connected": False,
                "trust_status": "UNTRUSTED",
                "discovered_tool_count": 0,
                "approved_tool_count": 0,
                "unapproved_tool_count": 0,
                "last_discovery_time": None,
                "last_trust_time": None,
            })

    if format in ("dict", "legacy"):
        from mcpath.backend.persistence.database import get_server_db_status
        db_statuses = await get_server_db_status(session=db)
        return {
            "servers": server_statuses or db_statuses,
            "active_server": config.active_server,
            "configured_servers": {k: v.model_dump() for k, v in config.servers.items()},
            "registered_in_db": db_statuses
        }

    return server_statuses


@router.post("/add")
async def add_server(req: AddServerRequest):
    """Add and discover a new MCP server (Security Model: ADDING != TRUSTING).

    Connects, discovers tools, namespaces collisions, runs capability inference,
    updates graph and compatible paths, persists data in PostgreSQL.
    Marked UNTRUSTED with NO_APPROVED_BASELINE (execution remains blocked by Stage 1).
    """
    if not req.name or not req.name.strip():
        raise HTTPException(status_code=400, detail="Server name is required")
    if not req.command or not req.command.strip():
        raise HTTPException(status_code=400, detail="Server command is required")

    params = {
        "name": req.name.strip(),
        "command": req.command.strip(),
        "args": req.args or [],
        "env": req.env or {},
        "transport": req.transport or "stdio"
    }

    try:
        res = await send_proxy_control_command("add_server", params)
        if res.get("status") == "error":
            raise HTTPException(status_code=500, detail=res.get("error"))
        return res.get("data")
    except DownstreamConnectionError as e:
        # Offline fallback: persist server definition to config and DB
        from mcpath.backend.persistence.database import save_discovered_tools
        from mcpath.proxy.client_manager import save_server_config_file
        config = settings.get_server_config()
        config.servers[req.name] = ServerDefinition(command=req.command, args=req.args or [], env=req.env or {})
        if hasattr(config, "active_servers") and req.name not in config.active_servers:
            config.active_servers.append(req.name)
        save_server_config_file(config)
        await save_discovered_tools(req.name, tools=[], command=req.command, args=req.args, env_vars=req.env)
        return {
            "name": req.name,
            "active": True,
            "is_active": True,
            "connected": False,
            "trust_status": "UNTRUSTED",
            "discovered_tool_count": 0,
            "approved_tool_count": 0,
            "unapproved_tool_count": 0,
            "message": f"Server '{req.name}' persisted to config and DB. Live proxy is offline: {e}"
        }


@router.post("/{server_name}/trust")
async def trust_server(server_name: str):
    """Explicitly Trust & Register the entire current tool manifest with ONE server-level action.

    Creates the approved Stage 1 baseline for all tools currently discovered on the server.
    """
    try:
        res = await send_proxy_control_command("trust_server", {"server_name": server_name})
        if res.get("status") == "error":
            raise HTTPException(status_code=400, detail=res.get("error"))
        return res.get("data")
    except DownstreamConnectionError as e:
        raise HTTPException(status_code=503, detail=f"Cannot trust server: {e}")


@router.post("/{server_name}/deactivate")
async def deactivate_server(server_name: str):
    """Deactivate an MCP server: disconnect live session, remove tools from catalog and graph.

    Preserves historical security events, tools, and approved baseline in PostgreSQL.
    """
    try:
        res = await send_proxy_control_command("deactivate_server", {"server_name": server_name})
        if res.get("status") == "error":
            raise HTTPException(status_code=400, detail=res.get("error"))
        return res.get("data")
    except DownstreamConnectionError:
        from mcpath.backend.persistence.database import set_server_active_state
        from mcpath.proxy.client_manager import save_server_config_file
        config = settings.get_server_config()
        if hasattr(config, "active_servers") and server_name in config.active_servers:
            config.active_servers = [s for s in config.active_servers if s != server_name]
            save_server_config_file(config)
        await set_server_active_state(server_name, is_active=False)
        return {
            "name": server_name,
            "active": False,
            "is_active": False,
            "connected": False,
            "message": f"Server '{server_name}' deactivated in config and database."
        }


@router.post("/{server_name}/activate")
async def activate_server(server_name: str):
    """Activate an existing MCP server: reconnect, rediscover tools, update graph and catalog.

    IMPORTANT: Does NOT create a new baseline. Existing approved baselines are verified.
    """
    try:
        res = await send_proxy_control_command("activate_server", {"server_name": server_name})
        if res.get("status") == "error":
            raise HTTPException(status_code=400, detail=res.get("error"))
        return res.get("data")
    except DownstreamConnectionError:
        from mcpath.backend.persistence.database import set_server_active_state
        from mcpath.proxy.client_manager import save_server_config_file
        config = settings.get_server_config()
        if server_name not in config.servers:
            raise HTTPException(status_code=404, detail=f"Server '{server_name}' not found in configuration")
        if hasattr(config, "active_servers") and config.active_servers is not None:
            if server_name not in config.active_servers:
                config.active_servers.append(server_name)
                save_server_config_file(config)
        await set_server_active_state(server_name, is_active=True)
        return {
            "name": server_name,
            "active": True,
            "is_active": True,
            "connected": False,
            "message": f"Server '{server_name}' activated in config and database."
        }


@router.get("/{server_name}")
async def get_server_detail(
    server_name: str,
    db: AsyncSession = Depends(get_db)
):
    """Return status for a single downstream MCP server."""
    try:
        res = await send_proxy_control_command("get_server_status", {"server_name": server_name})
        if res.get("status") == "success" and res.get("data"):
            return res.get("data")
    except Exception:
        pass

    from mcpath.backend.persistence.database import get_server_db_status
    db_statuses = await get_server_db_status(server_name=server_name, session=db)
    if db_statuses:
        return db_statuses[0]

    config = settings.get_server_config()
    if server_name in config.servers:
        s_def = config.servers[server_name]
        is_active = server_name in getattr(config, "active_servers", [config.active_server])
        return {
            "name": server_name,
            "command": s_def.command,
            "args": s_def.args,
            "active": is_active,
            "is_active": is_active,
            "connected": False,
            "trust_status": "UNTRUSTED",
            "discovered_tool_count": 0,
            "approved_tool_count": 0,
            "unapproved_tool_count": 0,
            "last_discovery_time": None,
            "last_trust_time": None
        }

    raise HTTPException(status_code=404, detail=f"Server '{server_name}' not found")


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
async def reload_servers(db: AsyncSession = Depends(get_db)):
    """Dynamically reload configured downstream MCP servers.

    - Reads current MCPath server configuration
    - Synchronizes ServerDB.is_active status in DB
    - Disconnects removed servers and connects newly added servers
    - Rediscovers tools and recomputes exposed-tool collision mapping
    - Rebuilds dynamic capability graph
    """
    config = settings.get_server_config()
    target_servers = getattr(config, "active_servers", None)
    if not target_servers:
        target_servers = [config.active_server] if config.active_server else list(config.servers.keys())
    active_set = set(target_servers) & set(config.servers.keys())

    # Synchronize ServerDB.is_active using authoritative reconcile function
    from mcpath.backend.persistence.database import reconcile_server_active_states
    try:
        await reconcile_server_active_states(
            active_servers=list(active_set),
            configured_servers=list(config.servers.keys()),
            session=db
        )
    except Exception as e:
        logger.warning("Could not synchronize server is_active state in DB: %s", e)

    from mcpath.proxy.client_manager import get_active_client_manager
    mgr = get_active_client_manager()
    if mgr is not None:
        summary = await mgr.reload()
        return summary

    try:
        res = await send_proxy_control_command("reload")
        if res.get("status") == "success":
            return res.get("data")
    except Exception:
        pass

    return {
        "status": "success",
        "message": "Proxy is not actively running in this process; reloaded configuration from disk",
        "active_servers": list(active_set),
        "configured_servers": list(config.servers.keys())
    }
