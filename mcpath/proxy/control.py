"""Localhost Control Channel for MCPath Zero-Trust Security Proxy.

Enables dynamic lifecycle management (Add, Trust, Deactivate, Activate, Status)
between the FastAPI backend and the live stdio proxy without restarting Claude Desktop.
"""

import asyncio
import json
import logging
from typing import Any, Dict, Optional
from mcpath.config.settings import settings
from mcpath.core.exceptions import DownstreamConnectionError
from mcpath.proxy.client_manager import get_active_client_manager, DownstreamClientManager

logger = logging.getLogger("mcpath.proxy.control")


class ProxyControlServer:
    """Lightweight localhost asyncio TCP server running alongside stdio proxy."""

    def __init__(self, client_manager: DownstreamClientManager, host: str = "127.0.0.1", port: Optional[int] = None):
        self.client_manager = client_manager
        self.host = host
        self.port = port or settings.proxy_control_port
        self._server: Optional[asyncio.Server] = None

    async def start(self) -> None:
        """Start listening on localhost control port."""
        try:
            self._server = await asyncio.start_server(
                self._handle_client,
                self.host,
                self.port
            )
            logger.info("MCPath Proxy control channel listening on %s:%d", self.host, self.port)
        except Exception as e:
            logger.warning("Could not start MCPath proxy control server on %s:%d: %s", self.host, self.port, e)

    async def stop(self) -> None:
        """Stop control server."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            logger.info("MCPath Proxy control channel stopped")

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Process incoming JSON command line and return response."""
        try:
            line = await reader.readline()
            if not line:
                writer.close()
                await writer.wait_closed()
                return

            req = json.loads(line.decode("utf-8"))
            action = req.get("action")
            params = req.get("params", {})

            result = await dispatch_control_action(self.client_manager, action, params)
            response = {"status": "success", "data": result}
        except Exception as e:
            logger.error("Error executing proxy control action: %s", e)
            response = {"status": "error", "error": str(e)}

        try:
            writer.write((json.dumps(response) + "\n").encode("utf-8"))
            await writer.drain()
        except Exception as e:
            logger.debug("Failed writing control response: %s", e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


async def dispatch_control_action(
    mgr: DownstreamClientManager,
    action: str,
    params: Optional[Dict[str, Any]] = None
) -> Any:
    """Execute dynamic lifecycle action on a DownstreamClientManager instance."""
    params = params or {}
    if action == "ping":
        return {"pong": True}
    elif action == "add_server":
        return await mgr.add_server(
            name=params["name"],
            command=params["command"],
            args=params.get("args"),
            env=params.get("env"),
            transport=params.get("transport", "stdio")
        )
    elif action == "trust_server":
        return await mgr.trust_server(server_name=params["server_name"])
    elif action == "deactivate_server":
        return await mgr.deactivate_server(server_name=params["server_name"])
    elif action == "activate_server":
        return await mgr.activate_server(server_name=params["server_name"])
    elif action == "get_server_status":
        return await mgr.get_server_status(server_name=params["server_name"])
    elif action == "get_all_servers_status":
        return await mgr.get_all_servers_status()
    elif action == "reload":
        return await mgr.reload()
    else:
        raise ValueError(f"Unknown proxy control action: '{action}'")


async def send_proxy_control_command(
    action: str,
    params: Optional[Dict[str, Any]] = None,
    timeout: float = 15.0
) -> Dict[str, Any]:
    """Send command to active proxy manager, routing in-process if available or via TCP."""
    # 1. Check in-process active manager first
    mgr = get_active_client_manager()
    if mgr is not None:
        try:
            res = await dispatch_control_action(mgr, action, params)
            return {"status": "success", "data": res}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    # 2. Forward via localhost TCP to running proxy process
    host = settings.proxy_control_host
    port = settings.proxy_control_port
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=2.0
        )
    except Exception as e:
        raise DownstreamConnectionError(
            f"MCPath Proxy is not actively running or control port {host}:{port} is unreachable: {e}"
        )

    try:
        payload = json.dumps({"action": action, "params": params or {}}) + "\n"
        writer.write(payload.encode("utf-8"))
        await writer.drain()

        line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if not line:
            raise DownstreamConnectionError("Empty response from MCPath Proxy control channel")
        return json.loads(line.decode("utf-8"))
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
