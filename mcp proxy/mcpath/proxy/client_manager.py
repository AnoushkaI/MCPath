"""Downstream MCP Client Manager.

Connects to target MCP servers using official MCP Python SDK client transports.
"""

from contextlib import asynccontextmanager
import logging
import sys
from typing import Any, AsyncIterator, Dict, List, Optional
from mcp.client.session import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters
import mcp.types as types
from mcpath.config.settings import ServerDefinition, PROJECT_ROOT
from mcpath.core.exceptions import DownstreamConnectionError

logger = logging.getLogger("mcpath.proxy.client_manager")


class DownstreamClientManager:
    """Manages connection and communication with downstream MCP server."""

    def __init__(self, server_def: ServerDefinition, server_name: str = "downstream"):
        self.server_def = server_def
        self.server_name = server_name
        self.session: Optional[ClientSession] = None
        self._tools_cache: Dict[str, types.Tool] = {}
        self._server_info: Optional[types.Implementation] = None

    @asynccontextmanager
    async def session_context(self) -> AsyncIterator[ClientSession]:
        """Establish downstream connection and yield initialized ClientSession."""
        # When command is 'python', ensure it resolves to sys.executable if running within virtualenv
        cmd = self.server_def.command
        if cmd == "python":
            cmd = sys.executable

        # Resolve args: if an argument is a relative path to a file that exists in PROJECT_ROOT, resolve to absolute path
        resolved_args = []
        for arg in self.server_def.args:
            candidate = PROJECT_ROOT / arg
            if candidate.exists():
                resolved_args.append(str(candidate.resolve()))
            else:
                resolved_args.append(arg)

        env = self.server_def.env if self.server_def.env else None
        server_params = StdioServerParameters(
            command=cmd,
            args=resolved_args,
            env=env,
            cwd=str(PROJECT_ROOT)
        )

        logger.info(
            "Connecting to downstream MCP server [%s] via command: %s %s (cwd=%s)",
            self.server_name,
            cmd,
            " ".join(resolved_args),
            str(PROJECT_ROOT)
        )

        try:
            async with stdio_client(server_params) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    init_result = await session.initialize()
                    self.session = session
                    self._server_info = init_result.server_info
                    logger.info(
                        "Downstream server connected: name='%s', version='%s'",
                        init_result.server_info.name,
                        init_result.server_info.version
                    )
                    yield session
        except Exception as e:
            logger.error("Failed to connect to downstream MCP server: %s", str(e), exc_info=True)
            raise DownstreamConnectionError(f"Downstream server connection failed: {e}") from e
        finally:
            self.session = None

    async def list_tools(
        self,
        session: ClientSession,
        params: Optional[types.PaginatedRequestParams] = None
    ) -> types.ListToolsResult:
        """Fetch available tools from downstream server and update local cache."""
        result = await session.list_tools(params=params)
        for tool in result.tools:
            self._tools_cache[tool.name] = tool
        return result

    async def call_tool(
        self,
        session: ClientSession,
        name: str,
        arguments: Optional[Dict[str, Any]] = None
    ) -> types.CallToolResult:
        """Forward tool call to downstream server."""
        return await session.call_tool(name=name, arguments=arguments)

    def get_tool_definition(self, name: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached tool definition dictionary for hashing and capability checks."""
        tool = self._tools_cache.get(name)
        if tool:
            return tool.model_dump(mode="json")
        return None
