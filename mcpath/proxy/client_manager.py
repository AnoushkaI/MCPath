"""Multi-Server Downstream MCP Client Manager.

Manages independent connections, sessions, transports, tool discovery,
deterministic namespace collision handling, and routed invocation across
multiple configured downstream MCP servers (Filesystem, Git, PostgreSQL, etc.).
"""

from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field
import logging
import os
from pathlib import Path
import sys
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple
from mcp.client.session import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters
import mcp.types as types
from mcpath.config.settings import (
    ServerConfig,
    ServerDefinition,
    PROJECT_ROOT,
    interpolate_server_config,
    settings,
)
from mcpath.core.exceptions import DownstreamConnectionError
from mcpath.graph.capability_graph import CapabilityGraph

logger = logging.getLogger("mcpath.proxy.client_manager")

# Global reference to running manager for dynamic reload operations
_ACTIVE_CLIENT_MANAGER: Optional["DownstreamClientManager"] = None


def get_active_client_manager() -> Optional["DownstreamClientManager"]:
    """Retrieve currently running DownstreamClientManager instance."""
    return _ACTIVE_CLIENT_MANAGER


def set_active_client_manager(manager: Optional["DownstreamClientManager"]) -> None:
    """Register active DownstreamClientManager instance."""
    global _ACTIVE_CLIENT_MANAGER
    _ACTIVE_CLIENT_MANAGER = manager


@dataclass
class ExposedTool:
    """Metadata describing an exposed tool and its downstream ownership."""
    exposed_name: str
    server_name: str
    original_name: str
    tool: types.Tool
    raw_definition: Dict[str, Any]


@dataclass
class DownstreamServerState:
    """Connection and manifest lifecycle state for a single downstream server."""
    server_name: str
    server_def: ServerDefinition
    session: Optional[ClientSession] = None
    exit_stack: Optional[AsyncExitStack] = None
    is_connected: bool = False
    error: Optional[str] = None
    tools: Dict[str, types.Tool] = field(default_factory=dict)
    server_info: Optional[types.Implementation] = None


class DownstreamClientManager:
    """Maintains independent MCP client connections for multiple ServerDefinition objects."""

    def __init__(
        self,
        server_defs: Optional[Any] = None,
        server_def: Optional[ServerDefinition] = None,
        server_name: Optional[str] = None
    ):
        # Backward compatibility when ServerDefinition is passed as first positional arg: DownstreamClientManager(server_def, server_name)
        if isinstance(server_defs, ServerDefinition):
            server_def = server_defs
            server_defs = None

        if server_defs is not None:
            self.server_defs: Dict[str, ServerDefinition] = dict(server_defs)
        elif server_def is not None:
            name = server_name or "downstream"
            self.server_defs = {name: server_def}
        else:
            self.server_defs = {}

        self.server_name: str = server_name or (
            list(self.server_defs.keys())[0] if len(self.server_defs) == 1 else "mcpath-proxy"
        )

        self.servers_state: Dict[str, DownstreamServerState] = {}
        self.sessions: Dict[str, ClientSession] = {}
        self.unavailable_servers: Dict[str, str] = {}
        self.exposed_tools: Dict[str, ExposedTool] = {}
        self._tools_cache: Dict[str, types.Tool] = {}  # Legacy lookup support
        self.capability_graph: CapabilityGraph = CapabilityGraph()

        # Initialize server states
        for s_name, s_def in self.server_defs.items():
            self.servers_state[s_name] = DownstreamServerState(server_name=s_name, server_def=s_def)

    @property
    def session(self) -> Optional[ClientSession]:
        """Backward-compatibility property returning active session for single-server callers."""
        if self.server_name in self.sessions:
            return self.sessions[self.server_name]
        if self.sessions:
            return next(iter(self.sessions.values()))
        return None

    def get_session(self, server_name: str) -> Optional[ClientSession]:
        """Retrieve active ClientSession for a specific downstream server."""
        return self.sessions.get(server_name)

    async def connect_server(self, server_name: str) -> bool:
        """Connect to a single downstream server independently with dedicated transport stack."""
        server_def = self.server_defs.get(server_name)
        if not server_def:
            logger.error("Cannot connect unknown server '%s'", server_name)
            return False

        # Disconnect any existing transport first to prevent leaks or stale handles
        await self.disconnect_server(server_name)

        state = DownstreamServerState(server_name=server_name, server_def=server_def)
        self.servers_state[server_name] = state

        # When command is 'python', ensure it resolves to sys.executable if running within virtualenv
        cmd = server_def.command
        if cmd == "python":
            cmd = sys.executable

        # Resolve args: relative paths within PROJECT_ROOT resolved to absolute
        resolved_args = []
        for arg in server_def.args:
            candidate = PROJECT_ROOT / arg
            if candidate.exists():
                resolved_args.append(str(candidate.resolve()))
            else:
                resolved_args.append(arg)

        # Merge full OS environment with server-specific overrides (crucial for Node/uvx on Windows)
        merged_env = {**os.environ}
        if server_def.env:
            merged_env.update(server_def.env)

        server_params = StdioServerParameters(
            command=cmd,
            args=resolved_args,
            env=merged_env,
            cwd=str(PROJECT_ROOT)
        )

        logger.info(
            "Connecting to downstream MCP server [%s] via command: %s %s (cwd=%s)",
            server_name,
            cmd,
            " ".join(resolved_args),
            str(PROJECT_ROOT)
        )

        stack = AsyncExitStack()
        try:
            read_stream, write_stream = await stack.enter_async_context(stdio_client(server_params))
            session = await stack.enter_async_context(ClientSession(read_stream, write_stream))
            init_result = await session.initialize()

            state.session = session
            state.exit_stack = stack
            state.is_connected = True
            state.server_info = init_result.server_info
            state.error = None
            self.sessions[server_name] = session
            self.unavailable_servers.pop(server_name, None)

            # Discover tools immediately on session establishment
            tools_res = await session.list_tools()
            state.tools = {t.name: t for t in tools_res.tools}
            for t in tools_res.tools:
                self._tools_cache[t.name] = t

            logger.info(
                "Downstream server [%s] connected: %d tools discovered (name='%s', version='%s')",
                server_name,
                len(state.tools),
                init_result.server_info.name,
                init_result.server_info.version
            )
            return True
        except Exception as e:
            logger.error("Failed to connect downstream server '%s': %s", server_name, str(e), exc_info=False)
            await stack.aclose()
            state.is_connected = False
            state.session = None
            state.exit_stack = None
            state.error = str(e)
            self.sessions.pop(server_name, None)
            self.unavailable_servers[server_name] = str(e)
            return False

    async def disconnect_server(self, server_name: str) -> None:
        """Gracefully disconnect a downstream server and release its subprocess transport."""
        state = self.servers_state.get(server_name)
        if state:
            if state.exit_stack:
                try:
                    await state.exit_stack.aclose()
                except Exception as e:
                    logger.debug("Closing transport stack for server '%s': %s", server_name, e)
            state.session = None
            state.exit_stack = None
            state.is_connected = False
            state.tools.clear()

        self.sessions.pop(server_name, None)
        logger.info("Downstream server '%s' disconnected", server_name)

    async def start_all_servers(self) -> None:
        """Connect to all configured downstream servers independently."""
        set_active_client_manager(self)
        for s_name in list(self.server_defs.keys()):
            await self.connect_server(s_name)
        self.recompute_exposed_tools()

    async def stop_all_servers(self) -> None:
        """Disconnect all connected downstream servers."""
        for s_name in list(self.servers_state.keys()):
            await self.disconnect_server(s_name)
        self.recompute_exposed_tools()
        set_active_client_manager(None)

    def register_active_session(
        self,
        server_name: str,
        session: ClientSession,
        server_def: Optional[ServerDefinition] = None,
        tools: Optional[List[types.Tool]] = None
    ) -> None:
        """Register an already initialized ClientSession (used by in-memory/mock test fixtures)."""
        s_def = server_def or ServerDefinition(command="test", args=[])
        self.server_defs[server_name] = s_def
        state = DownstreamServerState(
            server_name=server_name,
            server_def=s_def,
            session=session,
            is_connected=True
        )
        if tools:
            state.tools = {t.name: t for t in tools}
            for t in tools:
                self._tools_cache[t.name] = t
        elif self._tools_cache:
            state.tools = {k: v for k, v in self._tools_cache.items()}
        self.servers_state[server_name] = state
        self.sessions[server_name] = session
        self.unavailable_servers.pop(server_name, None)
        self.recompute_exposed_tools()

    def recompute_exposed_tools(self) -> None:
        """Recompute the aggregated exposed tools catalog and handle collisions deterministically.

        Collision Invariants:
        1. Unique tools preserve their exact original name, description, and input schema.
        2. If two or more servers expose the same tool name, every collider is deterministically
           namespaced as '{server_name}_{tool_name}'.
        3. An immutable mapping is maintained: exposed_name -> (server_name, original_name, raw_definition).
        """
        name_counts: Dict[str, int] = {}
        for s_name, state in self.servers_state.items():
            if state.is_connected:
                for t_name in state.tools.keys():
                    name_counts[t_name] = name_counts.get(t_name, 0) + 1

        new_exposed: Dict[str, ExposedTool] = {}
        graph_tools: Dict[str, List[Dict[str, Any]]] = {}

        for s_name, state in self.servers_state.items():
            if state.is_connected:
                raw_tools_list = []
                for t_name, tool_obj in state.tools.items():
                    raw_def = tool_obj.model_dump(mode="json")
                    raw_tools_list.append(raw_def)

                    # Collision handling
                    if name_counts[t_name] > 1:
                        exposed_name = f"{s_name}_{t_name}"
                    else:
                        exposed_name = t_name

                    input_schema = (
                        getattr(tool_obj, "input_schema", None)
                        or getattr(tool_obj, "inputSchema", None)
                        or {}
                    )
                    exposed_tool_obj = types.Tool(
                        name=exposed_name,
                        description=tool_obj.description,
                        input_schema=input_schema
                    )

                    new_exposed[exposed_name] = ExposedTool(
                        exposed_name=exposed_name,
                        server_name=s_name,
                        original_name=t_name,
                        tool=exposed_tool_obj,
                        raw_definition=raw_def
                    )
                    self._tools_cache[exposed_name] = tool_obj
                    self._tools_cache[t_name] = tool_obj

                graph_tools[s_name] = raw_tools_list

        self.exposed_tools = new_exposed
        self.capability_graph.rebuild_for_all_servers(graph_tools)
        try:
            import asyncio
            from mcpath.backend.persistence.database import persist_capability_graph
            loop = asyncio.get_running_loop()
            if loop.is_running():
                exported = self.capability_graph.export_graph()
                loop.create_task(persist_capability_graph(exported))
        except (RuntimeError, Exception) as e:
            logger.debug("Capability graph persistence deferred or skipped: %s", e)

        logger.info(
            "Aggregated catalog updated: %d tools exposed across %d connected servers (%d unavailable)",
            len(self.exposed_tools),
            len(self.sessions),
            len(self.unavailable_servers)
        )

    def get_aggregated_tools_result(self) -> types.ListToolsResult:
        """Return aggregated types.ListToolsResult containing exposed tools from all connected servers."""
        tools = [exp.tool for exp in self.exposed_tools.values()]
        return types.ListToolsResult(tools=tools)

    def get_exposed_tool(self, exposed_name: str) -> Optional[ExposedTool]:
        """Look up exposed tool metadata by exposed name."""
        return self.exposed_tools.get(exposed_name)

    def get_tool_definition(self, name: str, server_name: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieve cached tool definition dictionary for Stage 1 hashing and integrity checks."""
        # 1. If server_name is explicitly specified, find in that server's state first
        if server_name and server_name in self.servers_state:
            state = self.servers_state[server_name]
            if name in state.tools:
                return state.tools[name].model_dump(mode="json")

        # 2. Check exposed tools registry by exposed_name
        if name in self.exposed_tools:
            return self.exposed_tools[name].tool.model_dump(mode="json")

        # 3. Check legacy _tools_cache
        if name in self._tools_cache:
            return self._tools_cache[name].model_dump(mode="json")

        return None

    @asynccontextmanager
    async def session_context(self) -> AsyncIterator[Any]:
        """Context manager establishing connections to all downstream servers."""
        try:
            await self.start_all_servers()
            # If exactly one server was configured, yield its session for backwards compatibility
            if len(self.server_defs) == 1 and self.session:
                yield self.session
            else:
                yield self
        finally:
            await self.stop_all_servers()

    async def list_tools(
        self,
        session: Optional[ClientSession] = None,
        params: Optional[types.PaginatedRequestParams] = None
    ) -> types.ListToolsResult:
        """Fetch tools. If session is passed, fetch from that session (legacy); otherwise return aggregated list."""
        if session is not None:
            result = await session.list_tools(params=params)
            for tool in result.tools:
                self._tools_cache[tool.name] = tool
                # Also assign to matching server state if identifiable
                for state in self.servers_state.values():
                    if state.session == session:
                        state.tools[tool.name] = tool
            self.recompute_exposed_tools()
            return result

        # Refresh manifests from all active sessions
        for s_name, session in list(self.sessions.items()):
            try:
                res = await session.list_tools()
                if s_name in self.servers_state:
                    self.servers_state[s_name].tools = {t.name: t for t in res.tools}
            except Exception as e:
                logger.warning("Could not refresh tools for server '%s': %s", s_name, e)

        self.recompute_exposed_tools()
        return self.get_aggregated_tools_result()

    async def call_tool(
        self,
        session: Optional[ClientSession] = None,
        name: Optional[str] = None,
        arguments: Optional[Dict[str, Any]] = None
    ) -> types.CallToolResult:
        """Forward tool call. Supports legacy (session, name, arguments) and routed (name, arguments)."""
        if session is not None and name is not None:
            # Legacy direct session call
            return await session.call_tool(name=name, arguments=arguments)

        # Routed call by exposed tool name
        tool_name = name or ""
        exposed = self.get_exposed_tool(tool_name)
        if not exposed:
            raise ValueError(f"Tool '{tool_name}' not found on any active downstream MCP server")

        target_session = self.get_session(exposed.server_name)
        if not target_session:
            raise DownstreamConnectionError(
                f"Server '{exposed.server_name}' owning tool '{tool_name}' is not currently connected"
            )

        return await target_session.call_tool(name=exposed.original_name, arguments=arguments)

    async def reload(self, new_config: Optional[ServerConfig] = None) -> Dict[str, Any]:
        """Dynamic controlled reload: detects added/removed/changed servers, reconnects, and refreshes catalog."""
        config = new_config or settings.get_server_config()
        target_server_names = config.active_servers if hasattr(config, "active_servers") and config.active_servers else list(config.servers.keys())

        # Exclude sample_reference_server unless explicitly targeted
        target_server_names = [s for s in target_server_names if s in config.servers]

        current_servers = set(self.server_defs.keys())
        target_servers = set(target_server_names)

        removed = current_servers - target_servers
        added = target_servers - current_servers
        retained = current_servers & target_servers

        # 1. Gracefully disconnect removed servers
        for s_name in removed:
            await self.disconnect_server(s_name)
            self.server_defs.pop(s_name, None)
            self.servers_state.pop(s_name, None)
            self.capability_graph.remove_server(s_name)

        # 2. Add and connect newly configured servers
        for s_name in added:
            raw_def = config.servers[s_name]
            interpolated_def = interpolate_server_config(raw_def, settings)
            self.server_defs[s_name] = interpolated_def
            await self.connect_server(s_name)

        # 3. Check retained servers for configuration updates
        for s_name in retained:
            raw_def = config.servers[s_name]
            interpolated_def = interpolate_server_config(raw_def, settings)
            # If server was disconnected or failed previously, attempt reconnect
            if not self.servers_state.get(s_name) or not self.servers_state[s_name].is_connected:
                self.server_defs[s_name] = interpolated_def
                await self.connect_server(s_name)

        # 4. Recompute aggregated tools and update capability graph
        self.recompute_exposed_tools()

        summary = {
            "status": "success",
            "active_servers": list(self.sessions.keys()),
            "unavailable_servers": list(self.unavailable_servers.keys()),
            "added_servers": list(added),
            "removed_servers": list(removed),
            "total_tools_exposed": len(self.exposed_tools)
        }
        logger.info("Dynamic reload complete: %s", summary)
        return summary
