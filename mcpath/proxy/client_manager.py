"""Multi-Server Downstream MCP Client Manager.

Manages independent connections, sessions, transports, tool discovery,
deterministic namespace collision handling, and routed invocation across
multiple configured downstream MCP servers (Filesystem, Git, PostgreSQL, etc.).
"""

from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
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


def save_server_config_file(config: ServerConfig) -> None:
    """Persist updated ServerConfig to server_config.json on disk."""
    p = Path(settings.server_config_path)
    if not p.is_absolute():
        p = (PROJECT_ROOT / p).resolve()
    try:
        with open(p, "w", encoding="utf-8") as f:
            json.dump(config.model_dump(), f, indent=2)
        logger.info("Persisted updated configuration to %s", p)
    except Exception as e:
        logger.warning("Could not persist server_config.json: %s", e)


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
        # In test environments (e.g. pytest), skip un-awaited background DB writes to prevent SQLite lock collisions
        if os.environ.get("PYTEST_CURRENT_TEST") and not getattr(self, "force_persist_graph", False):
            logger.info(
                "Aggregated catalog updated: %d tools exposed across %d connected servers (%d unavailable)",
                len(self.exposed_tools),
                len(self.sessions),
                len(self.unavailable_servers)
            )
            return

        try:
            import asyncio
            from mcpath.backend.persistence.database import (
                persist_capability_graph,
                persist_tool_capabilities,
            )
            loop = asyncio.get_running_loop()
            if loop.is_running():
                exported = self.capability_graph.export_graph()
                raw_caps = [
                    {
                        "tool_name": cap.tool_name,
                        "server_name": cap.server_name,
                        "data_target": cap.data_target,
                        "operation": cap.operation,
                        "action_type": cap.action_type,
                        "external_destination": cap.external_destination,
                        "data_sensitivity": cap.data_sensitivity,
                        "action_sensitivity": cap.action_sensitivity,
                        "external_exposure": cap.external_exposure,
                        "policy_version": cap.policy_version,
                        "raw_metadata": cap.raw_metadata,
                    }
                    for cap in self.capability_graph.tool_capabilities.values()
                ]

                async def _persist_bg():
                    try:
                        await persist_capability_graph(exported)
                        await persist_tool_capabilities(raw_caps)
                    except Exception as ex:
                        logger.debug("Background capability persistence skipped: %s", ex)

                loop.create_task(_persist_bg())
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

        # 5. Synchronize DB ServerDB.is_active states with reloaded active_servers
        from mcpath.backend.persistence.database import reconcile_server_active_states
        try:
            await reconcile_server_active_states(
                active_servers=list(target_servers),
                configured_servers=list(config.servers.keys())
            )
        except Exception as e:
            logger.warning("Could not reconcile DB server states during reload: %s", e)

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

    async def add_server(
        self,
        name: str,
        command: str,
        args: Optional[List[str]] = None,
        env: Optional[Dict[str, str]] = None,
        transport: str = "stdio",
        session: Optional[Any] = None
    ) -> Dict[str, Any]:
        """Add and discover an MCP server.

        Security Model: ADDING != TRUSTING
        1. Validates configuration.
        2. Persists to server_config.json.
        3. Connects to real MCP server.
        4. Discovers tools via tools/list.
        5. Namespaces collisions and builds capability graph.
        6. Persists capabilities, nodes, edges, paths to PostgreSQL.
        7. Computes observed SHA-256 hashes using Stage 1 canonicalization.
        8. Persists tools to PostgreSQL ToolDB WITHOUT creating ApprovedHashDB rows.
        9. Marks server trust_status = 'UNTRUSTED'.
        Tools remain NO_APPROVED_BASELINE and will fail-closed in Stage 1.
        """
        if not name or not name.strip():
            raise ValueError("Server name is required")
        if not command or not command.strip():
            raise ValueError("Server command is required")

        server_name = name.strip()
        s_def = ServerDefinition(command=command, args=args or [], env=env or {})

        # 1. Update server_config.json: persist server definition, ensure not in active_servers until connected
        config = settings.get_server_config()
        config.servers[server_name] = s_def
        if hasattr(config, "active_servers") and config.active_servers is not None:
            config.active_servers = [s for s in config.active_servers if s != server_name]
        try:
            save_server_config_file(config)
        except Exception as e:
            logger.warning("Could not update server_config.json for '%s': %s", server_name, e)

        # 2. Add to in-memory server definitions
        interpolated_def = interpolate_server_config(s_def, settings)
        self.server_defs[server_name] = interpolated_def

        # 3. Connect to downstream server
        connected = await self.connect_server(server_name)
        state = self.servers_state.get(server_name)
        if not connected or not state or not state.is_connected:
            err_msg = state.error if state else "Connection failed"
            self.server_defs.pop(server_name, None)
            from mcpath.backend.persistence.database import save_discovered_tools
            try:
                await save_discovered_tools(
                    server_name=server_name,
                    tools=[],
                    command=command,
                    args=args,
                    env_vars=env,
                    is_active=False,
                    session=session
                )
            except Exception:
                pass
            raise DownstreamConnectionError(f"Failed to connect to MCP server '{server_name}': {err_msg}")

        # 4. Connection succeeded: add to active_servers in server_config.json
        if hasattr(config, "active_servers") and config.active_servers is not None:
            if server_name not in config.active_servers:
                config.active_servers.append(server_name)
                try:
                    save_server_config_file(config)
                except Exception as e:
                    logger.warning("Could not save active_servers for '%s': %s", server_name, e)

        # 5. Recompute exposed tools, namespace duplicate names, rebuild graph & paths, persist to DB
        self.recompute_exposed_tools()

        # 6. Calculate observed SHA-256 definition hashes using existing Stage 1 canonicalization
        from mcpath.pipeline.stages.stage1_hash import canonicalize_and_hash
        from mcpath.backend.persistence.database import save_discovered_tools

        observed_hashes: Dict[str, str] = {}
        raw_tools: List[Dict[str, Any]] = []
        for t_name, tool_obj in state.tools.items():
            tool_dict = tool_obj.model_dump(mode="json")
            raw_tools.append(tool_dict)
            _, sha = canonicalize_and_hash(tool_dict)
            observed_hashes[t_name] = sha

        # 7. Persist server and discovered tools to ToolDB with is_active=True (UNTRUSTED, NO approved baseline)
        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            await save_discovered_tools(
                server_name=server_name,
                tools=raw_tools,
                command=command,
                args=args,
                env_vars=env,
                is_active=True,
                session=session
            )
        except Exception as e:
            logger.warning("Could not persist discovered tools to DB for '%s': %s", server_name, e)

        return {
            "name": server_name,
            "active": True,
            "is_active": True,
            "connected": True,
            "trust_status": "UNTRUSTED",
            "discovered_tool_count": len(raw_tools),
            "approved_tool_count": 0,
            "unapproved_tool_count": len(raw_tools),
            "observed_hashes": observed_hashes,
            "last_discovery_time": now_iso,
            "last_trust_time": None,
            "message": f"Server '{server_name}' added and analyzed. Trust status: UNTRUSTED. Tools have NO_APPROVED_BASELINE."
        }

    async def trust_server(self, server_name: str, session: Optional[Any] = None) -> Dict[str, Any]:
        """Trust & Register all tools of an MCP server with ONE server-level action.

        1. Confirms server is connected.
        2. Calls tools/list again.
        3. Retrieves complete definitions.
        4. Canonicalizes and computes SHA-256 using Stage 1 implementation.
        5. Stores current hashes as approved baseline in ApprovedHashDB.
        6. Updates ServerDB trust_status = 'TRUSTED' and approval timestamp.
        """
        if server_name not in self.server_defs:
            config = settings.get_server_config()
            if server_name in config.servers:
                self.server_defs[server_name] = interpolate_server_config(config.servers[server_name], settings)
            else:
                raise ValueError(f"Server '{server_name}' not found")

        state = self.servers_state.get(server_name)
        if not state or not state.is_connected:
            connected = await self.connect_server(server_name)
            if not connected:
                raise DownstreamConnectionError(f"Server '{server_name}' is not connected and could not be reached")
            state = self.servers_state[server_name]

        # Call tools/list again on live session
        tools_res = await state.session.list_tools()
        raw_tools = [t.model_dump(mode="json") for t in tools_res.tools]
        state.tools = {t.name: t for t in tools_res.tools}

        from mcpath.pipeline.stages.stage1_hash import canonicalize_and_hash
        from mcpath.backend.persistence.database import register_trusted_server_and_tools

        synced = await register_trusted_server_and_tools(
            server_name=server_name,
            tools=raw_tools,
            canonicalize_and_hash_fn=canonicalize_and_hash,
            command=self.server_defs[server_name].command,
            args=self.server_defs[server_name].args,
            env_vars=self.server_defs[server_name].env,
            approved_by="admin:trusted_registration",
            session=session
        )

        self.recompute_exposed_tools()
        now_iso = datetime.now(timezone.utc).isoformat()

        config = settings.get_server_config()
        active_set = set(getattr(config, "active_servers", None) or ([config.active_server] if config.active_server else []))
        is_active = (server_name in active_set and server_name in config.servers)

        return {
            "name": server_name,
            "active": is_active,
            "is_active": is_active,
            "connected": True,
            "trust_status": "TRUSTED",
            "discovered_tool_count": len(raw_tools),
            "approved_tool_count": len(raw_tools),
            "unapproved_tool_count": 0,
            "approved_hashes": [
                {"tool_name": tool.name, "hash_sha256": ah.hash_sha256}
                for tool, ah in synced
            ],
            "last_discovery_time": now_iso,
            "last_trust_time": now_iso,
            "message": f"Server '{server_name}' trusted and registered. Approved baseline created for {len(raw_tools)} tools."
        }

    async def deactivate_server(self, server_name: str, session: Optional[Any] = None) -> Dict[str, Any]:
        """Deactivate server: disconnect session, remove from exposed catalog and graph, preserve DB data."""
        # 1. Update server_config.json
        try:
            config = settings.get_server_config()
            if hasattr(config, "active_servers") and config.active_servers:
                if server_name in config.active_servers:
                    config.active_servers = [s for s in config.active_servers if s != server_name]
                    save_server_config_file(config)
        except Exception as e:
            logger.warning("Could not update active_servers in server_config.json: %s", e)

        # 2. Update ServerDB.is_active = False in PostgreSQL
        from mcpath.backend.persistence.database import set_server_active_state
        try:
            await set_server_active_state(server_name, is_active=False, session=session)
        except Exception as e:
            logger.warning("Could not update ServerDB.is_active in DB: %s", e)

        # 3. Disconnect live session
        await self.disconnect_server(server_name)

        # 4. Remove from capability graph
        self.capability_graph.remove_server(server_name)

        # 5. Recompute exposed tools (removes from catalog & graph, rebuilds paths, persists to DB)
        self.recompute_exposed_tools()

        status = await self.get_server_status(server_name, session=session)
        status["active"] = False
        status["is_active"] = False
        status["connected"] = False
        status["message"] = f"Server '{server_name}' deactivated. Tools removed from active catalog and graph."
        return status

    async def activate_server(self, server_name: str, session: Optional[Any] = None) -> Dict[str, Any]:
        """Activate server: connect, discover tools, rebuild graph, restore to catalog. (DO NOT re-baseline)."""
        config = settings.get_server_config()
        if server_name not in self.server_defs:
            if server_name in config.servers:
                self.server_defs[server_name] = interpolate_server_config(config.servers[server_name], settings)
            else:
                raise ValueError(f"Server '{server_name}' not found in configuration")

        # 1. Connect to downstream server
        connected = await self.connect_server(server_name)
        if not connected:
            state = self.servers_state.get(server_name)
            err = state.error if state else "Connection failed"
            raise DownstreamConnectionError(f"Failed to activate server '{server_name}': {err}")

        # 2. Add to active_servers in server_config.json
        try:
            if hasattr(config, "active_servers") and config.active_servers is not None:
                if server_name not in config.active_servers:
                    config.active_servers.append(server_name)
                    save_server_config_file(config)
        except Exception as e:
            logger.warning("Could not update active_servers in server_config.json: %s", e)

        # 3. Update ServerDB.is_active = True
        from mcpath.backend.persistence.database import set_server_active_state
        try:
            await set_server_active_state(server_name, is_active=True, session=session)
        except Exception as e:
            logger.warning("Could not update ServerDB.is_active in DB: %s", e)

        # 4. Recompute exposed tools, rebuild graph and paths, persist to DB
        self.recompute_exposed_tools()

        status = await self.get_server_status(server_name, session=session)
        status["active"] = True
        status["is_active"] = True
        status["connected"] = True
        status["message"] = f"Server '{server_name}' activated."
        return status

    async def get_server_status(self, server_name: str, session: Optional[Any] = None) -> Dict[str, Any]:
        """Return status for a single server combining live connection and database baseline info."""
        from mcpath.backend.persistence.database import get_server_db_status
        db_stat = None
        try:
            db_statuses = await get_server_db_status(server_name=server_name, session=session)
            db_stat = db_statuses[0] if db_statuses else None
        except Exception as e:
            logger.debug("Could not query DB status for server '%s': %s", server_name, e)

        state = self.servers_state.get(server_name)
        is_connected = bool(state and state.is_connected)
        live_tools_count = len(state.tools) if (state and state.is_connected) else 0

        config = settings.get_server_config()
        active_set = set(getattr(config, "active_servers", None) or ([config.active_server] if config.active_server else []))
        is_active = (server_name in active_set and server_name in config.servers)

        discovered_count = live_tools_count if is_connected else (db_stat.get("discovered_tool_count", 0) if db_stat else 0)
        approved_count = db_stat.get("approved_tool_count", 0) if db_stat else 0
        unapproved_count = max(0, discovered_count - approved_count)

        if db_stat and db_stat.get("trust_status"):
            trust_status = db_stat["trust_status"]
        elif approved_count > 0 and approved_count == discovered_count:
            trust_status = "TRUSTED"
        else:
            trust_status = "UNTRUSTED"

        return {
            "name": server_name,
            "active": is_active,
            "is_active": is_active,
            "connected": is_connected,
            "trust_status": trust_status,
            "discovered_tool_count": discovered_count,
            "approved_tool_count": approved_count,
            "unapproved_tool_count": unapproved_count,
            "last_discovery_time": db_stat.get("last_discovery_time") if db_stat else None,
            "last_trust_time": db_stat.get("last_trust_time") if db_stat else None,
        }

    async def get_all_servers_status(self, session: Optional[Any] = None) -> List[Dict[str, Any]]:
        """Return status for all known downstream MCP servers."""
        from mcpath.backend.persistence.database import get_server_db_status
        config = settings.get_server_config()
        db_statuses = []
        try:
            db_statuses = await get_server_db_status(session=session)
        except Exception as e:
            logger.debug("Could not query DB status in get_all_servers_status: %s", e)

        db_map = {s["name"]: s for s in db_statuses}
        all_names = set(config.servers.keys()) | set(self.servers_state.keys()) | set(self.server_defs.keys()) | set(db_map.keys())

        result = []
        for name in sorted(all_names):
            stat = await self.get_server_status(name, session=session)
            result.append(stat)
        return result
