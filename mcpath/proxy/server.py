"""MCPath Proxy Server using official MCP Python SDK lowlevel Server.

Acts as an in-line security proxy intercepting requests and responses
between an MCP client (Claude Desktop) and multiple downstream MCP servers.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Callable, Dict, Optional
from mcp.client.session import ClientSession
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
import mcp.types as types
from mcpath.pipeline.pipeline_runner import PipelineRunner
from mcpath.pipeline.stage import PipelineContext
from mcpath.proxy.client_manager import DownstreamClientManager
from mcpath.risk_engine.explainability import format_explanation
from mcpath.risk_engine.models import EnforcementDecision, SecurityEventRecord

logger = logging.getLogger("mcpath.proxy.server")


def create_proxy_server(
    client_manager: DownstreamClientManager,
    downstream_session: Optional[ClientSession] = None,
    pipeline_runner: Optional[PipelineRunner] = None,
    server_name: str = "mcpath-proxy"
) -> Server:
    """Create configured MCP Server instance that routes through the security pipeline."""
    runner = pipeline_runner or PipelineRunner()
    if hasattr(runner, "stage2") and hasattr(runner.stage2, "graph"):
        runner.stage2.graph = client_manager.capability_graph

    call_history: List[str] = []

    # Backward compatibility with tests passing downstream_session directly
    if downstream_session is not None:
        client_manager.register_active_session(
            server_name=client_manager.server_name,
            session=downstream_session
        )

    async def handle_list_tools(
        context: Any,
        params: Optional[types.PaginatedRequestParams] = None
    ) -> types.ListToolsResult:
        """Intercept tools/list, return aggregated catalog from all connected downstream servers."""
        logger.info("Intercepted tools/list request across all downstream servers")
        # If exposed tools is empty, discover from active sessions
        if not client_manager.exposed_tools and client_manager.sessions:
            await client_manager.list_tools()
        result = client_manager.get_aggregated_tools_result()
        logger.info("Returning %d exposed tools from connected servers", len(result.tools))
        return result

    async def handle_call_tool(
        context: Any,
        params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        """Intercept tools/call, route to owning server, execute risk pipeline in 2 phases, enforce decision."""
        exposed_name = params.name
        arguments = params.arguments or {}
        timestamp = datetime.now(timezone.utc).isoformat()
        logger.info("Intercepted tools/call for exposed tool='%s'", exposed_name)

        # 1. Resolve owning downstream server and original tool name
        exposed_tool = client_manager.get_exposed_tool(exposed_name)
        if not exposed_tool:
            # Try a discovery refresh once
            try:
                await client_manager.list_tools()
                exposed_tool = client_manager.get_exposed_tool(exposed_name)
            except Exception as e:
                logger.warning("Could not refresh tool discovery for '%s': %s", exposed_name, e)

        if not exposed_tool:
            logger.error("Fail-closed: Tool '%s' not found on any active downstream server", exposed_name)
            return types.CallToolResult(
                is_error=True,
                content=[types.TextContent(
                    type="text",
                    text=f"MCPath Security Gate: Tool '{exposed_name}' is not registered or owning server is unavailable."
                )]
            )

        owning_server = exposed_tool.server_name
        original_name = exposed_tool.original_name
        tool_def = client_manager.get_tool_definition(original_name, server_name=owning_server) or exposed_tool.raw_definition

        logger.info(
            "Routing exposed tool='%s' -> downstream server='%s', original_tool='%s'",
            exposed_name,
            owning_server,
            original_name
        )

        user_prompt = None
        if hasattr(params, "meta") and params.meta:
            user_prompt = params.meta.get("user_prompt") or params.meta.get("prompt")
        if not user_prompt and isinstance(arguments, dict):
            user_prompt = arguments.get("_user_prompt") or arguments.get("user_prompt")

        event = SecurityEventRecord(
            timestamp=timestamp,
            server_name=owning_server,
            tool_name=original_name,
            arguments=arguments,
            user_prompt=user_prompt,
        )

        call_history.append(original_name)
        pipeline_ctx = PipelineContext(
            server_name=owning_server,
            tool_name=original_name,
            arguments=arguments,
            user_prompt=user_prompt,
            tool_definition=tool_def,
            call_history=list(call_history),
            event_record=event
        )

        # 2. Phase 1: Pre-execution pipeline (Stage 1 Hash Check + Stages 2-4 + Risk Engine Phase 1)
        evaluated_event = await runner.run_pre_call(pipeline_ctx)

        if evaluated_event.decision in (EnforcementDecision.BLOCK, EnforcementDecision.HOLD):
            explanation = format_explanation(evaluated_event)
            logger.warning("EXECUTION BLOCKED by MCPath Proxy Security Gate:\n%s", explanation)
            return types.CallToolResult(
                is_error=True,
                content=[types.TextContent(type="text", text=explanation)]
            )

        # 3. Forward call to the correct downstream MCP server ONLY if decision is ALLOW
        target_session = client_manager.get_session(owning_server)
        if not target_session:
            logger.error("Downstream session for server '%s' is not active", owning_server)
            return types.CallToolResult(
                is_error=True,
                content=[types.TextContent(
                    type="text",
                    text=f"MCPath Security Error: Downstream server '{owning_server}' is disconnected or unavailable."
                )]
            )

        try:
            downstream_result = await target_session.call_tool(
                name=original_name,
                arguments=arguments
            )
        except Exception as e:
            logger.error("Downstream execution failed for '%s:%s': %s", owning_server, original_name, str(e))
            return types.CallToolResult(
                is_error=True,
                content=[types.TextContent(type="text", text=f"Downstream Tool Execution Error: {e}")]
            )

        # 4. Phase 2: Post-execution pipeline (Stage 5 Response Risk + Risk Engine Phase 2 final)
        pipeline_ctx.tool_response = downstream_result
        final_event = await runner.run_post_call(pipeline_ctx)

        if final_event.decision in (EnforcementDecision.BLOCK, EnforcementDecision.HOLD):
            explanation = format_explanation(final_event)
            logger.warning("EXECUTION BLOCKED post-execution by response inspection:\n%s", explanation)
            return types.CallToolResult(
                is_error=True,
                content=[types.TextContent(type="text", text=explanation)]
            )

        logger.info("Execution allowed and forwarded successfully for '%s:%s'", owning_server, original_name)
        return downstream_result

    proxy_server = Server(
        name=server_name,
        version="0.1.0",
        instructions="MCPath Zero-Trust Security Proxy",
        on_list_tools=handle_list_tools,
        on_call_tool=handle_call_tool
    )
    proxy_server.handle_call_tool = handle_call_tool
    proxy_server.handle_list_tools = handle_list_tools

    return proxy_server


async def run_stdio_proxy(
    client_manager: DownstreamClientManager,
    pipeline_runner: Optional[PipelineRunner] = None
) -> None:
    """Run MCPath Proxy on stdio for seamless integration with Claude Desktop / MCP hosts."""
    from mcpath.proxy.control import ProxyControlServer
    logger.info("Starting MCPath stdio proxy...")
    control_server = ProxyControlServer(client_manager)
    await control_server.start()
    try:
        async with client_manager.session_context():
            proxy_server = create_proxy_server(
                client_manager=client_manager,
                pipeline_runner=pipeline_runner
            )
            async with stdio_server() as (read_stream, write_stream):
                logger.info("MCPath Proxy is listening on stdio for MCP client requests")
                await proxy_server.run(
                    read_stream,
                    write_stream,
                    proxy_server.create_initialization_options(),
                    raise_exceptions=True
                )
    finally:
        await control_server.stop()
