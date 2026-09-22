"""MCPath Proxy Server using official MCP Python SDK lowlevel Server.

Acts as an in-line security proxy intercepting requests and responses
between an MCP client (Claude Desktop) and downstream MCP servers.
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
    downstream_session: ClientSession,
    pipeline_runner: Optional[PipelineRunner] = None,
    server_name: str = "mcpath-proxy"
) -> Server:
    """Create configured MCP Server instance that routes through the security pipeline."""
    runner = pipeline_runner or PipelineRunner()

    async def handle_list_tools(
        context: Any,
        params: Optional[types.PaginatedRequestParams] = None
    ) -> types.ListToolsResult:
        """Intercept tools/list, cache definitions for runtime integrity checks, forward to client."""
        logger.info("Intercepted tools/list request for server '%s'", client_manager.server_name)
        result = await client_manager.list_tools(downstream_session, params=params)
        logger.info("Discovered %d tools from downstream server '%s'", len(result.tools), client_manager.server_name)
        return result

    async def handle_call_tool(
        context: Any,
        params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        """Intercept tools/call, execute 6-stage risk pipeline, enforce decision."""
        tool_name = params.name
        arguments = params.arguments or {}
        timestamp = datetime.now(timezone.utc).isoformat()
        logger.info("Intercepted tools/call for tool='%s' on server='%s'", tool_name, client_manager.server_name)

        # Look up tool definition from discovery cache
        tool_def = client_manager.get_tool_definition(tool_name)
        if not tool_def:
            # If not in memory cache, query downstream once to discover current definition
            try:
                await client_manager.list_tools(downstream_session)
                tool_def = client_manager.get_tool_definition(tool_name)
            except Exception as e:
                logger.warning("Could not refresh tool discovery for '%s': %s", tool_name, e)

        event = SecurityEventRecord(
            timestamp=timestamp,
            server_name=client_manager.server_name,
            tool_name=tool_name,
            arguments=arguments,
        )

        pipeline_ctx = PipelineContext(
            server_name=client_manager.server_name,
            tool_name=tool_name,
            arguments=arguments,
            tool_definition=tool_def,
            event_record=event
        )

        # 1. Pre-execution pipeline (Stage 1 Hash Check + Stages 2-4 + Risk Engine)
        evaluated_event = await runner.run_pre_call(pipeline_ctx)

        if evaluated_event.decision == EnforcementDecision.BLOCK:
            explanation = format_explanation(evaluated_event)
            logger.warning("EXECUTION BLOCKED by MCPath Proxy Security Gate:\n%s", explanation)
            return types.CallToolResult(
                is_error=True,
                content=[types.TextContent(type="text", text=explanation)]
            )

        # 2. Forward call to downstream MCP server ONLY if allowed
        try:
            downstream_result = await client_manager.call_tool(
                downstream_session,
                name=tool_name,
                arguments=arguments
            )
        except Exception as e:
            logger.error("Downstream execution failed for '%s': %s", tool_name, str(e))
            return types.CallToolResult(
                is_error=True,
                content=[types.TextContent(type="text", text=f"Downstream Tool Execution Error: {e}")]
            )

        # 3. Post-execution pipeline (Stage 5 Response Risk + Final Risk Engine)
        pipeline_ctx.tool_response = downstream_result
        final_event = await runner.run_post_call(pipeline_ctx)

        if final_event.decision == EnforcementDecision.BLOCK:
            explanation = format_explanation(final_event)
            logger.warning("EXECUTION BLOCKED post-execution by response inspection:\n%s", explanation)
            return types.CallToolResult(
                is_error=True,
                content=[types.TextContent(type="text", text=explanation)]
            )

        logger.info("Execution allowed and forwarded successfully for '%s'", tool_name)
        return downstream_result

    # Passthrough handlers for resources and prompts
    async def handle_list_resources(context: Any, params: Optional[types.PaginatedRequestParams] = None) -> types.ListResourcesResult:
        return await downstream_session.list_resources(params=params)

    async def handle_read_resource(context: Any, params: types.ReadResourceRequestParams) -> types.ReadResourceResult:
        return await downstream_session.read_resource(params.uri)

    async def handle_list_prompts(context: Any, params: Optional[types.PaginatedRequestParams] = None) -> types.ListPromptsResult:
        return await downstream_session.list_prompts(params=params)

    async def handle_get_prompt(context: Any, params: types.GetPromptRequestParams) -> types.GetPromptResult:
        return await downstream_session.get_prompt(params.name, arguments=params.arguments)

    proxy_server = Server(
        name=server_name,
        version="0.1.0",
        instructions="MCPath Zero-Trust Security Proxy",
        on_list_tools=handle_list_tools,
        on_call_tool=handle_call_tool,
        on_list_resources=handle_list_resources,
        on_read_resource=handle_read_resource,
        on_list_prompts=handle_list_prompts,
        on_get_prompt=handle_get_prompt
    )

    return proxy_server


async def run_stdio_proxy(
    client_manager: DownstreamClientManager,
    pipeline_runner: Optional[PipelineRunner] = None
) -> None:
    """Run MCPath Proxy on stdio for seamless integration with Claude Desktop / MCP hosts."""
    logger.info("Starting MCPath stdio proxy...")
    async with client_manager.session_context() as downstream_session:
        proxy_server = create_proxy_server(
            client_manager=client_manager,
            downstream_session=downstream_session,
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
