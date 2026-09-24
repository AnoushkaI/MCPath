"""Passthrough proxy coordinator.

Loads active downstream server configuration and coordinates multi-server proxy lifecycle.
"""

import logging
from typing import Dict, List, Optional
from mcpath.config.settings import settings, ServerDefinition, interpolate_server_config
from mcpath.core.exceptions import ConfigurationError
from mcpath.pipeline.pipeline_runner import PipelineRunner
from mcpath.proxy.client_manager import DownstreamClientManager
from mcpath.proxy.server import run_stdio_proxy

logger = logging.getLogger("mcpath.proxy.passthrough")


class PassthroughProxy:
    """Coordinates lifecycle of MCPath multi-server security proxy."""

    def __init__(
        self,
        server_names: Optional[List[str]] = None,
        server_name: Optional[str] = None,
        server_def: Optional[ServerDefinition] = None,
        pipeline_runner: Optional[PipelineRunner] = None
    ):
        server_config = settings.get_server_config()

        # Determine target servers
        if server_names:
            targets = server_names
        elif server_name:
            targets = [server_name]
        elif hasattr(server_config, "active_servers") and server_config.active_servers:
            targets = server_config.active_servers
        else:
            targets = [server_config.active_server]

        self.server_defs: Dict[str, ServerDefinition] = {}

        if server_def and server_name:
            self.server_defs[server_name] = server_def
        else:
            for s_name in targets:
                if s_name in server_config.servers:
                    raw_def = server_config.servers[s_name]
                    # Expand ${VAR} placeholders so machine-specific paths and credentials
                    # from .env are resolved before subprocesses launch.
                    interpolated_def = interpolate_server_config(raw_def, settings)
                    self.server_defs[s_name] = interpolated_def
                else:
                    logger.warning(
                        "Configured server '%s' not defined in servers map: %s",
                        s_name,
                        list(server_config.servers.keys())
                    )

        if not self.server_defs:
            raise ConfigurationError(
                f"No valid servers configured for MCPath proxy. Requested: {targets}, Available: {list(server_config.servers.keys())}"
            )

        self.client_manager = DownstreamClientManager(server_defs=self.server_defs)
        self.pipeline_runner = pipeline_runner or PipelineRunner()

    async def run(self):
        """Start the stdio proxy loop across all configured downstream servers."""
        from mcpath.backend.persistence.database import reconcile_server_active_states
        try:
            await reconcile_server_active_states()
        except Exception as e:
            logger.debug("Server active state reconciliation on proxy run skipped: %s", e)

        logger.info(
            "Starting MCPath multi-server proxy for servers: %s",
            list(self.server_defs.keys())
        )
        await run_stdio_proxy(
            client_manager=self.client_manager,
            pipeline_runner=self.pipeline_runner
        )
