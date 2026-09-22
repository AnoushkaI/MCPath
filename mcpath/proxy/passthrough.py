"""Passthrough proxy coordinator.

Loads active server configuration and manages the proxy lifecycle.
"""

import logging
from typing import Optional
from mcpath.config.settings import settings, ServerDefinition, interpolate_server_config
from mcpath.core.exceptions import ConfigurationError
from mcpath.pipeline.pipeline_runner import PipelineRunner
from mcpath.proxy.client_manager import DownstreamClientManager
from mcpath.proxy.server import run_stdio_proxy

logger = logging.getLogger("mcpath.proxy.passthrough")


class PassthroughProxy:
    """Coordinates lifecycle of MCPath passthrough proxy."""

    def __init__(
        self,
        server_name: Optional[str] = None,
        server_def: Optional[ServerDefinition] = None,
        pipeline_runner: Optional[PipelineRunner] = None
    ):
        server_config = settings.get_server_config()
        self.server_name = server_name or server_config.active_server

        if server_def:
            self.server_def = server_def
        elif self.server_name in server_config.servers:
            raw_def = server_config.servers[self.server_name]
            # Expand ${VAR} placeholders so machine-specific paths and credentials
            # from .env are resolved before the subprocess is launched.
            self.server_def = interpolate_server_config(raw_def, settings)
        else:
            raise ConfigurationError(
                f"Server '{self.server_name}' not found in configuration: {list(server_config.servers.keys())}"
            )

        self.client_manager = DownstreamClientManager(
            server_def=self.server_def,
            server_name=self.server_name
        )
        self.pipeline_runner = pipeline_runner or PipelineRunner()

    async def run(self):
        """Start the stdio proxy loop."""
        logger.info("Starting passthrough proxy for server: %s", self.server_name)
        await run_stdio_proxy(
            client_manager=self.client_manager,
            pipeline_runner=self.pipeline_runner
        )
