"""Pytest configuration and shared fixtures for MCPath."""

import asyncio
import pytest
from mcp.client._memory import create_client_server_memory_streams
from mcp.client.session import ClientSession
from mock_servers.sample_server import app as sample_app
from mcpath.proxy.server import create_proxy_server
from mcpath.proxy.client_manager import DownstreamClientManager
from mcpath.config.settings import ServerDefinition
from mcpath.pipeline.pipeline_runner import PipelineRunner


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()
