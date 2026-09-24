"""Tests verifying FastAPI backend routes and persistence skeleton."""

import pytest
from httpx import AsyncClient, ASGITransport
from mcpath.backend.app import app


@pytest.mark.asyncio
async def test_backend_health():
    """Verify backend health check returns status ok."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["service"] == "mcpath-backend"


@pytest.mark.asyncio
async def test_backend_overview_and_servers():
    """Verify overview metrics and server inventory routes."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res_overview = await client.get("/api/overview")
        assert res_overview.status_code == 200
        assert "total_calls" in res_overview.json()

        res_servers = await client.get("/api/servers")
        assert res_servers.status_code == 200
        assert isinstance(res_servers.json(), list)

        res_dict = await client.get("/api/servers?format=dict")
        assert res_dict.status_code == 200
        assert "active_server" in res_dict.json()
