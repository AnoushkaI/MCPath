"""Tests verifying MCPath Streamlit Frontend pages, components, and API client integration."""

import importlib
import pytest
from httpx import AsyncClient, ASGITransport
from mcpath.backend.app import app
from frontend.streamlit_app.api_client import MCPathAPIClient
from frontend.streamlit_app.styles import (
    render_decision_badge,
    render_hash_badge,
    render_trust_badge,
)


def test_frontend_modules_import():
    """Verify all Streamlit frontend pages and components import cleanly without syntax or dependency errors."""
    modules_to_test = [
        "frontend.streamlit_app.api_client",
        "frontend.streamlit_app.styles",
        "frontend.streamlit_app.components.graph_viewer",
        "frontend.streamlit_app.pages.1_Security_Overview",
        "frontend.streamlit_app.pages.2_Live_Runtime_Monitor",
        "frontend.streamlit_app.pages.3_Capability_Graph",
        "frontend.streamlit_app.pages.4_Risk_Analysis",
        "frontend.streamlit_app.pages.5_MCP_Servers",
        "frontend.streamlit_app.pages.6_Security_Events",
        "frontend.streamlit_app.pages.7_Tool_Baseline_Inspector",
    ]
    for mod_name in modules_to_test:
        mod = importlib.import_module(mod_name)
        assert (
            hasattr(mod, "render_page")
            or hasattr(mod, "render_capability_graph_html")
            or hasattr(mod, "MCPathAPIClient")
            or hasattr(mod, "apply_soc_styles")
        )


def test_style_badges():
    """Verify cybersecurity SOC badge rendering functions."""
    # Decision badges
    allow_badge = render_decision_badge("ALLOW")
    assert "badge-allow" in allow_badge
    assert "ALLOW" in allow_badge

    hold_badge = render_decision_badge("HOLD")
    assert "badge-hold" in hold_badge
    assert "HOLD" in hold_badge

    block_badge = render_decision_badge("BLOCK")
    assert "badge-block" in block_badge
    assert "BLOCK" in block_badge

    # Hash badges
    match_badge = render_hash_badge("MATCH")
    assert "badge-match" in match_badge

    mismatch_badge = render_hash_badge("HASH_MISMATCH")
    assert "badge-mismatch" in mismatch_badge

    nobaseline_badge = render_hash_badge("NO_APPROVED_BASELINE")
    assert "badge-nobaseline" in nobaseline_badge

    # Trust badges
    trusted_badge = render_trust_badge("TRUSTED")
    assert "badge-trusted" in trusted_badge

    untrusted_badge = render_trust_badge("UNTRUSTED")
    assert "badge-untrusted" in untrusted_badge


@pytest.mark.asyncio
async def test_backend_frontend_api_contract():
    """Verify all endpoints required by the Streamlit frontend are served correctly by FastAPI."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Health check
        res_health = await ac.get("/health")
        assert res_health.status_code == 200
        assert res_health.json()["status"] == "ok"

        # 2. Security Overview (Page 1)
        res_overview = await ac.get("/api/overview")
        assert res_overview.status_code == 200
        overview_data = res_overview.json()
        assert "total_calls" in overview_data
        assert "allowed_count" in overview_data
        assert "blocked_count" in overview_data
        assert "held_count" in overview_data
        assert "active_servers" in overview_data
        assert "stages" in overview_data
        assert "stage_1" in overview_data["stages"]

        # 3. Security Events (Pages 2 & 6)
        res_events = await ac.get("/api/events?limit=10")
        assert res_events.status_code == 200
        events_list = res_events.json()
        assert isinstance(events_list, list)

        if events_list:
            first_event_id = events_list[0]["event_id"]
            res_detail = await ac.get(f"/api/events/{first_event_id}")
            assert res_detail.status_code == 200
            detail_data = res_detail.json()
            assert detail_data["event_id"] == first_event_id
            assert "stage_results" in detail_data

        # 4. Capability Graph & Paths (Page 3)
        res_graph = await ac.get("/api/capabilities/graph")
        assert res_graph.status_code == 200
        graph_data = res_graph.json()
        assert "nodes" in graph_data
        assert "edges" in graph_data

        res_paths = await ac.get("/api/capabilities/paths")
        assert res_paths.status_code == 200
        assert isinstance(res_paths.json(), list)

        res_caps = await ac.get("/api/capabilities/tools")
        assert res_caps.status_code == 200
        assert isinstance(res_caps.json(), list)

        # 5. MCP Servers (Page 5)
        res_servers = await ac.get("/api/servers")
        assert res_servers.status_code == 200
        servers_list = res_servers.json()
        assert isinstance(servers_list, list)
        server_names = {s["name"] for s in servers_list}
        # Check required servers are present in inventory
        for req_srv in ["filesystem", "git", "rugpull-test", "email-server"]:
            assert req_srv in server_names, f"Required server '{req_srv}' missing from inventory"

        # 6. Tool/Baseline Inspector (Page 7)
        res_inspector = await ac.get("/api/hashes/inspector")
        assert res_inspector.status_code == 200
        inspector_list = res_inspector.json()
        assert isinstance(inspector_list, list)

        if inspector_list:
            item = inspector_list[0]
            assert "tool_name" in item
            assert "current_hash" in item
            assert "hash_status" in item
            assert "trust_state" in item
            assert item["hash_status"] in ("MATCH", "HASH_MISMATCH", "NO_APPROVED_BASELINE")
