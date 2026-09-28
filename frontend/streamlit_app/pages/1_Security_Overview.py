"""Security Overview Page.

Section 3 Requirement:
Show active/connected servers, trusted/untrusted servers, tool count,
ALLOW/HOLD/BLOCK counts, recent events, and Stage 1–5 status.
"""

from datetime import datetime
import pandas as pd
import streamlit as st

from frontend.streamlit_app.api_client import client
from frontend.streamlit_app.styles import (
    apply_soc_styles,
    render_header,
    render_decision_badge,
    render_hash_badge
)


def render_page():
    apply_soc_styles()
    render_header("Security Overview", "Zero-Trust MCP Proxy Enforcement Telemetry & Pipeline Status")

    # Fetch live data
    overview = client.get_overview()
    health = client.check_health()
    servers = client.get_servers()

    if not health.get("online"):
        st.error(
            f"🚨 **Backend Offline**: Unable to connect to MCPath API at `{client.base_url}`. "
            f"Error: {health.get('error')}. Please start the backend service."
        )

    # -------------------------------------------------------------------------
    # Top KPI Metrics Grid
    # -------------------------------------------------------------------------
    st.subheader("📊 Interception Metrics")

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.markdown(f"""
        <div class="soc-card soc-card-cyan">
            <div class="soc-card-label">Total Calls</div>
            <div class="soc-card-value">{overview.get('total_calls', 0)}</div>
            <div class="soc-card-subtext">Intercepted by proxy</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="soc-card soc-card-emerald">
            <div class="soc-card-label">Allowed</div>
            <div class="soc-card-value" style="color: #10b981;">{overview.get('allowed_count', 0)}</div>
            <div class="soc-card-subtext">Forwarded to MCP</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="soc-card soc-card-amber">
            <div class="soc-card-label">Held</div>
            <div class="soc-card-value" style="color: #f59e0b;">{overview.get('held_count', 0)}</div>
            <div class="soc-card-subtext">Medium risk review</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="soc-card soc-card-crimson">
            <div class="soc-card-label">Blocked</div>
            <div class="soc-card-value" style="color: #ef4444;">{overview.get('blocked_count', 0)}</div>
            <div class="soc-card-subtext">Zero-trust gates</div>
        </div>
        """, unsafe_allow_html=True)

    with col5:
        st.markdown(f"""
        <div class="soc-card soc-card-crimson">
            <div class="soc-card-label">Hash Violations</div>
            <div class="soc-card-value" style="color: #ef4444;">{overview.get('hash_violations', 0)}</div>
            <div class="soc-card-subtext">Rug-pull / Tamper</div>
        </div>
        """, unsafe_allow_html=True)

    st.write("")

    # -------------------------------------------------------------------------
    # Server & Tool Fleet Overview
    # -------------------------------------------------------------------------
    st.subheader("🖥️ Downstream Server Fleet & Tool Integrity")

    total_srv = overview.get('total_servers', 0)
    active_srv = overview.get('active_servers', 0)
    trusted_srv = overview.get('trusted_servers', 0)
    untrusted_srv = overview.get('untrusted_servers', 0)
    total_tools = overview.get('total_tools', 0)

    # Compute from servers list if overview returned 0
    if isinstance(servers, list) and servers:
        total_srv = len(servers)
        active_srv = sum(1 for s in servers if s.get("active") or s.get("is_active"))
        trusted_srv = sum(1 for s in servers if s.get("trust_status") == "TRUSTED")
        untrusted_srv = total_srv - trusted_srv
        total_tools = sum(s.get("discovered_tool_count", 0) for s in servers)

    fcol1, fcol2, fcol3, fcol4 = st.columns(4)
    with fcol1:
        st.markdown(f"""
        <div class="soc-card soc-card-cyan">
            <div class="soc-card-label">Active / Total Servers</div>
            <div class="soc-card-value">{active_srv} <span style="font-size: 1.1rem; color: #94a3b8;">/ {total_srv}</span></div>
            <div class="soc-card-subtext">Synchronized in DB</div>
        </div>
        """, unsafe_allow_html=True)

    with fcol2:
        st.markdown(f"""
        <div class="soc-card soc-card-emerald">
            <div class="soc-card-label">Trusted Servers</div>
            <div class="soc-card-value" style="color: #10b981;">{trusted_srv}</div>
            <div class="soc-card-subtext">Approved SHA-256 baselines</div>
        </div>
        """, unsafe_allow_html=True)

    with fcol3:
        st.markdown(f"""
        <div class="soc-card soc-card-amber">
            <div class="soc-card-label">Untrusted Servers</div>
            <div class="soc-card-value" style="color: #f59e0b;">{untrusted_srv}</div>
            <div class="soc-card-subtext">Pending Trust & Register</div>
        </div>
        """, unsafe_allow_html=True)

    with fcol4:
        st.markdown(f"""
        <div class="soc-card soc-card-indigo">
            <div class="soc-card-label">Discovered Tools</div>
            <div class="soc-card-value">{total_tools}</div>
            <div class="soc-card-subtext">Cataloged across servers</div>
        </div>
        """, unsafe_allow_html=True)

    st.write("")

    # -------------------------------------------------------------------------
    # 6-Stage Security Pipeline Status
    # -------------------------------------------------------------------------
    st.subheader("🛡️ Sequential 6-Stage Pipeline Status")

    pcol1, pcol2, pcol3 = st.columns(3)
    with pcol1:
        st.markdown("""
        <div class="stage-card stage-card-active">
            <div class="stage-num">STAGE 1 — HARD GATE</div>
            <div class="stage-title">Tool Integrity Hash Check</div>
            <div class="stage-type">Cryptographic Baseline Verification</div>
            <p style="font-size: 0.8rem; color: #94a3b8; margin-top: 8px;">
                Canonical SHA-256 hash comparison against PostgreSQL approved baseline.
                Blocks immediately on <b>HASH_MISMATCH</b> (rug-pull) or <b>NO_APPROVED_BASELINE</b>.
            </p>
            <div style="margin-top: 10px;">
                <span class="badge-trusted">ACTIVE ENFORCEMENT</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with pcol2:
        st.markdown("""
        <div class="stage-card stage-card-active">
            <div class="stage-num">STAGE 2 — SCORED METRIC</div>
            <div class="stage-title">Dynamic Capability Graph</div>
            <div class="stage-type">Causal Path Topology Analysis</div>
            <p style="font-size: 0.8rem; color: #94a3b8; margin-top: 8px;">
                Causal path traversal: <code>Agent → Tool → Resource → Action → Destination</code>.
                Weights data sensitivity (35%), action (40%), exposure (15%), chain risk (10%).
            </p>
            <div style="margin-top: 10px;">
                <span class="badge-trusted">ACTIVE ENFORCEMENT</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with pcol3:
        st.markdown("""
        <div class="stage-card stage-card-active">
            <div class="stage-num">STAGE 3 — SCORED METRIC</div>
            <div class="stage-title">Semantic Intent Risk</div>
            <div class="stage-type">Sentence Embeddings Cosine Sim</div>
            <p style="font-size: 0.8rem; color: #94a3b8; margin-top: 8px;">
                <code>all-MiniLM-L6-v2</code> compares user request prompt against normalized
                tool action phrase. Inverted score clamped to 0–100.
            </p>
            <div style="margin-top: 10px;">
                <span class="badge-trusted">ACTIVE ENFORCEMENT</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.write("")
    pcol4, pcol5, pcol6 = st.columns(3)
    with pcol4:
        st.markdown("""
        <div class="stage-card stage-card-stub">
            <div class="stage-num">STAGE 4 — BASELINE DEVIATION</div>
            <div class="stage-title">Behaviour Deviation Risk</div>
            <div class="stage-type">Operational Trace Baseline (Stub)</div>
            <p style="font-size: 0.8rem; color: #94a3b8; margin-top: 8px;">
                Compares runtime call frequency and parameter variance against historical baseline.
                Returns <code>score=0.0</code> pass-through until Day 9+ implementation.
            </p>
            <div style="margin-top: 10px;">
                <span class="badge-nobaseline">PASS-THROUGH STUB</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with pcol5:
        st.markdown("""
        <div class="stage-card stage-card-stub">
            <div class="stage-num">STAGE 5 — POST-CALL INSPECTION</div>
            <div class="stage-title">Response Risk</div>
            <div class="stage-type">Egress Content Inspection (Stub)</div>
            <p style="font-size: 0.8rem; color: #94a3b8; margin-top: 8px;">
                Inspects tool execution response payload before returning to Claude Desktop.
                Scans for sensitive data leakage. Currently pass-through stub.
            </p>
            <div style="margin-top: 10px;">
                <span class="badge-nobaseline">PASS-THROUGH STUB</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with pcol6:
        st.markdown("""
        <div class="stage-card stage-card-active">
            <div class="stage-num">STAGE 6 — SOLE ENFORCER</div>
            <div class="stage-title">Deterministic Risk Engine</div>
            <div class="stage-type">Threshold Max-Score Evaluation</div>
            <p style="font-size: 0.8rem; color: #94a3b8; margin-top: 8px;">
                Evaluates maximum risk across all active stages:
                <code>&lt;30.0: ALLOW</code> | <code>30.0–70.0: HOLD</code> | <code>&ge;70.0: BLOCK</code>.
                Hash failure forces immediate BLOCK.
            </p>
            <div style="margin-top: 10px;">
                <span class="badge-trusted">ACTIVE ENFORCEMENT</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.write("")

    # -------------------------------------------------------------------------
    # Recent Security Events
    # -------------------------------------------------------------------------
    st.subheader("⚡ Recent Security Interceptions")
    recent_events = overview.get("recent_events") or client.get_events(limit=5)

    if recent_events:
        table_rows = []
        for ev in recent_events:
            table_rows.append({
                "Timestamp": ev.get("timestamp") or ev.get("created_at"),
                "Server": ev.get("server_name"),
                "Tool": ev.get("tool_name"),
                "Decision": ev.get("decision"),
                "Stage 1 Hash": "MATCH" if ev.get("hash_matched") is True else ("MISMATCH" if ev.get("hash_matched") is False else "UNKNOWN"),
                "Reason": ev.get("reason"),
            })

        df = pd.DataFrame(table_rows)
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No security events recorded yet in PostgreSQL.")


if __name__ == "__main__":
    st.set_page_config(page_title="Security Overview - MCPath", layout="wide", page_icon="🛡️")
    render_page()
