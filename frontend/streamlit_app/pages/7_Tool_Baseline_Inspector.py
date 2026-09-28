"""Tool/Baseline Inspector Page.

Section 8 Requirement:
Show discovered tools, current hash, approved hash, hash status, trust state, capability metadata,
discovery time and trust time.
Make the rug-pull HASH_MISMATCH result clearly visible.
"""

import json
import pandas as pd
import streamlit as st

from frontend.streamlit_app.api_client import client
from frontend.streamlit_app.styles import (
    apply_soc_styles,
    render_header,
    render_hash_badge,
    render_trust_badge
)


def render_page():
    apply_soc_styles()
    render_header("Tool/Baseline Inspector", "Stage 1 Cryptographic Baseline Verification & Rug-Pull Detection")

    # Fetch tool inspector records from backend
    inspector_data = client.get_tool_baseline_inspector()

    if not inspector_data:
        st.warning("No discovered tools found in database.")
        return

    # Check for rug-pull HASH_MISMATCH
    mismatches = [t for t in inspector_data if t.get("hash_status") == "HASH_MISMATCH"]
    if mismatches:
        for m in mismatches:
            st.markdown(f"""
            <div class="soc-alert-box">
                <div class="soc-alert-title">
                    🚨 RUG-PULL ATTACK DETECTED: HASH MISMATCH on <code>{m.get('server_name')}:{m.get('tool_name')}</code>
                </div>
                <div class="soc-alert-desc">
                    The tool definition at runtime does not match the approved SHA-256 cryptographic baseline in PostgreSQL.
                    This indicates schema parameter tampering, prompt injection modifications, or unapproved tool code changes.
                </div>
                <div style="margin-top: 10px; font-family: monospace; font-size: 0.78rem;">
                    Approved Baseline: <span style="color: #6ee7b7;">{m.get('approved_hash')}</span><br>
                    Current Observed: <span style="color: #fca5a5;">{m.get('current_hash')}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)

    # Top KPI Metrics
    total = len(inspector_data)
    matches = sum(1 for t in inspector_data if t.get("hash_status") == "MATCH")
    mismatch_cnt = len(mismatches)
    no_baseline = sum(1 for t in inspector_data if t.get("hash_status") == "NO_APPROVED_BASELINE")

    k1, k2, k3, k4 = st.columns(4)
    with k1:
        st.metric("Total Cataloged Tools", total)
    with k2:
        st.metric("Approved Matches", matches)
    with k3:
        st.metric("Hash Mismatches (Rug-Pulls)", mismatch_cnt)
    with k4:
        st.metric("Unapproved / No Baseline", no_baseline)

    st.write("")

    # Filter controls
    servers_list = sorted(list({t.get("server_name") for t in inspector_data if t.get("server_name")}))
    fcol1, fcol2, fcol3 = st.columns([2, 2, 2])
    with fcol1:
        server_filter = st.selectbox("Filter Server", ["All"] + servers_list, index=0)
    with fcol2:
        status_filter = st.selectbox(
            "Filter Hash Status",
            ["All", "MATCH", "HASH_MISMATCH", "NO_APPROVED_BASELINE"],
            index=0
        )
    with fcol3:
        search_tool = st.text_input("Search Tool Name", placeholder="e.g. read_file")

    filtered_data = inspector_data
    if server_filter != "All":
        filtered_data = [t for t in filtered_data if t.get("server_name") == server_filter]
    if status_filter != "All":
        filtered_data = [t for t in filtered_data if t.get("hash_status") == status_filter]
    if search_tool.strip():
        filtered_data = [t for t in filtered_data if search_tool.lower() in t.get("tool_name", "").lower()]

    st.subheader(f"📋 Tool Integrity Manifest ({len(filtered_data)} tools)")

    table_rows = []
    for t in filtered_data:
        cur_h = t.get("current_hash", "")
        appr_h = t.get("approved_hash", "") or "NO_BASELINE"

        table_rows.append({
            "Server": t.get("server_name"),
            "Tool Name": t.get("tool_name"),
            "Hash Status": t.get("hash_status"),
            "Trust State": t.get("trust_state"),
            "Current SHA-256 (Observed)": cur_h[:16] + "..." if len(cur_h) > 16 else cur_h,
            "Approved SHA-256 (Baseline)": appr_h[:16] + "..." if len(appr_h) > 16 else appr_h,
            "Discovery Time": t.get("discovery_time") or "N/A",
            "Trust Approval Time": t.get("trust_time") or "Never",
        })

    df = pd.DataFrame(table_rows)
    st.dataframe(df, use_container_width=True, hide_index=True)

    st.markdown("---")

    # -------------------------------------------------------------------------
    # Deep-Dive Tool Baseline & Capability Inspection
    # -------------------------------------------------------------------------
    st.subheader("🔍 Deep-Dive Tool & Cryptographic Baseline Inspector")

    tool_options = [f"{t.get('server_name')}:{t.get('tool_name')}" for t in filtered_data]
    if tool_options:
        selected_tool_label = st.selectbox("Select Tool to Inspect:", tool_options, index=0)
        selected_tool = next(t for t in filtered_data if f"{t.get('server_name')}:{t.get('tool_name')}" == selected_tool_label)

        t_name = selected_tool.get("tool_name")
        s_name = selected_tool.get("server_name")
        h_status = selected_tool.get("hash_status")
        trust_st = selected_tool.get("trust_state")
        cur_sha = selected_tool.get("current_hash")
        app_sha = selected_tool.get("approved_hash")
        desc = selected_tool.get("description") or "No description"
        schema = selected_tool.get("input_schema") or {}
        cap = selected_tool.get("capability")

        # Top summary card
        sc1, sc2, sc3 = st.columns(3)
        with sc1:
            st.markdown(f"**Server:** `{s_name}`")
            st.markdown(f"**Tool:** `{t_name}`")
        with sc2:
            st.markdown(f"**Hash Status:** {render_hash_badge(h_status)}", unsafe_allow_html=True)
            st.markdown(f"**Trust State:** {render_trust_badge(trust_st)}", unsafe_allow_html=True)
        with sc3:
            st.markdown(f"**Discovered At:** `{selected_tool.get('discovery_time')}`")
            st.markdown(f"**Approved At:** `{selected_tool.get('trust_time') or 'Never'}`")

        # Hash Comparison Cards
        st.write("")
        st.write("#### SHA-256 Hash Comparison")
        hc1, hc2 = st.columns(2)
        with hc1:
            st.markdown("**Approved Baseline Hash (PostgreSQL Approved):**")
            if app_sha:
                st.code(app_sha, language="text")
            else:
                st.warning("⚠️ No approved baseline exists for this tool.")

        with hc2:
            st.markdown("**Current Observed Hash (Canonicalized Definition):**")
            if h_status == "HASH_MISMATCH":
                st.markdown(f'<div class="hash-mismatch-code">{cur_sha}</div>', unsafe_allow_html=True)
                st.error("🚨 Tampering Detected: Current hash does not match approved baseline!")
            else:
                st.code(cur_sha, language="text")

        # Capability & Schema tabs
        tab_schema, tab_cap, tab_action = st.tabs(["📄 Tool Definition & Schema", "🕸️ Capability Metadata", "⚙️ Baseline Admin"])

        with tab_schema:
            st.markdown(f"**Description:** {desc}")
            st.markdown("**Input Schema:**")
            st.json(schema)

        with tab_cap:
            if cap:
                st.markdown("**Inferred Capability Policy Attributes (Stage 2):**")
                cc1, cc2, cc3 = st.columns(3)
                with cc1:
                    st.markdown(f"**Resource Target:** `{cap.get('resource_type')}`")
                    st.markdown(f"**Operation:** `{cap.get('operation')}`")
                with cc2:
                    st.markdown(f"**Action Type:** `{cap.get('action')}`")
                    st.markdown(f"**Destination:** `{cap.get('destination')}`")
                with cc3:
                    st.markdown(f"**Data Sensitivity:** `{cap.get('data_sensitivity')}`")
                    st.markdown(f"**Action Sensitivity:** `{cap.get('action_sensitivity')}`")
                    st.markdown(f"**External Exposure:** `{cap.get('external_exposure')}`")
            else:
                st.info("No capability mapping found in database for this tool.")

        with tab_action:
            st.markdown("**Manual Baseline Approval (SOC Admin):**")
            st.caption("Explicitly approve this tool definition, updating the approved baseline SHA-256 in PostgreSQL.")
            if st.button("Approve Current Hash as Baseline", key=f"appr_{s_name}_{t_name}"):
                with st.spinner("Recording approved SHA-256 baseline..."):
                    tool_def = {"name": t_name, "description": desc, "inputSchema": schema}
                    ok, res = client.approve_tool_hash(s_name, t_name, tool_def, approved_by="soc_analyst:dashboard")
                    if ok:
                        st.success(f"Tool '{t_name}' approved successfully! Hash updated.")
                        st.rerun()
                    else:
                        st.error(f"Approval failed: {res}")


if __name__ == "__main__":
    st.set_page_config(page_title="Tool/Baseline Inspector - MCPath", layout="wide", page_icon="🔍")
    render_page()
