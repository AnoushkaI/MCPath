"""Live Runtime Monitor Page.

Modern SaaS Cybersecurity Runtime Interception Monitor.
Polls backend PostgreSQL event data and displays real Claude Desktop runtime events:
timestamp, server, tool, user request, Stage 1 integrity, capability path ID & match status,
graded risk scores (Stages 2-5), final decisions, and forensic drill-down.
"""

from datetime import datetime
import json
from typing import Any, Dict, Optional
import pandas as pd
import streamlit as st

from frontend.streamlit_app.api_client import client
from frontend.streamlit_app.styles import (
    apply_soc_styles,
    render_header,
    render_decision_badge,
    render_hash_badge,
    render_match_status_badge,
    render_path_id_badge,
    render_severity_badge
)


def format_score(score: Optional[float]) -> str:
    """Format risk score or display N/A."""
    if score is None:
        return "N/A"
    return f"{score:.1f}"


def render_event_inspector(event_detail: Dict[str, Any]):
    """Render full event details in an expandable cybersecurity SOC drawer."""
    if not event_detail:
        return

    st.markdown("---")
    st.subheader(f"🔍 Event Forensic Inspection: `{event_detail.get('event_id')}`")

    decision = event_detail.get("decision", "UNKNOWN")
    reason = event_detail.get("reason", "No reason provided")
    is_blocked = (decision == "BLOCK")

    # Banner alert for blocked events
    if is_blocked:
        st.markdown(f"""
        <div class="soc-alert-box">
            <div class="soc-alert-title">🚨 MCPath ZERO-TRUST ENFORCEMENT BLOCK</div>
            <div class="soc-alert-desc"><b>Reason:</b> {reason}</div>
            <div style="font-size: 0.78rem; margin-top: 6px; color: #fca5a5;">
                Hard Gate: <b>{event_detail.get('hard_gate_triggered') or 'Risk Engine Threshold'}</b> | 
                Action Taken: <b>{event_detail.get('action_taken', 'Blocked')}</b>
            </div>
        </div>
        """, unsafe_allow_html=True)

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f"**Timestamp:** `{event_detail.get('timestamp')}`")
        st.markdown(f"**Server:** `{event_detail.get('server_name')}`")
        st.markdown(f"**Tool:** `{event_detail.get('tool_name')}`")
    with c2:
        st.markdown(f"**Decision:** {render_decision_badge(decision)}", unsafe_allow_html=True)
        h_matched = event_detail.get("hash_matched")
        h_status = "MATCH" if h_matched is True else ("MISMATCH" if h_matched is False else "NO_APPROVED_BASELINE")
        st.markdown(f"**Stage 1 Hash:** {render_hash_badge(h_status)}", unsafe_allow_html=True)
    with c3:
        m_status = event_detail.get("match_status") or ("MATCHED" if event_detail.get("runtime_path_id") else "UNKNOWN")
        pid = event_detail.get("runtime_path_id")
        st.markdown(f"**Capability Match:** {render_match_status_badge(m_status)}", unsafe_allow_html=True)
        st.markdown(f"**Runtime Path ID:** {render_path_id_badge(pid)}", unsafe_allow_html=True)
    with c4:
        st.markdown(f"**Action Taken:** `{event_detail.get('action_taken')}`")
        st.markdown(f"**Hard Gate:** `{event_detail.get('hard_gate_triggered') or 'None'}`")

    # Tabs for deep dive
    tab_prompt, tab_cap, tab_stages, tab_intent, tab_hashes, tab_args = st.tabs([
        "💬 User Request & Prompt",
        "🗺️ Stage 2 Capability Path",
        "⚖️ Stage-by-Stage Breakdown",
        "🧠 Stage 3 Intent Details",
        "🔑 Hashes & Integrity",
        "📦 Invocation Arguments"
    ])

    with tab_prompt:
        st.markdown("#### User Request (Claude Desktop Prompt)")
        prompt_text = event_detail.get("user_prompt")
        if prompt_text:
            st.info(prompt_text)
        else:
            st.write("*(No user prompt text associated with this event — standard tool call)*")

    with tab_cap:
        st.markdown("#### Stage 2 Runtime Capability Path Mapping")
        matched_cap_path = event_detail.get("matched_capability_path")
        runtime_pid = event_detail.get("runtime_path_id")
        match_st = event_detail.get("match_status") or ("MATCHED" if runtime_pid else "UNKNOWN")

        st.markdown(f"""
        <div style="background-color: #0f172a; border: 1px solid #1e293b; border-radius: 6px; padding: 14px 18px; margin-bottom: 14px;">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;">
                <div>
                    <b>Match Status:</b> {render_match_status_badge(match_st)}
                    <span style="margin-left: 10px;"><b>Runtime Path ID:</b> {render_path_id_badge(runtime_pid)}</span>
                </div>
                <div>
                    <span style="font-size: 0.75rem; color: #94a3b8;">
                        {'(Precomputed Path Matched)' if runtime_pid else '(No Modelled Graph Path)'}
                    </span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        if matched_cap_path:
            p_nodes = matched_cap_path.get("path_nodes", [])
            p_edges = matched_cap_path.get("path_edges", [])
            p_score = matched_cap_path.get("path_risk_score", 0.0)
            p_class = matched_cap_path.get("classification", "LOW")
            p_override = matched_cap_path.get("is_critical_override", False)
            p_expl = matched_cap_path.get("explanation", "")

            st.write(f"**Causal Node Chain:** `{' ➔ '.join(p_nodes)}`")
            st.write(f"**Risk Score:** `{p_score:.1f}` ({render_severity_badge(p_class)}) | **Critical Override:** `{'🚨 YES' if p_override else 'No'}`", unsafe_allow_html=True)
            st.write(f"**Policy Explanation:** {p_expl}")

            # Direct action to highlight this path in the Capability Graph page
            if st.button("🗺️ Open & Highlight Path in Capability Graph", key=f"view_path_{event_detail.get('event_id')}"):
                st.session_state["selected_path_id"] = runtime_pid
                st.success(f"Path `{runtime_pid}` selected! Switch to Capability Paths page in sidebar to view.")
        else:
            if match_st == "UNMODELED":
                st.warning(f"⚠️ Tool `{event_detail.get('tool_name')}` is registered, but has no compatible causal graph path to a sink. Fail-secure elevated score applied.")
            elif match_st == "UNKNOWN":
                st.error(f"🚨 Tool `{event_detail.get('tool_name')}` is completely unrecognized in the capability graph. Fail-secure elevated score applied.")
            else:
                st.info("No precomputed capability path associated with this event.")

    with tab_stages:
        st.markdown("#### Sequential Pipeline Execution Breakdown")
        stage_results = event_detail.get("stage_results", [])
        if stage_results:
            stage_rows = []
            for sr in stage_results:
                stage_rows.append({
                    "Stage #": sr.get("stage_number"),
                    "Stage Name": sr.get("stage_name"),
                    "Passed": "✔ Passed" if sr.get("passed") else "✖ Blocked",
                    "Hard Block": "🚨 YES" if sr.get("hard_block") else "No",
                    "Score": format_score(sr.get("score")),
                    "Explanation": sr.get("explanation"),
                })
            st.table(stage_rows)
        else:
            scores = event_detail.get("scores", {}) or {}
            col_s1, col_s2, col_s3, col_s4, col_s5 = st.columns(5)
            with col_s1:
                st.metric("Stage 1 (Hash)", "MATCH" if event_detail.get("hash_matched") else "MISMATCH")
            with col_s2:
                st.metric("Stage 2 (Cap)", format_score(scores.get("capability_risk")))
            with col_s3:
                st.metric("Stage 3 (Intent)", format_score(scores.get("intent_risk")))
            with col_s4:
                st.metric("Stage 4 (Beh)", format_score(scores.get("behaviour_risk")))
            with col_s5:
                st.metric("Stage 5 (Resp)", format_score(scores.get("response_risk")))

    with tab_intent:
        st.markdown("#### Stage 3 Semantic Intent Evaluation")
        intent_eval = event_detail.get("intent_evaluation")
        if intent_eval:
            i_col1, i_col2, i_col3 = st.columns(3)
            with i_col1:
                st.metric("Cosine Similarity", f"{intent_eval.get('cosine_similarity', 0.0):.4f}")
            with i_col2:
                st.metric("Intent Risk Score", f"{intent_eval.get('intent_risk_score', 0.0):.2f}")
            with i_col3:
                st.metric("Classification", intent_eval.get("classification", "UNKNOWN"))

            st.write(f"**Similarity Threshold:** `{intent_eval.get('similarity_threshold', 0.70)}` | **Policy Version:** `{intent_eval.get('policy_version', '1.0.0')}`")
            st.write(f"**Tool Action Text:** `{intent_eval.get('tool_action')}`")
            st.write(f"**Explanation:** {intent_eval.get('explanation')}")
        else:
            st.info("No dedicated Stage 3 Intent record found (Stage 3 may have been bypassed due to earlier hard block).")

    with tab_hashes:
        st.markdown("#### Stage 1 Cryptographic Hash Verification")
        exp_h = event_detail.get("expected_hash") or "NO_APPROVED_BASELINE"
        obs_h = event_detail.get("observed_hash") or "NOT_COMPUTED"
        matched = event_detail.get("hash_matched")

        st.write("**Approved Hash (Baseline):**")
        st.code(exp_h, language="text")
        st.write("**Observed Hash (Canonical):**")
        if matched is False:
            st.markdown(f'<div class="hash-mismatch-code">{obs_h}</div>', unsafe_allow_html=True)
            st.error("🚨 HASH MISMATCH DETECTED: Tool definition at runtime does not match approved baseline (Rug-Pull).")
        else:
            st.code(obs_h, language="text")

    with tab_args:
        st.markdown("#### Invocation Arguments")
        args = event_detail.get("arguments")
        if args:
            st.json(args)
        else:
            st.write("*(No arguments provided)*")


def render_page():
    apply_soc_styles()
    render_header("Live Runtime Monitor", "Real-Time Interception Telemetry, Pipeline Decisions & Capability Mapping")

    # Filter controls
    ctrl_col1, ctrl_col2, ctrl_col3, ctrl_col4 = st.columns([2, 2, 2, 2])
    with ctrl_col1:
        server_filter = st.selectbox(
            "Filter Server",
            ["All", "filesystem", "git", "postgres-mcp", "rugpull-test", "email-server"],
            index=0
        )
    with ctrl_col2:
        decision_filter = st.selectbox(
            "Filter Decision",
            ["All", "ALLOW", "HOLD", "BLOCK"],
            index=0
        )
    with ctrl_col3:
        limit = st.slider("Events Limit", min_value=10, max_value=100, value=30, step=10)
    with ctrl_col4:
        st.write("")
        st.write("")
        if st.button("🔄 Refresh Telemetry", use_container_width=True):
            st.rerun()

    events = client.get_events(
        limit=limit,
        server=server_filter,
        decision=decision_filter
    )

    now_str = datetime.now().strftime("%H:%M:%S")
    st.caption(f"⚡ Live feed active — Last refreshed at {now_str}")

    if not events:
        st.info("No runtime security events found matching the selected filters.")
        return

    # Prepare summary statistics
    total = len(events)
    n_allow = sum(1 for e in events if e.get("decision") == "ALLOW")
    n_hold = sum(1 for e in events if e.get("decision") == "HOLD")
    n_block = sum(1 for e in events if e.get("decision") == "BLOCK")

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric("Total Interceptions", total)
    with m2:
        st.metric("Allowed Calls", f"{n_allow} ({n_allow/total*100:.0f}%)" if total else "0")
    with m3:
        st.metric("Held Calls", f"{n_hold} ({n_hold/total*100:.0f}%)" if total else "0")
    with m4:
        st.metric("Blocked Calls", f"{n_block} ({n_block/total*100:.0f}%)" if total else "0")

    # Table data formatting
    table_data = []
    for ev in events:
        scores = ev.get("scores", {}) or {}
        cap = scores.get("capability_risk")
        intent = scores.get("intent_risk")

        h_matched = ev.get("hash_matched")
        h_str = "MATCH" if h_matched is True else ("MISMATCH" if h_matched is False else "NO BASELINE")

        if h_matched is False or ev.get("hard_gate_triggered"):
            cap_str = "NOT EXECUTED" if cap is None else format_score(cap)
            intent_str = "NOT EXECUTED" if intent is None else format_score(intent)
        else:
            cap_str = format_score(cap)
            intent_str = format_score(intent)

        m_status = ev.get("match_status") or ("MATCHED" if ev.get("runtime_path_id") else "UNKNOWN")
        pid = ev.get("runtime_path_id") or "None"

        table_data.append({
            "Event ID": ev.get("event_id"),
            "Timestamp": ev.get("timestamp"),
            "Server": ev.get("server_name"),
            "Tool": ev.get("tool_name"),
            "Decision": ev.get("decision"),
            "Match Status": m_status,
            "Runtime Path ID": pid,
            "Stage 1": h_str,
            "Cap Score": cap_str,
            "Intent Score": intent_str,
            "User Request": (ev.get("user_prompt") or "")[:35] + ("..." if len(ev.get("user_prompt") or "") > 35 else ""),
            "Reason": ev.get("reason"),
        })

    df = pd.DataFrame(table_data)
    st.dataframe(df, use_container_width=True, hide_index=True)

    # Event Selector for Drill-down inspection
    event_ids = [e.get("event_id") for e in events]
    selected_id = st.selectbox("Select Event for Deep-Dive SOC Inspection:", event_ids, index=0)
    if selected_id:
        detail = client.get_event_detail(selected_id)
        if detail:
            render_event_inspector(detail)


if __name__ == "__main__":
    st.set_page_config(page_title="Live Runtime Monitor - MCPath", layout="wide", page_icon="📡")
    render_page()
