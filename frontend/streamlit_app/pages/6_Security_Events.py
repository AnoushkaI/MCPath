"""Security Events Audit Log Page.

Comprehensive zero-trust audit log querying PostgreSQL security_events table.
Provides full filterability, keyword search, capability path mapping, and forensic drill-down.
"""

from typing import Any, Dict, List, Optional
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


def render_page():
    apply_soc_styles()
    render_header("Security Events", "Zero-Trust Interception Audit Log, Forensic Explainability & Path Tracing")

    # Filter controls
    fcol1, fcol2, fcol3, fcol4 = st.columns([2, 2, 3, 1])
    with fcol1:
        server_filter = st.selectbox(
            "Filter Server",
            ["All", "filesystem", "git", "postgres-mcp", "rugpull-test", "email-server"],
            index=0
        )
    with fcol2:
        decision_filter = st.selectbox(
            "Filter Decision",
            ["All", "ALLOW", "HOLD", "BLOCK"],
            index=0
        )
    with fcol3:
        search_query = st.text_input("Search (Tool, Prompt, Reason, ID, Path)", placeholder="Search keyword or Path ID...")
    with fcol4:
        limit = st.selectbox("Limit", [25, 50, 100, 200], index=1)

    events = client.get_events(
        limit=limit,
        server=server_filter,
        decision=decision_filter
    )

    if search_query.strip():
        q = search_query.lower()
        events = [
            e for e in events
            if q in (e.get("tool_name") or "").lower()
            or q in (e.get("user_prompt") or "").lower()
            or q in (e.get("reason") or "").lower()
            or q in (e.get("event_id") or "").lower()
            or q in (e.get("runtime_path_id") or "").lower()
        ]

    st.write(f"Showing **{len(events)}** security events")

    if not events:
        st.info("No security events match the current criteria.")
        return

    # Dataframe display
    table_rows = []
    for ev in events:
        h_matched = ev.get("hash_matched")
        h_status = "MATCH" if h_matched is True else ("MISMATCH" if h_matched is False else "NO BASELINE")
        m_status = ev.get("match_status") or ("MATCHED" if ev.get("runtime_path_id") else "UNKNOWN")

        table_rows.append({
            "Event ID": ev.get("event_id"),
            "Timestamp": ev.get("timestamp"),
            "Server": ev.get("server_name"),
            "Tool": ev.get("tool_name"),
            "Decision": ev.get("decision"),
            "Match Status": m_status,
            "Runtime Path ID": ev.get("runtime_path_id") or "None",
            "Hash Status": h_status,
            "Prompt": (ev.get("user_prompt") or "")[:40] + ("..." if len(ev.get("user_prompt") or "") > 40 else ""),
            "Reason": ev.get("reason"),
            "Action Taken": ev.get("action_taken"),
        })

    df = pd.DataFrame(table_rows)
    st.dataframe(df, use_container_width=True, hide_index=True)

    # Export Button
    csv = df.to_csv(index=False).encode('utf-8')
    st.download_button(
        "📥 Export Audit Log to CSV",
        csv,
        "mcpath_security_events.csv",
        "text/csv",
        key='download-csv'
    )

    st.markdown("---")

    # -------------------------------------------------------------------------
    # Selected Event Deep-Dive
    # -------------------------------------------------------------------------
    st.subheader("🔍 Selected Event Forensic Inspection")
    event_ids = [e.get("event_id") for e in events]
    selected_id = st.selectbox("Select Event ID to view full forensic record:", event_ids, index=0)

    if selected_id:
        detail = client.get_event_detail(selected_id)
        if detail:
            dec = detail.get("decision", "UNKNOWN")
            is_blocked = (dec == "BLOCK")

            if is_blocked:
                st.markdown(f"""
                <div class="soc-alert-box">
                    <div class="soc-alert-title">🚨 ZERO-TRUST INTERCEPTION BLOCK</div>
                    <div class="soc-alert-desc"><b>Reason:</b> {detail.get('reason')}</div>
                    <div style="font-size: 0.8rem; margin-top: 4px; color: #fecaca;">
                        Hard Gate: <b>{detail.get('hard_gate_triggered') or 'Risk Engine Threshold'}</b> | 
                        Action Taken: <b>{detail.get('action_taken')}</b>
                    </div>
                </div>
                """, unsafe_allow_html=True)

            dcol1, dcol2, dcol3, dcol4 = st.columns(4)
            with dcol1:
                st.markdown(f"**Event ID:** `{detail.get('event_id')}`")
                st.markdown(f"**Server Name:** `{detail.get('server_name')}`")
                st.markdown(f"**Tool Name:** `{detail.get('tool_name')}`")

            with dcol2:
                st.markdown(f"**Decision:** {render_decision_badge(dec)}", unsafe_allow_html=True)
                st.markdown(f"**Timestamp:** `{detail.get('timestamp')}`")
                st.markdown(f"**Action Taken:** `{detail.get('action_taken')}`")

            with dcol3:
                hm = detail.get("hash_matched")
                h_str = "MATCH" if hm is True else ("MISMATCH" if hm is False else "NO_APPROVED_BASELINE")
                st.markdown(f"**Stage 1 Hash:** {render_hash_badge(h_str)}", unsafe_allow_html=True)
                st.markdown(f"**Hard Gate Triggered:** `{detail.get('hard_gate_triggered') or 'None'}`")

            with dcol4:
                m_stat = detail.get("match_status") or ("MATCHED" if detail.get("runtime_path_id") else "UNKNOWN")
                st.markdown(f"**Capability Match:** {render_match_status_badge(m_stat)}", unsafe_allow_html=True)
                st.markdown(f"**Runtime Path ID:** {render_path_id_badge(detail.get('runtime_path_id'))}", unsafe_allow_html=True)

            st.write("")
            tab_path, tab1, tab2, tab3 = st.tabs([
                "🗺️ Related Capability Path",
                "💬 Prompt & Parameters",
                "📊 Graded Risk Scores",
                "🔑 Cryptographic Hashes"
            ])

            with tab_path:
                matched_path = detail.get("matched_capability_path")
                pid = detail.get("runtime_path_id")
                if matched_path:
                    st.markdown(f"""
                    <div style="background-color: #0f172a; border: 1px solid #1e293b; border-left: 4px solid #38bdf8; border-radius: 6px; padding: 14px 18px; margin-bottom: 12px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;">
                            <div>
                                <span style="font-family: monospace; font-size: 0.9rem; color: #38bdf8; font-weight: 700;">🔑 PATH ID: {matched_path.get('path_id')}</span>
                                <span style="margin-left: 10px; color: #f8fafc; font-weight: 600;">Tool: <code>{matched_path.get('tool_name')}</code></span>
                            </div>
                            <div>
                                {render_severity_badge(matched_path.get('classification'), matched_path.get('path_risk_score'))}
                                {'<span class="badge-block">🚨 CRITICAL OVERRIDE</span>' if matched_path.get('is_critical_override') else ''}
                            </div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                    st.write(f"**Causal Chain:** `{' ➔ '.join(matched_path.get('path_nodes', []))}`")
                    st.write(f"**Explanation:** {matched_path.get('explanation')}")

                    if st.button("🗺️ Inspect Path in Capability Graph", key=f"sec_view_path_{detail.get('event_id')}"):
                        st.session_state["selected_path_id"] = pid
                        st.success(f"Path `{pid}` selected! Navigate to Capability Paths in the sidebar.")
                else:
                    if pid:
                        st.info(f"Associated with Runtime Path ID: `{pid}` (precomputed path details query returned no cached row).")
                    else:
                        st.info("No matching precomputed capability path associated with this event (Call was evaluated as UNKNOWN or UNMODELED).")

            with tab1:
                st.markdown("**User Request:**")
                st.info(detail.get("user_prompt") or "*(No user prompt text)*")
                st.markdown("**Arguments Payload:**")
                st.json(detail.get("arguments") or {})

            with tab2:
                scores = detail.get("scores", {}) or {}
                sc1, sc2, sc3, sc4 = st.columns(4)
                sc1.metric("Capability Risk", f"{scores.get('capability_risk', 0.0):.1f}" if scores.get('capability_risk') is not None else "N/A")
                sc2.metric("Intent Risk", f"{scores.get('intent_risk', 0.0):.1f}" if scores.get('intent_risk') is not None else "N/A")
                sc3.metric("Behaviour Risk", f"{scores.get('behaviour_risk', 0.0):.1f}" if scores.get('behaviour_risk') is not None else "N/A")
                sc4.metric("Response Risk", f"{scores.get('response_risk', 0.0):.1f}" if scores.get('response_risk') is not None else "N/A")

                stage_results = detail.get("stage_results", [])
                if stage_results:
                    st.write("**Granular Stage Logs:**")
                    st.table([
                        {
                            "Stage": sr.get("stage_name"),
                            "Passed": "✔" if sr.get("passed") else "✖",
                            "Score": sr.get("score"),
                            "Explanation": sr.get("explanation")
                        }
                        for sr in stage_results
                    ])

            with tab3:
                exp = detail.get("expected_hash") or "NO_APPROVED_BASELINE"
                obs = detail.get("observed_hash") or "NOT_COMPUTED"
                st.write("**Expected Hash (Approved Baseline):**")
                st.code(exp, language="text")
                st.write("**Observed Hash (Canonical at Runtime):**")
                if detail.get("hash_matched") is False:
                    st.markdown(f'<div class="hash-mismatch-code">{obs}</div>', unsafe_allow_html=True)
                else:
                    st.code(obs, language="text")


if __name__ == "__main__":
    st.set_page_config(page_title="Security Events - MCPath", layout="wide", page_icon="📜")
    render_page()
