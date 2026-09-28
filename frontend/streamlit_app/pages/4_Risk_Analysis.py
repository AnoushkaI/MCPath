"""Risk Analysis Page.

Section 6 Requirement:
Display separate Stage 1 hash status and Stage 2–5 scores plus Risk Engine decision.
Clearly show NOT EXECUTED/NOT COMPUTED when an earlier stage blocks.
Never replace the separate scores with a single opaque trust score.
"""

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
    render_header("Risk Analysis", "Attributable Multi-Stage Graded Risk Pipeline & Deterministic Enforcement")

    st.markdown("""
    <div style="background-color: #111827; border: 1px solid #1e293b; border-left: 4px solid #818cf8; border-radius: 6px; padding: 12px 18px; margin-bottom: 20px;">
        <span style="font-weight: 700; color: #c7d2fe;">ARCHITECTURAL BOUNDARY:</span>
        <span style="color: #94a3b8; font-size: 0.88rem;">
            MCPath computes separate, explainable risk scores across each isolated pipeline stage.
            Scores are <b>never averaged into a single opaque trust score</b>.
            When Stage 1 fails, subsequent stages are <b>NOT EXECUTED</b>.
        </span>
    </div>
    """, unsafe_allow_html=True)

    events = client.get_events(limit=100)
    if not events:
        st.warning("No security events found in database to analyze.")
        return

    # -------------------------------------------------------------------------
    # Event Selector for Deep Dive
    # -------------------------------------------------------------------------
    st.subheader("🎯 Deep-Dive Event Risk Pipeline Inspection")

    event_labels = []
    for ev in events:
        dec = ev.get("decision", "UNKNOWN")
        srv = ev.get("server_name", "")
        tool = ev.get("tool_name", "")
        eid = ev.get("event_id", "")
        event_labels.append(f"{eid} | [{dec}] {srv} ➔ {tool}")

    selected_idx = st.selectbox(
        "Choose an Intercepted Security Event to Inspect:",
        range(len(event_labels)),
        format_func=lambda i: event_labels[i]
    )

    selected_event = events[selected_idx]
    event_id = selected_event.get("event_id")

    # Fetch complete event details (stage results, intent eval, etc.)
    detail = client.get_event_detail(event_id) or selected_event
    scores = detail.get("scores", {}) or {}
    h_matched = detail.get("hash_matched")
    hard_gate = detail.get("hard_gate_triggered")
    decision = detail.get("decision", "UNKNOWN")
    reason = detail.get("reason", "")

    is_stage1_blocked = (h_matched is False or hard_gate in ("Stage1HashCheck", "NO_APPROVED_BASELINE", "HASH_MISMATCH"))

    # -------------------------------------------------------------------------
    # Visual Stage-by-Stage Sequential Flow
    # -------------------------------------------------------------------------
    st.write("#### Sequential 6-Stage Execution Flow")

    col_s1, col_s2, col_s3, col_s4, col_s5, col_s6 = st.columns(6)

    # Stage 1: Tool Integrity Hash
    with col_s1:
        if h_matched is True:
            s1_val = "MATCH"
            s1_color = "#10b981"
            s1_sub = "Passed Hard Gate"
        elif h_matched is False:
            s1_val = "MISMATCH"
            s1_color = "#ef4444"
            s1_sub = "🚨 Rug-Pull Detected"
        else:
            s1_val = "NO BASELINE"
            s1_color = "#ef4444"
            s1_sub = "🚨 Unapproved Tool"

        st.markdown(f"""
        <div class="soc-card" style="border-top: 3px solid {s1_color}; text-align: center; padding: 12px 8px;">
            <div class="soc-card-label" style="font-size: 0.7rem;">STAGE 1: INTEGRITY</div>
            <div style="font-size: 1.1rem; font-weight: 700; color: {s1_color}; margin: 6px 0;">{s1_val}</div>
            <div class="soc-card-subtext" style="font-size: 0.7rem;">{s1_sub}</div>
        </div>
        """, unsafe_allow_html=True)

    # Stage 2: Capability Risk
    with col_s2:
        cap_val = scores.get("capability_risk")
        if is_stage1_blocked and cap_val is None:
            s2_text = "NOT EXECUTED"
            s2_color = "#94a3b8"
            s2_sub = "Blocked by Stage 1"
        elif cap_val is not None:
            s2_text = f"{cap_val:.1f}"
            s2_color = "#ef4444" if cap_val >= 70 else ("#f59e0b" if cap_val >= 30 else "#10b981")
            s2_sub = "Score (0–100)"
        else:
            s2_text = "NOT COMPUTED"
            s2_color = "#94a3b8"
            s2_sub = "N/A"

        st.markdown(f"""
        <div class="soc-card" style="border-top: 3px solid {s2_color}; text-align: center; padding: 12px 8px;">
            <div class="soc-card-label" style="font-size: 0.7rem;">STAGE 2: CAPABILITY</div>
            <div style="font-size: 1.1rem; font-weight: 700; color: {s2_color}; margin: 6px 0;">{s2_text}</div>
            <div class="soc-card-subtext" style="font-size: 0.7rem;">{s2_sub}</div>
        </div>
        """, unsafe_allow_html=True)

    # Stage 3: Intent Risk
    with col_s3:
        intent_val = scores.get("intent_risk")
        if is_stage1_blocked and intent_val is None:
            s3_text = "NOT EXECUTED"
            s3_color = "#94a3b8"
            s3_sub = "Blocked by Stage 1"
        elif intent_val is not None:
            s3_text = f"{intent_val:.1f}"
            s3_color = "#ef4444" if intent_val >= 70 else ("#f59e0b" if intent_val >= 30 else "#10b981")
            s3_sub = "Cosine Inverted"
        else:
            s3_text = "NOT COMPUTED"
            s3_color = "#94a3b8"
            s3_sub = "N/A"

        st.markdown(f"""
        <div class="soc-card" style="border-top: 3px solid {s3_color}; text-align: center; padding: 12px 8px;">
            <div class="soc-card-label" style="font-size: 0.7rem;">STAGE 3: INTENT</div>
            <div style="font-size: 1.1rem; font-weight: 700; color: {s3_color}; margin: 6px 0;">{s3_text}</div>
            <div class="soc-card-subtext" style="font-size: 0.7rem;">{s3_sub}</div>
        </div>
        """, unsafe_allow_html=True)

    # Stage 4: Behaviour Deviation
    with col_s4:
        beh_val = scores.get("behaviour_risk")
        if is_stage1_blocked:
            s4_text = "NOT EXECUTED"
            s4_color = "#94a3b8"
            s4_sub = "Blocked by Stage 1"
        else:
            s4_text = f"{beh_val:.1f}" if beh_val is not None else "0.0"
            s4_color = "#94a3b8"
            s4_sub = "Pass-Through Stub"

        st.markdown(f"""
        <div class="soc-card" style="border-top: 3px solid {s4_color}; text-align: center; padding: 12px 8px;">
            <div class="soc-card-label" style="font-size: 0.7rem;">STAGE 4: BEHAVIOUR</div>
            <div style="font-size: 1.1rem; font-weight: 700; color: {s4_color}; margin: 6px 0;">{s4_text}</div>
            <div class="soc-card-subtext" style="font-size: 0.7rem;">{s4_sub}</div>
        </div>
        """, unsafe_allow_html=True)

    # Stage 5: Response Risk
    with col_s5:
        resp_val = scores.get("response_risk")
        if is_stage1_blocked or decision == "BLOCK":
            s5_text = "NOT EXECUTED"
            s5_color = "#94a3b8"
            s5_sub = "Pre-Call Blocked"
        else:
            s5_text = f"{resp_val:.1f}" if resp_val is not None else "0.0"
            s5_color = "#94a3b8"
            s5_sub = "Post-Call Stub"

        st.markdown(f"""
        <div class="soc-card" style="border-top: 3px solid {s5_color}; text-align: center; padding: 12px 8px;">
            <div class="soc-card-label" style="font-size: 0.7rem;">STAGE 5: RESPONSE</div>
            <div style="font-size: 1.1rem; font-weight: 700; color: {s5_color}; margin: 6px 0;">{s5_text}</div>
            <div class="soc-card-subtext" style="font-size: 0.7rem;">{s5_sub}</div>
        </div>
        """, unsafe_allow_html=True)

    # Stage 6: Deterministic Risk Engine Decision
    with col_s6:
        if decision == "ALLOW":
            d_color = "#10b981"
            d_icon = "● ALLOW"
        elif decision == "HOLD":
            d_color = "#f59e0b"
            d_icon = "▲ HOLD"
        else:
            d_color = "#ef4444"
            d_icon = "✖ BLOCK"

        st.markdown(f"""
        <div class="soc-card" style="border-top: 3px solid {d_color}; text-align: center; padding: 12px 8px;">
            <div class="soc-card-label" style="font-size: 0.7rem;">RISK ENGINE</div>
            <div style="font-size: 1.1rem; font-weight: 700; color: {d_color}; margin: 6px 0;">{d_icon}</div>
            <div class="soc-card-subtext" style="font-size: 0.7rem;">Final Enforcement</div>
        </div>
        """, unsafe_allow_html=True)

    st.write("")

    # Detailed Explainability Box
    st.info(f"📋 **Risk Engine Decision Reason:** {reason}")

    # Display Stage 3 Intent details if available
    intent_eval = detail.get("intent_evaluation")
    if intent_eval:
        st.write("#### Stage 3 Semantic Intent Evaluation Details")
        st.markdown(f"""
        - **User Request:** `{intent_eval.get('user_request')}`
        - **Tool Action Representation:** `{intent_eval.get('tool_action')}`
        - **Cosine Similarity:** `{intent_eval.get('cosine_similarity', 0.0):.4f}` (Threshold: `{intent_eval.get('similarity_threshold', 0.70)}`)
        - **Derived Intent Risk Score:** `{intent_eval.get('intent_risk_score', 0.0):.2f}`
        - **Classification:** `{intent_eval.get('classification', 'LOW')}`
        """)

    st.markdown("---")

    # -------------------------------------------------------------------------
    # Comparative Multi-Stage Evaluation Matrix across Events
    # -------------------------------------------------------------------------
    st.subheader("📊 Comparative Multi-Stage Interception Matrix")
    st.caption("Displays distinct per-stage scores across recent runtime events. Early blocks show NOT EXECUTED.")

    matrix_rows = []
    for ev in events:
        ev_id = ev.get("event_id")
        sc = ev.get("scores", {}) or {}
        hm = ev.get("hash_matched")
        hg = ev.get("hard_gate_triggered")
        dec = ev.get("decision")

        # Stage 1 Hash status
        if hm is True:
            s1_str = "MATCH"
        elif hm is False:
            s1_str = "MISMATCH"
        else:
            s1_str = "NO BASELINE"

        # Check if stage 1 blocked
        if hm is False or hg:
            s2_str = "NOT EXECUTED"
            s3_str = "NOT EXECUTED"
            s4_str = "NOT EXECUTED"
            s5_str = "NOT EXECUTED"
        else:
            c_score = sc.get("capability_risk")
            i_score = sc.get("intent_risk")
            b_score = sc.get("behaviour_risk")
            r_score = sc.get("response_risk")

            s2_str = f"{c_score:.1f}" if c_score is not None else "0.0"
            s3_str = f"{i_score:.1f}" if i_score is not None else "0.0"
            s4_str = f"{b_score:.1f}" if b_score is not None else "0.0"
            s5_str = f"{r_score:.1f}" if r_score is not None else "0.0"

        # Max risk calculation
        num_scores = [v for v in [sc.get("capability_risk"), sc.get("intent_risk"), sc.get("behaviour_risk"), sc.get("response_risk")] if v is not None]
        max_risk_str = f"{max(num_scores):.1f}" if num_scores else ("100.0 (Hard Gate)" if hm is False else "0.0")

        matrix_rows.append({
            "Event ID": ev_id,
            "Timestamp": ev.get("timestamp"),
            "Server": ev.get("server_name"),
            "Tool": ev.get("tool_name"),
            "Stage 1 Hash": s1_str,
            "Stage 2 (Cap)": s2_str,
            "Stage 3 (Intent)": s3_str,
            "Stage 4 (Beh)": s4_str,
            "Stage 5 (Resp)": s5_str,
            "Max Score": max_risk_str,
            "Decision": dec,
        })

    df_matrix = pd.DataFrame(matrix_rows)
    st.dataframe(df_matrix, use_container_width=True, hide_index=True)


if __name__ == "__main__":
    st.set_page_config(page_title="Risk Analysis - MCPath", layout="wide", page_icon="⚖️")
    render_page()
