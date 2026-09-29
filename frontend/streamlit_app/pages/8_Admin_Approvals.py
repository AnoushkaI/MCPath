"""Admin Approvals Page.

Human-in-the-Loop Zero-Trust Approval Workflow for calls held by the MCPath Risk Engine.
Provides instant Approve / Reject controls, masked argument inspection, real-time countdown
timer, and complete audit history.
"""

from datetime import datetime, timezone
import json
from typing import Optional
import pandas as pd
import streamlit as st

from frontend.streamlit_app.api_client import client
from frontend.streamlit_app.styles import (
    apply_soc_styles,
    render_header,
    render_decision_badge,
)


def parse_created_datetime(ts_str: Optional[str]) -> Optional[datetime]:
    """Parse ISO timestamp string into UTC datetime."""
    if not ts_str:
        return None
    try:
        clean = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def render_page():
    apply_soc_styles()
    
    header_col1, header_col2 = st.columns([3, 1])
    with header_col1:
        render_header(
            "Administrator Approval Queue",
            "Human-in-the-Loop Zero-Trust Review for Held Tool Invocations"
        )
    with header_col2:
        st.write("")
        if st.button("🔄 Refresh Queue", use_container_width=True):
            st.rerun()

    _render_live_approval_queue()


@st.fragment(run_every="2s")
def _render_live_approval_queue():
    now = datetime.now(timezone.utc)
    timeout_duration = 30.0  # Configured 30s deadline

    # 1. Fetch approvals data from backend API
    all_approvals = client.get_approvals(limit=100)
    pending_approvals = [a for a in all_approvals if a.get("status") == "PENDING"]
    resolved_approvals = [a for a in all_approvals if a.get("status") != "PENDING"]

    # 2. Top Summary KPI Cards
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f"""
        <div class="soc-card soc-card-amber">
            <div class="soc-card-label">Pending Review</div>
            <div class="soc-card-value" style="color: #f59e0b;">{len(pending_approvals)}</div>
            <div class="soc-card-subtext">Awaiting admin action</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        approved_count = len([a for a in resolved_approvals if a.get("status") == "APPROVED"])
        st.markdown(f"""
        <div class="soc-card soc-card-emerald">
            <div class="soc-card-label">Approved & Forwarded</div>
            <div class="soc-card-value" style="color: #10b981;">{approved_count}</div>
            <div class="soc-card-subtext">Executed downstream exactly once</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        rejected_count = len([a for a in resolved_approvals if a.get("status") == "REJECTED"])
        st.markdown(f"""
        <div class="soc-card soc-card-rose">
            <div class="soc-card-label">Rejected / Blocked</div>
            <div class="soc-card-value" style="color: #f43f5e;">{rejected_count}</div>
            <div class="soc-card-subtext">Denied by administrator</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        timed_out_count = len([a for a in resolved_approvals if a.get("status") == "TIMED_OUT"])
        st.markdown(f"""
        <div class="soc-card soc-card-cyan">
            <div class="soc-card-label">Timed Out</div>
            <div class="soc-card-value">{timed_out_count}</div>
            <div class="soc-card-subtext">Auto-closed at 30s deadline</div>
        </div>
        """, unsafe_allow_html=True)

    now_str = datetime.now().strftime("%H:%M:%S")
    st.caption(f"⚡ Live queue polling active (2s interval) — Last polled at {now_str}")

    # -------------------------------------------------------------------------
    # Active Pending Approvals Section
    # -------------------------------------------------------------------------
    st.subheader(f"⏳ Pending Review Queue ({len(pending_approvals)})")

    if not pending_approvals:
        st.success("✅ **No pending approvals in queue.** All runtime tool calls have been evaluated and resolved.")
    else:
        st.markdown(f"""
        <div style="background: rgba(245, 158, 11, 0.18); border: 2px solid #f59e0b; border-radius: 8px; padding: 14px 18px; margin-bottom: 20px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-size: 1.1rem; font-weight: 700; color: #f59e0b;">
                    🚨 ACTION REQUIRED: {len(pending_approvals)} Tool Invocation(s) Currently Held for Review!
                </span>
                <span style="background: #f59e0b; color: #0b0f19; font-weight: 800; padding: 3px 10px; border-radius: 4px; font-size: 0.8rem;">
                    WAITING FOR APPROVAL
                </span>
            </div>
            <div style="color: #f8fafc; font-size: 0.85rem; margin-top: 6px;">
                Claude Desktop is currently paused awaiting your security decision. Approve to resume and forward downstream exactly once; Block to reject immediately.
            </div>
        </div>
        """, unsafe_allow_html=True)

        for item in pending_approvals:
            appr_id = item.get("approval_id")
            event_id = item.get("event_id")
            server = item.get("server_name")
            tool = item.get("tool_name")
            score = float(item.get("risk_score", 0.0) or 0.0)
            reason = item.get("reason", "Held for review")
            args_data = item.get("arguments") or {}
            created_at = item.get("created_at")

            # Calculate remaining time against 30s deadline
            dt_created = parse_created_datetime(created_at)
            if dt_created:
                elapsed = (now - dt_created).total_seconds()
                remaining_sec = max(0, int(timeout_duration - elapsed))
            else:
                remaining_sec = 30

            if remaining_sec > 15:
                badge_bg = "rgba(16, 185, 129, 0.2)"
                badge_border = "#10b981"
                badge_color = "#10b981"
                timer_text = f"⏳ {remaining_sec}s remaining (Deadline: 30s)"
            elif remaining_sec > 5:
                badge_bg = "rgba(245, 158, 11, 0.2)"
                badge_border = "#f59e0b"
                badge_color = "#f59e0b"
                timer_text = f"⏳ {remaining_sec}s remaining — Action needed soon"
            else:
                badge_bg = "rgba(239, 68, 68, 0.2)"
                badge_border = "#ef4444"
                badge_color = "#ef4444"
                timer_text = f"⏰ {remaining_sec}s remaining — Auto-timeout imminent"

            with st.container():
                st.markdown(f"""
                <div style="background: rgba(30, 41, 59, 0.85); border: 1px solid rgba(245, 158, 11, 0.5); border-radius: 8px; padding: 18px; margin-bottom: 16px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
                        <span style="font-size: 1.15rem; font-weight: 700; color: #f8fafc;">
                            🛠️ Server: <code>{server}</code> : <span style="color: #38bdf8;">{tool}</span>
                        </span>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <span style="background: #f59e0b25; color: #f59e0b; padding: 4px 12px; border-radius: 6px; font-weight: 700; font-size: 0.95rem; border: 1px solid #f59e0b77;">
                                Risk Score: {score:.1f} (HOLD)
                            </span>
                            <span style="background: {badge_bg}; color: {badge_color}; border: 1px solid {badge_border}; padding: 4px 12px; border-radius: 6px; font-weight: 800; font-size: 0.92rem;">
                                {timer_text}
                            </span>
                        </div>
                    </div>
                    <div style="color: #94a3b8; font-size: 0.85rem; margin-top: 8px;">
                        <b>Approval ID:</b> <code>{appr_id}</code> &nbsp;|&nbsp;
                        <b>Event ID:</b> <code>{event_id}</code> &nbsp;|&nbsp;
                        <b>Created At:</b> {created_at}
                    </div>
                    <div style="color: #e2e8f0; font-size: 0.92rem; margin-top: 10px; background: rgba(15, 23, 42, 0.6); padding: 8px 12px; border-radius: 4px; border-left: 3px solid #f59e0b;">
                        <b>Hold Reason:</b> {reason}
                    </div>
                </div>
                """, unsafe_allow_html=True)

                # Visual countdown progress bar
                progress_val = min(1.0, max(0.0, remaining_sec / timeout_duration))
                st.progress(progress_val)

                col_args, col_btn1, col_btn2 = st.columns([3, 1, 1])
                with col_args:
                    with st.expander("🔍 Inspect Invocation Arguments (Sensitive Values Masked)", expanded=True):
                        st.json(args_data)

                with col_btn1:
                    if st.button("✅ Approve & Forward", key=f"appr_btn_{appr_id}", use_container_width=True, type="primary"):
                        success, res = client.approve_call(appr_id, resolver="admin_soc")
                        if success:
                            st.success(f"Approved call '{tool}'! Resuming tool execution downstream...")
                            st.rerun()
                        else:
                            st.error(f"Approval failed: {res}")

                with col_btn2:
                    if st.button("🚫 Block / Reject", key=f"rej_btn_{appr_id}", use_container_width=True):
                        success, res = client.reject_call(appr_id, resolver="admin_soc")
                        if success:
                            st.warning(f"Rejected call '{tool}'. Execution blocked.")
                            st.rerun()
                        else:
                            st.error(f"Rejection failed: {res}")

                st.markdown("<hr style='border-color: rgba(255,255,255,0.08);'>", unsafe_allow_html=True)

    # -------------------------------------------------------------------------
    # Resolved Approvals History Section
    # -------------------------------------------------------------------------
    st.subheader(f"📜 Approval Audit History ({len(resolved_approvals)} Resolved)")

    if not resolved_approvals:
        st.info("No resolved approvals recorded yet.")
    else:
        # Filter controls
        filter_col1, filter_col2 = st.columns([2, 4])
        with filter_col1:
            status_filter = st.selectbox(
                "Filter History by Status",
                ["All", "APPROVED", "REJECTED", "TIMED_OUT"],
                key="resolved_status_filter"
            )

        filtered_history = resolved_approvals
        if status_filter != "All":
            filtered_history = [a for a in resolved_approvals if a.get("status") == status_filter]

        df_resolved = pd.DataFrame(filtered_history)
        display_cols = ["approval_id", "server_name", "tool_name", "risk_score", "status", "resolved_by", "resolved_at", "created_at"]
        available_cols = [c for c in display_cols if c in df_resolved.columns]
        st.dataframe(df_resolved[available_cols], use_container_width=True)


if __name__ == "__main__":
    st.set_page_config(
        page_title="Admin Approvals | MCPath",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    render_page()
