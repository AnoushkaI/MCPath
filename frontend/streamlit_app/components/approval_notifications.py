"""Global Real-Time HOLD Notification Component for MCPath Dashboard.

Renders prominent real-time notifications on any dashboard page when tool calls
are held for administrator review, featuring live countdown timers and instant
Approve / Reject actions.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
import streamlit as st

from frontend.streamlit_app.api_client import client


def parse_created_datetime(ts_str: Optional[str]) -> Optional[datetime]:
    """Parse ISO timestamp into UTC datetime."""
    if not ts_str:
        return None
    try:
        # Handle trailing Z or offsets
        clean = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


@st.fragment(run_every="2s")
def render_global_hold_notification(approvals_page_name: Optional[Any] = None) -> None:
    """Render prominent banner across all dashboard pages when HOLD decisions occur.
    
    Refreshes automatically every 2 seconds without requiring manual page reload.
    """
    pending_list = client.get_pending_approvals(limit=10)
    if not pending_list:
        return

    now = datetime.now(timezone.utc)
    timeout_duration = 30.0  # Configured approval deadline seconds

    # Container with cyber-themed pulsing alert styling
    with st.container():
        st.markdown(f"""
        <style>
        @keyframes pulse-amber {{
            0% {{ box-shadow: 0 0 0 0 rgba(245, 158, 11, 0.7); }}
            70% {{ box-shadow: 0 0 0 10px rgba(245, 158, 11, 0); }}
            100% {{ box-shadow: 0 0 0 0 rgba(245, 158, 11, 0); }}
        }}
        .hold-notification-banner {{
            background: linear-gradient(135deg, rgba(30, 20, 10, 0.95) 0%, rgba(45, 25, 12, 0.92) 100%);
            border: 2px solid #f59e0b;
            border-radius: 10px;
            padding: 16px 20px;
            margin-bottom: 24px;
            box-shadow: 0 4px 20px rgba(245, 158, 11, 0.25);
            animation: pulse-amber 2.5s infinite;
        }}
        </style>
        """, unsafe_allow_html=True)

        st.markdown(f"""
        <div class="hold-notification-banner">
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(245, 158, 11, 0.3); padding-bottom: 10px; margin-bottom: 14px;">
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span style="font-size: 1.4rem;">🚨</span>
                    <span style="font-size: 1.15rem; font-weight: 800; color: #fbbf24; letter-spacing: -0.01em;">
                        ADMINISTRATOR ACTION REQUIRED: {len(pending_list)} Tool Call(s) Held on Risk Review
                    </span>
                </div>
                <span style="background: #f59e0b; color: #0b0f19; font-weight: 800; font-size: 0.8rem; padding: 4px 10px; border-radius: 4px; text-transform: uppercase;">
                    Decision Pending
                </span>
            </div>
            <div style="font-size: 0.86rem; color: #f1f5f9; line-height: 1.4; margin-bottom: 8px;">
                Claude Desktop is currently paused awaiting your security decision. Approved calls execute downstream exactly once; rejected or timed-out calls are immediately blocked.
            </div>
        </div>
        """, unsafe_allow_html=True)

        seen_ids = set()
        for idx, item in enumerate(pending_list):
            appr_id = item.get("approval_id")
            if not appr_id or appr_id in seen_ids:
                continue
            seen_ids.add(appr_id)

            server = item.get("server_name", "unknown")
            tool = item.get("tool_name", "unknown")
            score = float(item.get("risk_score", 50.0) or 50.0)
            reason = item.get("reason", "Held for review")
            args_data = item.get("arguments") or {}
            created_at_str = item.get("created_at") or "Unknown"

            # Calculate live remaining seconds
            dt_created = parse_created_datetime(created_at_str)
            if dt_created:
                elapsed = (now - dt_created).total_seconds()
                remaining_sec = max(0, int(timeout_duration - elapsed))
            else:
                remaining_sec = 30

            # Countdown color
            if remaining_sec > 15:
                timer_color = "#10b981"  # Emerald
            elif remaining_sec > 5:
                timer_color = "#f59e0b"  # Amber
            else:
                timer_color = "#ef4444"  # Red

            timer_label = f"⏳ {remaining_sec}s remaining" if remaining_sec > 0 else "⏰ 0s remaining (Timing out...)"

            with st.container():
                st.markdown(f"""
                <div style="background: rgba(15, 23, 42, 0.9); border: 1px solid rgba(245, 158, 11, 0.4); border-radius: 8px; padding: 14px 18px; margin-bottom: 12px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
                        <span style="font-size: 1.05rem; font-weight: 700; color: #f8fafc;">
                            🛠️ Server: <code style="color: #38bdf8;">{server}</code> &nbsp;|&nbsp; Tool: <code style="color: #00f0ff;">{tool}</code>
                        </span>
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <span style="background: rgba(245, 158, 11, 0.15); border: 1px solid #f59e0b; color: #fbbf24; font-weight: 700; font-size: 0.85rem; padding: 3px 8px; border-radius: 4px;">
                                Risk: {score:.1f} (HOLD)
                            </span>
                            <span style="background: rgba(15, 23, 42, 0.8); border: 1px solid {timer_color}; color: {timer_color}; font-weight: 800; font-size: 0.88rem; padding: 3px 10px; border-radius: 4px;">
                                {timer_label}
                            </span>
                        </div>
                    </div>
                    <div style="font-size: 0.82rem; color: #94a3b8; margin-top: 6px;">
                        <b>Approval ID:</b> <code>{appr_id}</code> &nbsp;•&nbsp;
                        <b>Event ID:</b> <code>{item.get("event_id")}</code> &nbsp;•&nbsp;
                        <b>Timestamp:</b> {created_at_str}
                    </div>
                    <div style="font-size: 0.86rem; color: #e2e8f0; margin-top: 8px; background: rgba(30, 41, 59, 0.6); padding: 8px 12px; border-radius: 4px; border-left: 3px solid #f59e0b;">
                        <b>Hold Reason:</b> {reason}
                    </div>
                </div>
                """, unsafe_allow_html=True)

                col_args, col_btn1, col_btn2, col_nav = st.columns([3, 1.2, 1.2, 1.4])
                with col_args:
                    with st.expander(f"🔍 Masked Arguments ({tool})", expanded=False):
                        st.json(args_data)

                with col_btn1:
                    if st.button("✅ Approve", key=f"global_appr_{appr_id}_{idx}", use_container_width=True, type="primary"):
                        success, res = client.approve_call(appr_id, resolver="admin_soc")
                        if success:
                            st.success(f"Approved '{tool}'! Resuming tool execution downstream...")
                            st.rerun()
                        else:
                            st.error(f"Approval failed: {res}")

                with col_btn2:
                    if st.button("🚫 Block / Reject", key=f"global_rej_{appr_id}_{idx}", use_container_width=True):
                        success, res = client.reject_call(appr_id, resolver="admin_soc")
                        if success:
                            st.warning(f"Rejected '{tool}'. Execution blocked.")
                            st.rerun()
                        else:
                            st.error(f"Rejection failed: {res}")

                with col_nav:
                    if approvals_page_name and st.button("📋 Full Queue", key=f"global_nav_{appr_id}_{idx}", use_container_width=True):
                        st.switch_page(approvals_page_name)

                st.markdown("<hr style='border-color: rgba(245, 158, 11, 0.2); margin: 8px 0 16px 0;'>", unsafe_allow_html=True)
