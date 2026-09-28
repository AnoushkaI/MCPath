"""MCP Servers Management Page.

Section 7 Requirement:
Use the existing server-management APIs for list/add/activate/deactivate/trust.
Add-server form must collect server name, command, args, and environment variables.
ADD/DISCOVERY must remain UNTRUSTED with no approved baseline.
Only explicit "Trust & Register" creates the approved SHA-256 baseline.
Preserve the current servers: filesystem, git, postgres-mcp, rugpull-test, email-server.
Do not remove or deactivate any existing server during implementation.
"""

import json
import pandas as pd
import streamlit as st

from frontend.streamlit_app.api_client import client
from frontend.streamlit_app.styles import (
    apply_soc_styles,
    render_header,
    render_trust_badge
)


def render_page():
    apply_soc_styles()
    render_header("MCP Servers", "Downstream Server Lifecycle, Dynamic Discovery & Baseline Trust Management")

    st.markdown("""
    <div style="background-color: #111827; border: 1px solid #1e293b; border-left: 4px solid #00f0ff; border-radius: 6px; padding: 12px 18px; margin-bottom: 20px;">
        <span style="font-weight: 700; color: #38bdf8;">SECURITY MODEL (ADDING != TRUSTING):</span>
        <span style="color: #94a3b8; font-size: 0.88rem;">
            When an MCP server is added or discovered, it is cataloged as <b>UNTRUSTED</b> with <b>NO_APPROVED_BASELINE</b>.
            Execution is blocked by Stage 1 until an administrator performs an explicit <b>Trust & Register</b> action.
        </span>
    </div>
    """, unsafe_allow_html=True)

    # Top action bar
    top_col1, top_col2 = st.columns([3, 1])
    with top_col1:
        st.subheader("🖥️ Downstream Server Fleet Inventory")
    with top_col2:
        if st.button("🔄 Reload & Reconcile DB", use_container_width=True):
            with st.spinner("Synchronizing server configuration and database states..."):
                ok, res = client.reload_servers()
                if ok:
                    st.success("Successfully synchronized server fleet states!")
                    st.rerun()
                else:
                    st.error(f"Reload failed: {res}")

    # Fetch server list
    servers = client.get_servers()
    if not isinstance(servers, list):
        servers = []

    # Display Servers
    if servers:
        for srv in servers:
            s_name = srv.get("name", "")
            is_active = bool(srv.get("active") or srv.get("is_active"))
            trust_status = srv.get("trust_status", "UNTRUSTED")
            disc_tools = srv.get("discovered_tool_count", 0)
            appr_tools = srv.get("approved_tool_count", 0)
            unappr_tools = srv.get("unapproved_tool_count", 0)
            cmd = srv.get("command", "")
            args = srv.get("args", [])
            last_disc = srv.get("last_discovery_time") or "N/A"
            last_trust = srv.get("last_trust_time") or "Never"

            status_indicator = "🟢 ACTIVE" if is_active else "⚪ INACTIVE"
            card_border = "#10b981" if (is_active and trust_status == "TRUSTED") else ("#f59e0b" if is_active else "#475569")

            with st.expander(f"**{s_name}** — {status_indicator} | Trust: {trust_status} | {disc_tools} Tools", expanded=is_active):
                col_info1, col_info2, col_act = st.columns([2, 2, 2])

                with col_info1:
                    st.markdown(f"**Server Name:** `{s_name}`")
                    st.markdown(f"**Command:** `{cmd}`")
                    st.markdown(f"**Arguments:** `{' '.join(args) if args else 'None'}`")

                with col_info2:
                    st.markdown(f"**Trust Status:** {render_trust_badge(trust_status)}", unsafe_allow_html=True)
                    st.markdown(f"**Tools Cataloged:** `{disc_tools}` (Approved: `{appr_tools}`, Pending: `{unappr_tools}`)")
                    st.markdown(f"**Last Trust Approval:** `{last_trust}`")

                with col_act:
                    st.markdown("**Server Actions:**")
                    bcol1, bcol2 = st.columns(2)

                    with bcol1:
                        if is_active:
                            if st.button("Deactivate", key=f"deact_{s_name}", use_container_width=True):
                                with st.spinner(f"Deactivating {s_name}..."):
                                    ok, msg = client.deactivate_server(s_name)
                                    if ok:
                                        st.success(f"Deactivated {s_name}")
                                        st.rerun()
                                    else:
                                        st.error(f"Failed: {msg}")
                        else:
                            if st.button("Activate", key=f"act_{s_name}", use_container_width=True):
                                with st.spinner(f"Activating {s_name}..."):
                                    ok, msg = client.activate_server(s_name)
                                    if ok:
                                        st.success(f"Activated {s_name}")
                                        st.rerun()
                                    else:
                                        st.error(f"Failed: {msg}")

                    with bcol2:
                        if st.button("Trust & Register", key=f"trust_{s_name}", type="primary" if trust_status != "TRUSTED" else "secondary", use_container_width=True):
                            with st.spinner(f"Generating approved SHA-256 baselines for {s_name}..."):
                                ok, res = client.trust_server(s_name)
                                if ok:
                                    st.success(f"Successfully trusted {s_name}! Approved baseline established.")
                                    st.rerun()
                                else:
                                    st.error(f"Trust registration failed: {res}")

                # Show Discovered Tools for this server
                tools = client.get_server_tools(s_name)
                if tools:
                    st.markdown(f"**Discovered Tools Manifest ({len(tools)} tools):**")
                    t_rows = []
                    for t in tools:
                        t_rows.append({
                            "Tool Name": t.get("name"),
                            "Description": t.get("description"),
                            "Schema Parameters": ", ".join(t.get("input_schema", {}).get("properties", {}).keys()) if t.get("input_schema") else "None",
                            "Discovered At": t.get("updated_at")
                        })
                    st.dataframe(pd.DataFrame(t_rows), use_container_width=True, hide_index=True)
                else:
                    st.caption("No tools cataloged for this server yet.")

    else:
        st.info("No MCP servers found.")

    st.markdown("---")

    # -------------------------------------------------------------------------
    # Add New Downstream MCP Server Form
    # -------------------------------------------------------------------------
    st.subheader("➕ Add & Discover New MCP Server")
    st.caption("Connects downstream server and discovers tools. Newly discovered tools will remain UNTRUSTED until explicitly approved.")

    with st.form("add_server_form", clear_on_submit=True):
        col_f1, col_f2 = st.columns(2)
        with col_f1:
            form_name = st.text_input("Server Name *", placeholder="e.g. weather-mcp")
            form_command = st.text_input("Executable Command *", placeholder="e.g. npx, python, uvx")
        with col_f2:
            form_args = st.text_input("Command Arguments (comma or space separated)", placeholder="e.g. -y @modelcontextprotocol/server-weather")
            form_transport = st.selectbox("Transport Protocol", ["stdio"], index=0)

        form_env = st.text_area(
            "Environment Variables (JSON format, optional)",
            placeholder='{\n  "API_KEY": "secret_token",\n  "DEBUG": "true"\n}',
            height=100
        )

        submitted = st.form_submit_button("⚡ Discover & Add Server (UNTRUSTED)", type="primary")

        if submitted:
            if not form_name or not form_command:
                st.error("Server Name and Executable Command are required.")
            else:
                # Parse args
                args_list = []
                if form_args:
                    if "," in form_args:
                        args_list = [a.strip() for a in form_args.split(",") if a.strip()]
                    else:
                        args_list = form_args.split()

                # Parse env JSON
                env_dict = {}
                if form_env.strip():
                    try:
                        env_dict = json.loads(form_env)
                    except Exception as e:
                        st.error(f"Invalid JSON in environment variables: {e}")
                        return

                with st.spinner(f"Connecting and discovering tools on '{form_name}'..."):
                    ok, res = client.add_server(
                        name=form_name,
                        command=form_command,
                        args=args_list,
                        env=env_dict,
                        transport=form_transport
                    )
                    if ok:
                        st.success(
                            f"Server '{form_name}' successfully added and cataloged! "
                            f"Status: UNTRUSTED. Execution remains blocked until you click 'Trust & Register'."
                        )
                        st.rerun()
                    else:
                        st.error(f"Failed to add server: {res}")


if __name__ == "__main__":
    st.set_page_config(page_title="MCP Servers - MCPath", layout="wide", page_icon="🖥️")
    render_page()
