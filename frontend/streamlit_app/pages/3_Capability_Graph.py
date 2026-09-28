"""Capability Paths & Graph Explorer.

Modern SaaS cybersecurity interface for visualizing precomputed capability paths,
typed-edge causal chains, and mapping observed runtime events to capability paths.

Distinction:
- PRECOMPUTED POSSIBLE PATHS: Statically enumerated causal sequences mapped by Stage 2 policy rules.
- OBSERVED RUNTIME ACTIVITY: Actual intercepted tool calls recorded by MCPath proxy.
"""

from typing import Any, Dict, List, Optional
import pandas as pd
import streamlit as st

from frontend.streamlit_app.api_client import client
from frontend.streamlit_app.components.graph_viewer import render_capability_graph_html
from frontend.streamlit_app.styles import (
    apply_soc_styles,
    render_header,
    render_severity_badge,
    render_path_id_badge,
    render_match_status_badge
)


def render_page():
    apply_soc_styles()
    render_header("Capability Paths", "Causal Capability Graph & Persistent Precomputed Path Registry (Stage 2)")

    # -------------------------------------------------------------------------
    # Distinction Banner: Possible Paths vs. Observed Runtime Activity
    # -------------------------------------------------------------------------
    st.markdown("""
    <div style="background: linear-gradient(90deg, rgba(30, 41, 59, 0.7) 0%, rgba(17, 24, 39, 0.9) 100%);
                border: 1px solid #334155; border-left: 4px solid #00f0ff; border-radius: 8px; padding: 14px 20px; margin-bottom: 20px;">
        <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px;">
            <div>
                <span style="font-weight: 700; color: #38bdf8; font-size: 0.95rem;">
                    🗺️ CAPABILITY MODEL DISTINCTION:
                </span>
                <span style="color: #cbd5e1; font-size: 0.85rem; margin-left: 6px;">
                    <b>Precomputed Possible Paths</b> represent statically verified causal reachability (Agent → Tool → Resource → Action → Destination) based on tool definitions and policy.
                </span>
                <div style="color: #94a3b8; font-size: 0.8rem; margin-top: 4px;">
                    ⚠️ A precomputed possible path defines potential capability reach. It is <b>never</b> presented as proof that an attack occurred unless correlated with an <b>Observed Runtime Event</b>.
                </div>
            </div>
            <div>
                <span style="background: rgba(0, 240, 255, 0.1); border: 1px solid #00f0ff; color: #00f0ff; font-size: 0.75rem; padding: 3px 8px; border-radius: 4px; font-weight: 600;">
                    MODEL: PRECOMPUTED CAUSAL DAG
                </span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Fetch graph and paths from backend
    with st.spinner("Loading capability graph topology and path catalog..."):
        graph_data = client.get_capability_graph()
        all_paths = client.get_capability_paths()
        tool_caps = client.get_tool_capabilities()

    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])

    if not nodes or not all_paths:
        st.warning(
            "⚠️ No capability graph nodes or paths found in backend persistence. "
            "Ensure the MCPath backend is running and servers are registered."
        )
        return

    # Check if a path was selected from another page (Runtime Monitor or Security Events)
    query_params = st.query_params
    selected_path_id_from_url = query_params.get("path_id")
    if selected_path_id_from_url:
        st.session_state["selected_path_id"] = selected_path_id_from_url

    event_id_highlight = st.session_state.get("highlight_event_id")

    # -------------------------------------------------------------------------
    # Top KPI Metrics Grid
    # -------------------------------------------------------------------------
    total_nodes = len(nodes)
    total_edges = len(edges)
    total_paths = len(all_paths)
    high_paths = sum(1 for p in all_paths if p.get("classification") == "HIGH" or p.get("path_risk_score", 0) >= 70.0)
    overrides = sum(1 for p in all_paths if p.get("is_critical_override"))

    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.markdown(f"""
        <div class="soc-card soc-card-cyan">
            <div class="soc-card-label">Precomputed Paths</div>
            <div class="soc-card-value">{total_paths}</div>
            <div class="soc-card-subtext">Persistent Path IDs</div>
        </div>
        """, unsafe_allow_html=True)
    with m2:
        st.markdown(f"""
        <div class="soc-card soc-card-crimson">
            <div class="soc-card-label">High-Risk Paths</div>
            <div class="soc-card-value" style="color: #ef4444;">{high_paths}</div>
            <div class="soc-card-subtext">Score ≥ 70 / Critical</div>
        </div>
        """, unsafe_allow_html=True)
    with m3:
        st.markdown(f"""
        <div class="soc-card soc-card-amber">
            <div class="soc-card-label">Critical Overrides</div>
            <div class="soc-card-value" style="color: #f59e0b;">{overrides}</div>
            <div class="soc-card-subtext">Sensitive → External</div>
        </div>
        """, unsafe_allow_html=True)
    with m4:
        st.markdown(f"""
        <div class="soc-card soc-card-indigo">
            <div class="soc-card-label">Graph Nodes</div>
            <div class="soc-card-value">{total_nodes}</div>
            <div class="soc-card-subtext">Tools, Resources, Sinks</div>
        </div>
        """, unsafe_allow_html=True)
    with m5:
        st.markdown(f"""
        <div class="soc-card soc-card-emerald">
            <div class="soc-card-label">Typed Edges</div>
            <div class="soc-card-value" style="color: #10b981;">{total_edges}</div>
            <div class="soc-card-subtext">Causal Flow Rules</div>
        </div>
        """, unsafe_allow_html=True)

    st.write("")

    # -------------------------------------------------------------------------
    # Graph Visualization Mode & Filters
    # -------------------------------------------------------------------------
    st.subheader("🔍 Graph Display Mode & Filters")
    st.caption("To prevent visual clutter, MCPath focuses on specific paths or subgraphs by default rather than rendering the entire infrastructure graph.")

    col_mode, col_server, col_tool, col_sev = st.columns([3, 2, 2, 2])

    server_list = sorted(list({n.get("server") for n in nodes if n.get("server") and n.get("server") != "mcpath"}))

    with col_mode:
        view_mode = st.radio(
            "Graph View Mode",
            [
                "🎯 Focused Path Chain (Recommended)",
                "🏢 Server / Tool Subgraph",
                "🌐 Full Infrastructure Topology"
            ],
            index=0,
            horizontal=False
        )

    with col_server:
        selected_server = st.selectbox("Filter Server", ["All"] + server_list, index=0)

    # Filter tool options based on server
    tools_for_server = sorted(list({
        p.get("tool_name") for p in all_paths
        if selected_server == "All" or any(n.get("server") == selected_server and n.get("label") == p.get("tool_name") for n in nodes)
    }))

    with col_tool:
        selected_tool = st.selectbox("Filter Tool", ["All"] + tools_for_server, index=0)

    with col_sev:
        selected_severity = st.selectbox(
            "Risk Filter",
            ["All", "HIGH (Score ≥ 70)", "MEDIUM (30 ≤ Score < 70)", "LOW (Score < 30)", "Critical Overrides Only"],
            index=0
        )

    # Filter available paths
    filtered_paths = list(all_paths)
    if selected_server != "All":
        filtered_paths = [
            p for p in filtered_paths
            if any(n.get("server") == selected_server and n.get("label") == p.get("tool_name") for n in nodes)
        ]
    if selected_tool != "All":
        filtered_paths = [p for p in filtered_paths if p.get("tool_name") == selected_tool]

    if selected_severity == "HIGH (Score ≥ 70)":
        filtered_paths = [p for p in filtered_paths if p.get("classification") == "HIGH" or p.get("path_risk_score", 0) >= 70.0]
    elif selected_severity == "MEDIUM (30 ≤ Score < 70)":
        filtered_paths = [p for p in filtered_paths if 30.0 <= p.get("path_risk_score", 0) < 70.0 and not p.get("is_critical_override")]
    elif selected_severity == "LOW (Score < 30)":
        filtered_paths = [p for p in filtered_paths if p.get("path_risk_score", 0) < 30.0 and not p.get("is_critical_override")]
    elif selected_severity == "Critical Overrides Only":
        filtered_paths = [p for p in filtered_paths if p.get("is_critical_override")]

    # -------------------------------------------------------------------------
    # Selected Path Selection & Forensic Inspection
    # -------------------------------------------------------------------------
    st.markdown("---")
    st.subheader("🎯 Path Inspector & Causal Chain")

    path_options_map = {
        f"{p.get('path_id')} | {p.get('tool_name')} ({p.get('classification')}, {p.get('path_risk_score', 0):.1f})": p
        for p in filtered_paths
    }

    selected_path_obj = None
    default_index = 0

    # Auto-select path if set in session state
    target_path_id = st.session_state.get("selected_path_id")
    if target_path_id:
        for idx, (label, p_obj) in enumerate(path_options_map.items()):
            if p_obj.get("path_id") == target_path_id:
                default_index = idx
                break

    if path_options_map:
        selected_label = st.selectbox(
            "Select Capability Path to Inspect & Highlight in Graph:",
            list(path_options_map.keys()),
            index=default_index if default_index < len(path_options_map) else 0
        )
        selected_path_obj = path_options_map[selected_label]
        # Update session state with current path_id
        st.session_state["selected_path_id"] = selected_path_obj.get("path_id")

    if selected_path_obj:
        pid = selected_path_obj.get("path_id")
        p_score = selected_path_obj.get("path_risk_score", 0.0)
        p_class = selected_path_obj.get("classification", "LOW")
        p_override = selected_path_obj.get("is_critical_override", False)
        p_nodes = selected_path_obj.get("path_nodes", [])
        p_edges = selected_path_obj.get("path_edges", [])
        p_expl = selected_path_obj.get("explanation", "")

        # Highlight card for the selected path
        st.markdown(f"""
        <div style="background-color: #111827; border: 1px solid #1f2937; border-left: 4px solid {'#ef4444' if p_class == 'HIGH' else ('#f59e0b' if p_class == 'MEDIUM' else '#10b981')}; border-radius: 8px; padding: 18px 22px; margin-bottom: 16px;">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                <div>
                    <span style="font-family: ui-monospace, monospace; font-size: 0.88rem; color: #38bdf8; font-weight: 700; background: rgba(56, 189, 248, 0.15); padding: 3px 8px; border-radius: 4px; border: 1px solid rgba(56, 189, 248, 0.3);">
                        🔑 PATH ID: {pid}
                    </span>
                    <span style="margin-left: 10px; font-weight: 700; color: #f8fafc; font-size: 1.05rem;">
                        Tool: <code>{selected_path_obj.get('tool_name')}</code>
                    </span>
                </div>
                <div style="display: flex; gap: 8px; align-items: center;">
                    {render_severity_badge(p_class, p_score)}
                    {'<span class="badge-block">🚨 CRITICAL OVERRIDE</span>' if p_override else ''}
                    <span style="font-size: 0.75rem; color: #94a3b8; font-family: monospace;">PRECOMPUTED POSSIBLE</span>
                </div>
            </div>
            <div style="margin-top: 12px; color: #94a3b8; font-size: 0.85rem;">
                <b>Policy Evaluation:</b> {p_expl}
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Causal Progression Steps visualization
        st.markdown("**Step-by-Step Causal Chain:**")
        step_cols = st.columns(len(p_nodes))
        node_icons = {
            "Agent": "🤖",
            "Tool": "🔧",
            "Data/Resource": "📦",
            "Resource": "📦",
            "Action": "⚡",
            "External Destination": "🌐",
            "Destination": "🌐",
        }

        for idx, n_name in enumerate(p_nodes):
            n_type = "Agent"
            if n_name.startswith("Tool:"):
                n_type = "Tool"
            elif n_name.startswith("Resource:"):
                n_type = "Resource"
            elif n_name.startswith("Action:"):
                n_type = "Action"
            elif n_name.startswith("Destination:"):
                n_type = "Destination"

            icon = node_icons.get(n_type, "📌")
            edge_label = p_edges[idx - 1] if idx > 0 and idx - 1 < len(p_edges) else None

            with step_cols[idx]:
                if edge_label:
                    st.caption(f"➔ `{edge_label}`")
                st.markdown(f"""
                <div style="background-color: #0f172a; border: 1px solid #1e293b; border-radius: 6px; padding: 10px; text-align: center;">
                    <div style="font-size: 1.1rem;">{icon}</div>
                    <div style="font-size: 0.7rem; color: #38bdf8; text-transform: uppercase; font-weight: 700; margin-top: 2px;">{n_type}</div>
                    <div style="font-size: 0.76rem; color: #f1f5f9; font-weight: 600; word-break: break-all; margin-top: 4px;">{n_name}</div>
                </div>
                """, unsafe_allow_html=True)

        # Dimension breakdown metrics
        sc1, sc2, sc3, sc4 = st.columns(4)
        with sc1:
            st.metric("Data Sensitivity (30%)", f"{selected_path_obj.get('data_sensitivity', 0):.2f}")
        with sc2:
            st.metric("Action Sensitivity (25%)", f"{selected_path_obj.get('action_sensitivity', 0):.2f}")
        with sc3:
            st.metric("External Exposure (20%)", f"{selected_path_obj.get('external_exposure', 0):.2f}")
        with sc4:
            st.metric("Chain Risk (25%)", f"{selected_path_obj.get('chain_risk', 0):.2f}")

    st.write("")

    # -------------------------------------------------------------------------
    # Interactive Graph Canvas Rendering
    # -------------------------------------------------------------------------
    st.subheader("🕸️ Interactive Graph Topology")

    # Determine nodes and edges to display based on view_mode
    if "Focused Path Chain" in view_mode and selected_path_obj:
        path_node_set = set(selected_path_obj.get("path_nodes", []))
        displayed_nodes = [n for n in nodes if n.get("id") in path_node_set]
        displayed_edges = [
            e for e in edges
            if e.get("source") in path_node_set and e.get("target") in path_node_set
        ]
        risky_nodes = path_node_set if (selected_path_obj.get("classification") == "HIGH" or selected_path_obj.get("is_critical_override")) else set()
        st.caption(f"Displaying focused causal chain for `{selected_path_obj.get('path_id')}` ({len(displayed_nodes)} nodes, {len(displayed_edges)} edges)")
    elif "Server / Tool Subgraph" in view_mode:
        relevant_node_ids = {"Agent"}
        for p in filtered_paths:
            for nid in p.get("path_nodes", []):
                relevant_node_ids.add(nid)

        displayed_nodes = [
            n for n in nodes
            if n.get("id") in relevant_node_ids or (selected_server != "All" and n.get("server") == selected_server)
        ]
        valid_ids = {n.get("id") for n in displayed_nodes}
        displayed_edges = [e for e in edges if e.get("source") in valid_ids and e.get("target") in valid_ids]
        risky_nodes = {
            nid for p in filtered_paths
            if p.get("classification") == "HIGH" or p.get("is_critical_override")
            for nid in p.get("path_nodes", [])
        }
        st.caption(f"Displaying filtered subgraph ({len(displayed_nodes)} nodes, {len(displayed_edges)} edges)")
    else:  # Full Infrastructure Topology
        displayed_nodes = nodes
        displayed_edges = edges
        risky_nodes = {
            nid for p in all_paths
            if p.get("classification") == "HIGH" or p.get("is_critical_override")
            for nid in p.get("path_nodes", [])
        }
        st.caption(f"Displaying full multi-server infrastructure graph ({len(displayed_nodes)} nodes, {len(displayed_edges)} edges)")

    render_capability_graph_html(
        nodes=displayed_nodes,
        edges=displayed_edges,
        risky_path_node_ids=risky_nodes,
        height_px=540
    )

    st.write("")

    # -------------------------------------------------------------------------
    # Searchable Precomputed Capability Paths Catalog Table
    # -------------------------------------------------------------------------
    st.subheader(f"📋 Precomputed Capability Paths Registry ({len(filtered_paths)} paths)")
    st.caption("Unique, persistent path IDs remain stable across graph rebuilds whenever the underlying path has not changed.")

    search_kw = st.text_input("🔍 Search Paths (by Path ID, Tool, Resource, Action, or Destination)", placeholder="e.g. read_file, credentials, external_network...")

    table_paths = filtered_paths
    if search_kw.strip():
        kw = search_kw.lower().strip()
        table_paths = [
            p for p in table_paths
            if kw in (p.get("path_id") or "").lower()
            or kw in (p.get("tool_name") or "").lower()
            or kw in " ".join(p.get("path_nodes", [])).lower()
            or kw in (p.get("explanation") or "").lower()
        ]

    if table_paths:
        table_rows = []
        for p in table_paths[:100]:
            pid = p.get("path_id", "")
            score = p.get("path_risk_score", 0.0)
            sev = p.get("classification", "LOW")
            override = "🚨 YES" if p.get("is_critical_override") else "No"
            chain_str = " ➔ ".join(p.get("path_nodes", []))

            table_rows.append({
                "Path ID": pid,
                "Tool": p.get("tool_name"),
                "Score": f"{score:.1f}",
                "Classification": sev,
                "Critical Override": override,
                "Chain Nodes": chain_str,
                "Data Sens": f"{p.get('data_sensitivity', 0):.2f}",
                "Action Sens": f"{p.get('action_sensitivity', 0):.2f}",
                "Ext Exposure": f"{p.get('external_exposure', 0):.2f}",
                "Chain Risk": f"{p.get('chain_risk', 0):.2f}",
                "Explanation": p.get("explanation", ""),
            })

        df_paths = pd.DataFrame(table_rows)
        st.dataframe(df_paths, use_container_width=True, hide_index=True)
    else:
        st.info("No capability paths match your search and filter criteria.")

    st.write("")

    # -------------------------------------------------------------------------
    # Discovered Tool Capabilities Policy Inventory
    # -------------------------------------------------------------------------
    with st.expander("📋 View Inferred Tool Capabilities (Stage 2 Policy Attributes)"):
        if tool_caps:
            cap_rows = []
            for tc in tool_caps:
                cap_rows.append({
                    "Tool Name": tc.get("tool_name"),
                    "Server": tc.get("server_name"),
                    "Resource Target": tc.get("data_target"),
                    "Operation": tc.get("operation"),
                    "Action Type": tc.get("action_type"),
                    "Data Sensitivity": f"{tc.get('data_sensitivity', 0.0):.2f}",
                    "Action Sensitivity": f"{tc.get('action_sensitivity', 0.0):.2f}",
                    "External Exposure": f"{tc.get('external_exposure', 0.0):.2f}",
                    "Destination": tc.get("external_destination") or "None (Internal)",
                })
            df_caps = pd.DataFrame(cap_rows)
            st.dataframe(df_caps, use_container_width=True, hide_index=True)


if __name__ == "__main__":
    st.set_page_config(page_title="Capability Paths - MCPath", layout="wide", page_icon="🗺️")
    render_page()
