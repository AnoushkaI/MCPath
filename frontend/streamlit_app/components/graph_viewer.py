"""Capability Graph Viewer Component using interactive Vis.js / HTML5 Canvas."""

import json
from typing import Any, Dict, List, Optional
import streamlit as st
import streamlit.components.v1 as components


def render_capability_graph_html(
    nodes: List[Dict[str, Any]],
    edges: List[Dict[str, Any]],
    risky_path_node_ids: Optional[set] = None,
    height_px: int = 580
):
    """Render dynamic interactive capability graph using vis-network in an iframe."""
    if not nodes:
        st.info("No graph nodes available to display.")
        return

    risky_path_node_ids = risky_path_node_ids or set()

    # Transform nodes into vis.js format
    vis_nodes = []
    for n in nodes:
        nid = n.get("id", "")
        ntype = n.get("type", "Unknown")
        label = n.get("label", nid)
        server = n.get("server", "")

        is_risky = nid in risky_path_node_ids

        # Color mapping by node type
        if ntype == "Agent":
            color = {"background": "#0e7490", "border": "#00f0ff", "highlight": {"background": "#0891b2", "border": "#67e8f9"}}
            shape = "diamond"
            size = 28
        elif ntype == "Tool":
            color = {"background": "#1e3a8a", "border": "#3b82f6", "highlight": {"background": "#1d4ed8", "border": "#93c5fd"}}
            shape = "box"
            size = 24
        elif ntype == "Resource":
            color = {"background": "#064e3b", "border": "#10b981", "highlight": {"background": "#047857", "border": "#6ee7b7"}}
            shape = "ellipse"
            size = 22
        elif ntype == "Action":
            color = {"background": "#78350f", "border": "#f59e0b", "highlight": {"background": "#b45309", "border": "#fcd34d"}}
            shape = "hexagon"
            size = 24
        elif ntype == "Destination":
            color = {"background": "#7f1d1d" if is_risky else "#334155", "border": "#ef4444" if is_risky else "#64748b", "highlight": {"background": "#991b1b", "border": "#fca5a5"}}
            shape = "database"
            size = 26
        else:
            color = {"background": "#1e293b", "border": "#475569", "highlight": {"background": "#334155", "border": "#94a3b8"}}
            shape = "dot"
            size = 18

        if is_risky and ntype != "Agent":
            color["border"] = "#ef4444"
            color["background"] = "#450a0a"

        # Tooltip text
        title_lines = [f"<b>{label}</b>", f"Type: {ntype}"]
        if server:
            title_lines.append(f"Server: {server}")
        for k, v in n.items():
            if k not in ("id", "type", "label", "server") and v:
                title_lines.append(f"{k}: {v}")
        tooltip = "<br>".join(title_lines)

        vis_nodes.append({
            "id": nid,
            "label": label,
            "title": tooltip,
            "shape": shape,
            "size": size,
            "color": color,
            "font": {"color": "#f8fafc", "face": "ui-sans-serif, system-ui", "size": 12},
            "borderWidth": 2 if not is_risky else 3,
            "shadow": is_risky
        })

    # Transform edges into vis.js format
    vis_edges = []
    for idx, e in enumerate(edges):
        src = e.get("source", "")
        tgt = e.get("target", "")
        rel = e.get("relation", "")

        is_risky_edge = (src in risky_path_node_ids and tgt in risky_path_node_ids)

        edge_color = "#ef4444" if is_risky_edge else "#475569"
        arrows = "to"

        vis_edges.append({
            "id": f"e_{idx}",
            "from": src,
            "to": tgt,
            "label": rel,
            "arrows": arrows,
            "color": {"color": edge_color, "highlight": "#00f0ff", "hover": "#38bdf8"},
            "font": {"color": "#cbd5e1", "size": 10, "align": "middle", "strokeWidth": 2, "strokeColor": "#0b0f19"},
            "width": 2 if is_risky_edge else 1,
            "dashes": is_risky_edge,
            "smooth": {"type": "cubicBezier", "roundness": 0.2}
        })

    nodes_json = json.dumps(vis_nodes)
    edges_json = json.dumps(vis_edges)

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
        <style>
            html, body {{
                margin: 0;
                padding: 0;
                width: 100%;
                height: 100%;
                background-color: #0b0f19;
                overflow: hidden;
            }}
            #network-container {{
                width: 100%;
                height: {height_px}px;
                border: 1px solid #1e293b;
                border-radius: 8px;
                background: radial-gradient(circle, #111827 0%, #0b0f19 100%);
            }}
            #controls {{
                position: absolute;
                top: 12px;
                right: 16px;
                z-index: 10;
                background: rgba(15, 23, 42, 0.85);
                border: 1px solid #334155;
                padding: 6px 12px;
                border-radius: 6px;
                font-family: ui-monospace, monospace;
                font-size: 11px;
                color: #94a3b8;
                pointer-events: none;
            }}
            .legend-item {{
                display: inline-block;
                margin-right: 10px;
            }}
            .dot {{
                display: inline-block;
                width: 8px;
                height: 8px;
                border-radius: 50%;
                margin-right: 4px;
            }}
        </style>
    </head>
    <body>
        <div id="controls">
            <span class="legend-item"><span class="dot" style="background:#00f0ff;"></span>Agent</span>
            <span class="legend-item"><span class="dot" style="background:#3b82f6;"></span>Tool</span>
            <span class="legend-item"><span class="dot" style="background:#10b981;"></span>Resource</span>
            <span class="legend-item"><span class="dot" style="background:#f59e0b;"></span>Action</span>
            <span class="legend-item"><span class="dot" style="background:#ef4444;"></span>Risky Path</span>
        </div>
        <div id="network-container"></div>
        <script type="text/javascript">
            const nodes = new vis.DataSet({nodes_json});
            const edges = new vis.DataSet({edges_json});
            const container = document.getElementById('network-container');
            const data = {{ nodes: nodes, edges: edges }};
            const options = {{
                nodes: {{
                    borderWidth: 2,
                    shadow: true
                }},
                edges: {{
                    shadow: false
                }},
                physics: {{
                    enabled: true,
                    solver: 'forceAtlas2Based',
                    forceAtlas2Based: {{
                        gravitationalConstant: -40,
                        centralGravity: 0.008,
                        springLength: 90,
                        springConstant: 0.06,
                        damping: 0.88
                    }},
                    stabilization: {{
                        iterations: 120,
                        updateInterval: 25
                    }}
                }},
                interaction: {{
                    hover: true,
                    tooltipDelay: 100,
                    zoomView: true,
                    dragView: true
                }}
            }};
            const network = new vis.Network(container, data, options);
        </script>
    </body>
    </html>
    """
    components.html(html_content, height=height_px + 20)
