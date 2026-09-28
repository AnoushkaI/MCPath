"""MCPath Zero-Trust Security Dashboard — Main Application Entrypoint.

CRITICAL ARCHITECTURAL BOUNDARY:
This Streamlit dashboard is strictly in the read-only / administrative observability path.
Enforcement Architecture:
  Claude Desktop -> MCPath stdio proxy -> MCP Servers (LIVE ENFORCEMENT)
  MCPath Proxy -> FastAPI Backend -> PostgreSQL -> Dashboard (OBSERVABILITY & CONTROL)

The dashboard communicates exclusively via localhost HTTP with the FastAPI backend.
It CANNOT directly manipulate proxy Python objects or intercept MCP stdio traffic.
"""

import os
import sys
from pathlib import Path
import streamlit as st

# Ensure repository root is on sys.path
repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from frontend.streamlit_app.api_client import client
from frontend.streamlit_app.styles import apply_soc_styles

st.set_page_config(
    page_title="MCPath Zero-Trust Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply global cybersecurity theme
apply_soc_styles()

# -------------------------------------------------------------------------
# Sidebar Branding & Global Controls
# -------------------------------------------------------------------------
with st.sidebar:
    st.markdown("""
    <div style="padding: 10px 0; border-bottom: 1px solid #1e293b; margin-bottom: 14px;">
        <div style="font-size: 1.25rem; font-weight: 800; color: #f8fafc; letter-spacing: -0.02em;">
            🛡️ MCPath <span style="color: #00f0ff; font-size: 0.8rem; font-weight: 600; padding: 2px 6px; border: 1px solid #00f0ff; border-radius: 4px;">ZERO-TRUST</span>
        </div>
        <div style="font-size: 0.76rem; color: #94a3b8; margin-top: 4px;">
            Sequential Risk-Pipeline Proxy Observability
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Backend Connection Status
    health = client.check_health()
    if health.get("online"):
        st.markdown("""
        <div style="background-color: rgba(16, 185, 129, 0.12); border: 1px solid rgba(16, 185, 129, 0.4); border-radius: 6px; padding: 8px 12px; margin-bottom: 14px;">
            <div style="display: flex; align-items: center; gap: 8px;">
                <span style="height: 8px; width: 8px; background-color: #10b981; border-radius: 50%; display: inline-block;"></span>
                <span style="font-size: 0.8rem; font-weight: 700; color: #10b981;">FASTAPI BACKEND ONLINE</span>
            </div>
            <div style="font-size: 0.72rem; color: #94a3b8; font-family: monospace; margin-top: 2px;">
                http://127.0.0.1:8000
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div style="background-color: rgba(239, 68, 68, 0.12); border: 1px solid rgba(239, 68, 68, 0.4); border-radius: 6px; padding: 8px 12px; margin-bottom: 14px;">
            <div style="display: flex; align-items: center; gap: 8px;">
                <span style="height: 8px; width: 8px; background-color: #ef4444; border-radius: 50%; display: inline-block;"></span>
                <span style="font-size: 0.8rem; font-weight: 700; color: #ef4444;">BACKEND OFFLINE</span>
            </div>
            <div style="font-size: 0.72rem; color: #fca5a5; margin-top: 2px;">
                Cannot reach {client.base_url}
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("""
    <div style="padding: 10px 0; font-size: 0.78rem; color: #cbd5e1; border-top: 1px solid #1e293b; margin-top: 20px;">
        <div style="font-weight: 700; color: #f8fafc; margin-bottom: 6px; letter-spacing: 0.05em;">ACTIVE MCP PIPELINE:</div>
        <div style="line-height: 1.5; color: #94a3b8;">
            <div>1. Tool Integrity (Canonical SHA-256)</div>
            <div>2. Capability Graph (Path Weights)</div>
            <div>3. Semantic Intent (MiniLM-L6-v2)</div>
            <div>4. Behaviour Deviation (Trace Stub)</div>
            <div>5. Response Egress (Stub)</div>
            <div>6. Deterministic Risk Engine</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

# -------------------------------------------------------------------------
# Multi-page Routing using Streamlit Navigation
# -------------------------------------------------------------------------
current_dir = Path(__file__).resolve().parent

pages = [
    st.Page(str(current_dir / "pages" / "1_Security_Overview.py"), title="Security Overview", icon="🛡️", default=True),
    st.Page(str(current_dir / "pages" / "2_Live_Runtime_Monitor.py"), title="Live Runtime Monitor", icon="📡"),
    st.Page(str(current_dir / "pages" / "3_Capability_Graph.py"), title="Capability Paths", icon="🗺️"),
    st.Page(str(current_dir / "pages" / "5_MCP_Servers.py"), title="MCP Server Management", icon="🖥️"),
    st.Page(str(current_dir / "pages" / "6_Security_Events.py"), title="Security Events", icon="📜"),
    st.Page(str(current_dir / "pages" / "7_Tool_Baseline_Inspector.py"), title="Tool Integrity", icon="🔒"),
    st.Page(str(current_dir / "pages" / "4_Risk_Analysis.py"), title="Risk Analysis", icon="⚖️"),
]

pg = st.navigation(pages)
pg.run()
