"""MCPath Admin & Security Analyst Dashboard.

CRITICAL ARCHITECTURAL BOUNDARY:
This dashboard is strictly in the read-only observability path.
It reads from the FastAPI backend and displays proxy-boundary evidence.
It CANNOT insert itself into the live enforcement path.
[TODO Day 12-13: Complete Streamlit / React UI panels]
"""

import streamlit as st


def main():
    st.set_page_config(page_title="MCPath Security Dashboard", layout="wide")
    st.title("🛡️ MCPath Zero-Trust Security Dashboard")
    st.caption("Runtime Zero-Trust MCP Proxy: Sequential Risk-Pipeline Architecture")

    tabs = st.tabs([
        "Overview",
        "Live Tool Monitor",
        "Capability Graph",
        "Risk Analysis",
        "Security Events",
        "Server Inventory"
    ])

    with tabs[0]:
        st.subheader("Security Overview")
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Tool Calls", "0")
        col2.metric("Allowed Calls", "0")
        col3.metric("Blocked Calls", "0")
        col4.metric("Hash Violations", "0")

    with tabs[1]:
        st.subheader("Live Tool Monitor")
        st.info("Live tool calls passing through MCPath proxy will appear here.")

    with tabs[2]:
        st.subheader("Dynamic Capability Graph")
        st.info("Causal capability graph: Agent -> Tool -> Resource -> Action -> Destination.")

    with tabs[3]:
        st.subheader("Risk Analysis")
        st.info("Attributable graded scores across Hash, Capability, Intent, Behaviour, and Response.")

    with tabs[4]:
        st.subheader("Security Event Details")
        st.info("Section 7 attributable explainability records.")

    with tabs[5]:
        st.subheader("MCP Server / Tool Inventory")
        st.info("Discovered tools, canonical hashes, and connected servers.")


if __name__ == "__main__":
    main()
