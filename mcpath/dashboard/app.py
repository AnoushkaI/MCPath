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
        try:
            import requests
            resp = requests.get("http://127.0.0.1:8000/api/capabilities/graph", timeout=2)
            if resp.status_code == 200:
                gdata = resp.json()
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Graph Nodes", gdata.get("total_nodes", 0))
                c2.metric("Typed Edges", gdata.get("total_edges", 0))
                c3.metric("Policy Version", gdata.get("policy_version", "1.0.0"))

                paths_resp = requests.get("http://127.0.0.1:8000/api/capabilities/paths", timeout=2)
                if paths_resp.status_code == 200:
                    paths = paths_resp.json()
                    c4.metric("Compatible Paths", len(paths))
                    st.write("### Compatible Paths & Path Scores")
                    for p in paths:
                        path_str = " ➔ ".join(p.get("path_nodes", []))
                        score = p.get("path_risk_score", 0.0)
                        sev = p.get("classification", "LOW")
                        override = " 🚨 CRITICAL OVERRIDE" if p.get("is_critical_override") else ""
                        with st.expander(f"[{sev}] {path_str} (Score: {score:.1f}){override}"):
                            st.write(f"**Explanation:** {p.get('explanation')}")
                            st.write(
                                f"Data Sens: {p.get('data_sensitivity')} | "
                                f"Action Sens: {p.get('action_sensitivity')} | "
                                f"Ext Exposure: {p.get('external_exposure')} | "
                                f"Chain Risk: {p.get('chain_risk')}"
                            )
                else:
                    st.info("No paths available yet from backend API.")
            else:
                st.info("Causal capability graph: Agent -> Tool -> Resource -> Action -> Destination. (Backend API offline)")
        except Exception:
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
