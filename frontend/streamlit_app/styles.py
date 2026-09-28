"""Professional Cybersecurity & SOC-style styling for MCPath Dashboard."""

from typing import Optional
import streamlit as st


SOC_CSS = """
<style>
/* -------------------------------------------------------------
   MCPath Zero-Trust SOC Dashboard Theme
   Palette: Cyber Slate #0b0f19, Deep Surface #111827, Panel #0f172a,
            Accent Cyan #00f0ff, Emerald #10b981, Amber #f59e0b, Crimson #ef4444,
            High-Contrast Text: Primary #f8fafc, Secondary #cbd5e1, Muted #94a3b8
   ------------------------------------------------------------- */

/* Root & Global Container */
:root {
    --text-color: #f1f5f9;
    --background-color: #0b0f19;
    --secondary-background-color: #111827;
    --primary-color: #00f0ff;
}

.stApp {
    background-color: #0b0f19 !important;
    color: #e2e8f0 !important;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}

/* Headings */
h1, h2, h3, h4, h5, h6 {
    color: #f8fafc !important;
    font-weight: 700 !important;
}

p, span, div {
    color: inherit;
}

/* Top Navigation / App Header */
header[data-testid="stHeader"] {
    background-color: #0b0f19 !important;
    border-bottom: 1px solid #1e293b !important;
}

/* Sidebar styling */
section[data-testid="stSidebar"] {
    background-color: #0f172a !important;
    border-right: 1px solid #1e293b !important;
}

section[data-testid="stSidebar"] * {
    color: #cbd5e1;
}

/* Sidebar Navigation Links (Streamlit 1.35+ st.navigation) */
[data-testid="stSidebarNav"] a,
[data-testid="stSidebarNavLink"],
[data-testid="stSidebarNavLink"] span,
[data-testid="stSidebarNavItems"] span {
    color: #e2e8f0 !important;
    font-weight: 500 !important;
    font-size: 0.92rem !important;
    text-decoration: none !important;
    opacity: 1 !important;
}

[data-testid="stSidebarNavLink"]:hover,
[data-testid="stSidebarNavLink"]:hover span {
    color: #ffffff !important;
    background-color: rgba(255, 255, 255, 0.08) !important;
}

/* Active Sidebar Navigation Item */
[data-testid="stSidebarNavLink"][aria-current="page"],
[data-testid="stSidebarNavLink"][aria-current="page"] span,
[data-testid="stSidebarNavLink"].active,
[data-testid="stSidebarNavLink"].active span {
    color: #00f0ff !important;
    font-weight: 700 !important;
    background-color: rgba(0, 240, 255, 0.12) !important;
    border-left: 3px solid #00f0ff !important;
}

/* Header bar styling */
.soc-header {
    background: linear-gradient(90deg, #111827 0%, #0f172a 100%);
    border: 1px solid #1e293b;
    border-left: 4px solid #00f0ff;
    border-radius: 8px;
    padding: 18px 24px;
    margin-bottom: 24px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
}

.soc-header-title {
    font-size: 1.6rem;
    font-weight: 700;
    color: #f8fafc;
    letter-spacing: -0.02em;
    display: flex;
    align-items: center;
    gap: 12px;
}

.soc-header-subtitle {
    font-size: 0.88rem;
    color: #cbd5e1;
    margin-top: 4px;
}

/* SOC Metric Cards */
.soc-card {
    background-color: #111827;
    border: 1px solid #1f2937;
    border-radius: 8px;
    padding: 16px 20px;
    transition: transform 0.15s ease, border-color 0.15s ease;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
}

.soc-card:hover {
    border-color: #374151;
    transform: translateY(-2px);
}

.soc-card-cyan { border-top: 3px solid #00f0ff; }
.soc-card-emerald { border-top: 3px solid #10b981; }
.soc-card-amber { border-top: 3px solid #f59e0b; }
.soc-card-crimson { border-top: 3px solid #ef4444; }
.soc-card-indigo { border-top: 3px solid #818cf8; }

.soc-card-label {
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #cbd5e1;
    font-weight: 600;
    margin-bottom: 6px;
}

.soc-card-value {
    font-size: 2rem;
    font-weight: 700;
    color: #f8fafc;
    line-height: 1.1;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}

.soc-card-subtext {
    font-size: 0.75rem;
    color: #94a3b8;
    margin-top: 6px;
}

/* Built-in Streamlit Metrics */
div[data-testid="stMetric"] {
    background-color: #111827 !important;
    border: 1px solid #1e293b !important;
    border-radius: 8px !important;
    padding: 12px 16px !important;
}

div[data-testid="stMetricLabel"] p {
    color: #cbd5e1 !important;
    font-size: 0.8rem !important;
    font-weight: 600 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.05em !important;
}

div[data-testid="stMetricValue"] div {
    color: #f8fafc !important;
    font-weight: 700 !important;
}

/* Decision Badges */
.badge-allow {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 9999px;
    background-color: rgba(16, 185, 129, 0.18);
    color: #34d399;
    border: 1px solid rgba(16, 185, 129, 0.5);
    font-size: 0.78rem;
    font-weight: 700;
    letter-spacing: 0.05em;
}

.badge-hold {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 9999px;
    background-color: rgba(245, 158, 11, 0.18);
    color: #fbbf24;
    border: 1px solid rgba(245, 158, 11, 0.5);
    font-size: 0.78rem;
    font-weight: 700;
    letter-spacing: 0.05em;
}

.badge-block {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 9999px;
    background-color: rgba(239, 68, 68, 0.18);
    color: #f87171;
    border: 1px solid rgba(239, 68, 68, 0.5);
    font-size: 0.78rem;
    font-weight: 700;
    letter-spacing: 0.05em;
}

.badge-trusted {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    background-color: rgba(16, 185, 129, 0.2);
    color: #34d399;
    border: 1px solid #059669;
    font-size: 0.75rem;
    font-weight: 600;
}

.badge-untrusted {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    background-color: rgba(245, 158, 11, 0.2);
    color: #fbbf24;
    border: 1px solid #d97706;
    font-size: 0.75rem;
    font-weight: 600;
}

.badge-mismatch {
    display: inline-block;
    padding: 3px 9px;
    border-radius: 4px;
    background-color: rgba(239, 68, 68, 0.25);
    color: #fca5a5;
    border: 1px solid #dc2626;
    font-size: 0.75rem;
    font-weight: 700;
    animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
}

.badge-match {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    background-color: rgba(16, 185, 129, 0.15);
    color: #6ee7b7;
    border: 1px solid #059669;
    font-size: 0.75rem;
    font-weight: 600;
}

.badge-nobaseline {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    background-color: rgba(148, 163, 184, 0.2);
    color: #cbd5e1;
    border: 1px solid #64748b;
    font-size: 0.75rem;
    font-weight: 600;
}

/* Monospace Code & Hash Styling */
.hash-code {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 0.76rem;
    background-color: #030712;
    color: #38bdf8;
    padding: 3px 6px;
    border-radius: 4px;
    border: 1px solid #1e293b;
    word-break: break-all;
}

.hash-mismatch-code {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 0.76rem;
    background-color: rgba(239, 68, 68, 0.12);
    color: #f87171;
    padding: 3px 6px;
    border-radius: 4px;
    border: 1px solid rgba(239, 68, 68, 0.4);
    word-break: break-all;
}

/* Banner Alert Box */
.soc-alert-box {
    background: linear-gradient(90deg, rgba(239, 68, 68, 0.15) 0%, rgba(17, 24, 39, 0.8) 100%);
    border: 1px solid rgba(239, 68, 68, 0.5);
    border-left: 5px solid #ef4444;
    border-radius: 8px;
    padding: 16px 20px;
    margin-bottom: 20px;
    color: #fecaca;
}

.soc-alert-title {
    font-size: 1.05rem;
    font-weight: 700;
    color: #f87171;
    display: flex;
    align-items: center;
    gap: 8px;
}

.soc-alert-desc {
    font-size: 0.85rem;
    color: #fca5a5;
    margin-top: 4px;
}

/* Pipeline Stage Pill Cards */
.stage-card {
    background-color: #111827;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 14px 16px;
    height: 100%;
}

.stage-card-active {
    border-top: 3px solid #10b981;
}

.stage-card-stub {
    border-top: 3px solid #64748b;
}

.stage-num {
    font-size: 0.72rem;
    text-transform: uppercase;
    font-weight: 700;
    letter-spacing: 0.08em;
    color: #38bdf8;
}

.stage-title {
    font-size: 0.95rem;
    font-weight: 700;
    color: #f1f5f9;
    margin: 4px 0;
}

.stage-type {
    font-size: 0.75rem;
    color: #cbd5e1;
}

/* Buttons */
.stButton > button,
button[data-testid="baseButton-secondary"] {
    background-color: #1e293b !important;
    color: #f8fafc !important;
    border: 1px solid #334155 !important;
    border-radius: 6px !important;
    font-weight: 600 !important;
    font-size: 0.88rem !important;
    transition: all 0.15s ease !important;
}

.stButton > button:hover,
button[data-testid="baseButton-secondary"]:hover {
    background-color: #334155 !important;
    color: #ffffff !important;
    border-color: #00f0ff !important;
    box-shadow: 0 0 10px rgba(0, 240, 255, 0.2) !important;
}

button[data-testid="baseButton-primary"] {
    background-color: #0284c7 !important;
    color: #ffffff !important;
    border: 1px solid #38bdf8 !important;
    border-radius: 6px !important;
    font-weight: 600 !important;
}

button[data-testid="baseButton-primary"]:hover {
    background-color: #0369a1 !important;
    border-color: #00f0ff !important;
}

.stDownloadButton > button {
    background-color: #1e293b !important;
    color: #f8fafc !important;
    border: 1px solid #334155 !important;
    font-weight: 600 !important;
}

.stDownloadButton > button:hover {
    background-color: #334155 !important;
    border-color: #00f0ff !important;
    color: #ffffff !important;
}

/* Form Inputs & Labels */
label[data-testid="stWidgetLabel"],
label[data-testid="stWidgetLabel"] p,
div[data-testid="stWidgetLabel"] p {
    color: #e2e8f0 !important;
    font-weight: 600 !important;
    font-size: 0.88rem !important;
}

div[data-testid="stCaptionContainer"] p,
.stCaption,
small {
    color: #94a3b8 !important;
    font-size: 0.82rem !important;
}

div[data-baseweb="input"] input,
div[data-baseweb="textarea"] textarea,
input[type="text"],
textarea {
    background-color: #111827 !important;
    color: #f8fafc !important;
    border-color: #334155 !important;
    font-size: 0.9rem !important;
}

div[data-baseweb="input"] input::placeholder,
textarea::placeholder {
    color: #94a3b8 !important;
    opacity: 1 !important;
}

/* Selectbox & Dropdowns (BaseWeb) */
div[data-baseweb="select"] {
    background-color: #111827 !important;
    border: 1px solid #334155 !important;
    border-radius: 6px !important;
}

div[data-baseweb="select"] * {
    color: #f8fafc !important;
}

div[data-baseweb="popover"],
ul[role="listbox"] {
    background-color: #111827 !important;
    border: 1px solid #334155 !important;
}

li[role="option"] {
    background-color: #111827 !important;
    color: #e2e8f0 !important;
}

li[role="option"]:hover,
li[role="option"][aria-selected="true"] {
    background-color: #1e293b !important;
    color: #00f0ff !important;
}

/* Radio buttons & Checkboxes */
div[data-testid="stRadio"] label p,
div[data-testid="stCheckbox"] label p {
    color: #f1f5f9 !important;
    font-size: 0.9rem !important;
    font-weight: 500 !important;
}

/* Tabs */
div[data-baseweb="tab-list"] {
    border-bottom: 1px solid #1e293b !important;
    gap: 4px;
}

button[data-baseweb="tab"] {
    color: #94a3b8 !important;
    font-weight: 500 !important;
    font-size: 0.9rem !important;
    background: transparent !important;
    border: none !important;
}

button[data-baseweb="tab"]:hover {
    color: #f8fafc !important;
}

button[data-baseweb="tab"][aria-selected="true"] {
    color: #00f0ff !important;
    font-weight: 700 !important;
    border-bottom: 2px solid #00f0ff !important;
}

button[data-baseweb="tab"] p {
    color: inherit !important;
}

/* Expander styling */
div[data-testid="stExpander"] {
    background-color: #111827 !important;
    border: 1px solid #1e293b !important;
    border-radius: 8px !important;
    margin-bottom: 10px !important;
}

div[data-testid="stExpander"] details {
    border: none !important;
}

div[data-testid="stExpander"] summary {
    background-color: #111827 !important;
    color: #f8fafc !important;
    font-weight: 600 !important;
    border-radius: 8px !important;
}

div[data-testid="stExpander"] summary p {
    color: #f8fafc !important;
    font-weight: 600 !important;
}

div[data-testid="stExpander"] summary:hover p {
    color: #00f0ff !important;
}

/* Streamlit DataFrames and Tables */
div[data-testid="stDataFrame"],
div[data-testid="stTable"] {
    background-color: #111827 !important;
    border: 1px solid #1e293b !important;
    border-radius: 6px !important;
    overflow: hidden;
}

div[data-testid="stTable"] table {
    color: #e2e8f0 !important;
    background-color: #111827 !important;
}

div[data-testid="stTable"] th {
    background-color: #1e293b !important;
    color: #f8fafc !important;
    font-weight: 700 !important;
    border-bottom: 1px solid #334155 !important;
}

div[data-testid="stTable"] td {
    border-bottom: 1px solid #1e293b !important;
    color: #e2e8f0 !important;
}

/* Code Blocks & Pre */
div[data-testid="stCodeBlock"] pre,
code {
    background-color: #030712 !important;
    color: #38bdf8 !important;
    border: 1px solid #1e293b !important;
    border-radius: 4px !important;
}

/* Animations */
@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: .5; }
}
</style>
"""


def apply_soc_styles():
    """Inject custom SOC theme CSS into the current Streamlit page."""
    st.markdown(SOC_CSS, unsafe_allow_html=True)


def render_header(
    title: str,
    subtitle: str,
    badge_text: str = "ZERO-TRUST SOC",
    badge_color: str = "#00f0ff"
):
    """Render a consistent cybersecurity header bar."""
    html = f"""
    <div class="soc-header">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
            <div>
                <div class="soc-header-title">
                    <span>🛡️ {title}</span>
                    <span style="font-size: 0.7rem; font-weight: 700; background: rgba(0, 240, 255, 0.12); color: {badge_color}; border: 1px solid {badge_color}; padding: 2px 8px; border-radius: 4px; letter-spacing: 0.06em;">
                        {badge_text}
                    </span>
                </div>
                <div class="soc-header-subtitle">{subtitle}</div>
            </div>
            <div style="text-align: right; font-family: ui-monospace, monospace; font-size: 0.78rem; color: #94a3b8;">
                <div>ENFORCEMENT: <span style="color: #10b981; font-weight: bold;">LIVE / ZERO-TRUST</span></div>
                <div>OBSERVABILITY: <span style="color: #38bdf8; font-weight: bold;">HTTP LOCALHOST</span></div>
            </div>
        </div>
    </div>
    """
    st.markdown(html, unsafe_allow_html=True)


def render_decision_badge(decision: str) -> str:
    """Return HTML string for decision badge."""
    dec = (decision or "UNKNOWN").upper()
    if dec == "ALLOW":
        return '<span class="badge-allow">● ALLOW</span>'
    elif dec == "HOLD":
        return '<span class="badge-hold">▲ HOLD</span>'
    elif dec == "BLOCK":
        return '<span class="badge-block">✖ BLOCK</span>'
    return f'<span class="badge-nobaseline">{dec}</span>'


def render_hash_badge(status: str) -> str:
    """Return HTML string for hash integrity status badge."""
    st_upper = (status or "").upper()
    if st_upper == "MATCH":
        return '<span class="badge-match">✔ MATCH</span>'
    elif st_upper in ("HASH_MISMATCH", "TAMPERED", "MISMATCH"):
        return '<span class="badge-mismatch">🚨 HASH MISMATCH</span>'
    elif st_upper == "NO_APPROVED_BASELINE":
        return '<span class="badge-nobaseline">⚠ NO BASELINE</span>'
    return f'<span class="badge-nobaseline">{status}</span>'


def render_trust_badge(status: str) -> str:
    """Return HTML string for server or tool trust badge."""
    st_upper = (status or "").upper()
    if st_upper == "TRUSTED":
        return '<span class="badge-trusted">TRUSTED</span>'
    elif st_upper in ("HASH_MISMATCH", "TAMPERED"):
        return '<span class="badge-mismatch">TAMPERED</span>'
    return '<span class="badge-untrusted">UNTRUSTED</span>'


def render_match_status_badge(status: Optional[str], path_id: Optional[str] = None) -> str:
    """Return HTML string for runtime capability match status."""
    st_upper = (status or "UNKNOWN").upper()
    if st_upper == "MATCHED":
        id_str = f" ({path_id})" if path_id else ""
        return f'<span class="badge-allow" style="font-family: monospace;">✔ MATCHED{id_str}</span>'
    elif st_upper == "UNMODELED":
        return '<span class="badge-hold" style="font-family: monospace;">▲ UNMODELED</span>'
    elif st_upper == "UNKNOWN":
        return '<span class="badge-block" style="font-family: monospace;">✖ UNKNOWN</span>'
    return f'<span class="badge-nobaseline">{status or "N/A"}</span>'


def render_path_id_badge(path_id: Optional[str]) -> str:
    """Render a persistent path ID pill."""
    if not path_id:
        return '<span style="color: #94a3b8; font-size: 0.75rem;">None</span>'
    return (
        f'<span style="font-family: ui-monospace, monospace; font-size: 0.75rem; '
        f'color: #38bdf8; background: rgba(56, 189, 248, 0.12); border: 1px solid rgba(56, 189, 248, 0.3); '
        f'padding: 2px 7px; border-radius: 4px; font-weight: 600;">🔑 {path_id}</span>'
    )


def render_severity_badge(classification: Optional[str], score: Optional[float] = None) -> str:
    """Render risk severity badge with optional score."""
    sev = (classification or "LOW").upper()
    score_str = f" ({score:.1f})" if score is not None else ""
    if sev == "HIGH":
        return f'<span class="badge-block" style="font-weight: 700;">🔴 HIGH{score_str}</span>'
    elif sev == "MEDIUM":
        return f'<span class="badge-hold" style="font-weight: 700;">🟡 MEDIUM{score_str}</span>'
    return f'<span class="badge-allow" style="font-weight: 700;">🟢 LOW{score_str}</span>'
