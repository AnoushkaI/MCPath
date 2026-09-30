# MCPath: Runtime Zero-Trust Security Proxy for MCP

[![Tests](https://img.shields.io/badge/tests-141%20passed%20(100%25)-brightgreen)](file:///c:/projects/mcp%20proxy/tests)
[![Evaluation Benchmark](https://img.shields.io/badge/benchmark-48%2F48%20scenarios%20(100%25)-brightgreen)](file:///c:/projects/mcp%20proxy/evaluation)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![MCP SDK](https://img.shields.io/badge/MCP-Official%20Python%20SDK-purple)](https://github.com/modelcontextprotocol/python-sdk)
[![FastAPI](https://img.shields.io/badge/API-FastAPI-009688)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/SOC%20Dashboard-Streamlit-FF4B4B)](https://streamlit.io/)
[![GitHub branch](https://img.shields.io/badge/branch-test-blue)](https://github.com/AnoushkaI/MCPath/tree/test)

**MCPath** is an in-line, zero-trust security proxy purpose-built for the **Model Context Protocol (MCP)**. It sits transparently between any MCP host (such as **Claude Desktop**, Cursor, Windsurf, or custom agent frameworks) and downstream MCP servers.

Every single tool discovery, execution request, and response passes through a deterministic **6-stage sequential risk pipeline**, ensuring tool integrity, capability topology compliance, semantic intent alignment, and administrative oversight **before** any command reaches a downstream server.

---

## 🏛️ System Architecture

MCPath enforces a strict separation between the **Live Enforcement Path** (stdio, sub-50ms latency gate) and the **Asynchronous Observability Path** (REST API, database persistence, and SOC dashboard):

```
                                  +---------------------------+
                                  | Claude Desktop / MCP Host |
                                  +---------------------------+
                                                |
                                                | stdio (MCP JSON-RPC)
                                                v
+---------------------------------------------------------------------------------------------------+
|                                       MCPATH IN-LINE PROXY                                        |
|                                                                                                   |
|  [Stage 1: Tool Integrity Hash] ──► Hard Gate: Canonical SHA-256 Baseline Match                   |
|               │                                                                                   |
|  [Stage 2: Capability Graph]   ──► Causal Topology Risk & Sensitive Data Path Overrides           |
|               │                                                                                   |
|  [Stage 3: Semantic Intent]    ──► Sentence-Transformers (all-MiniLM-L6-v2) User Prompt Alignment |
|               │                                                                                   |
|  [Stage 4: Behaviour Baseline] ──► Statistical Trace Deviation Check                              |
|               │                                                                                   |
|  [Stage 6: Risk Engine]        ──► Deterministic Rule Engine                                      |
|               │                    ├── BLOCK (Score >= 70.0 or Hard Gate)                         |
|               │                    ├── HOLD  (Score 30.0 - 69.9) ──► Admin Approval Queue         |
|               │                    └── ALLOW (Score < 30.0)                                       |
|               ▼ (Forwarded ONLY if Approved / Allowed)                                            |
|  [Stage 5: Response Inspector] ──► Post-execution Sensitive Content & Exfiltration Check          |
+---------------------------------------------------------------------------------------------------+
        │                                                           │
        │ Downstream stdio                                          │ Async Telemetry & Control IPC
        v                                                           v
+-----------------------+                                  +-----------------+      +------------+
| Downstream MCP Server |                                  | FastAPI Backend | ---> | PostgreSQL |
| (Filesystem, Git,     |                                  |   (Port 8000)   |      |  (9 Tables)|
|  Postgres, Custom)    |                                  +-----------------+      +------------+
+-----------------------+                                           │                      │
                                                                    v                      v
                                                           +-------------------------------------+
                                                           |        Streamlit SOC Dashboard      |
                                                           | (8 Pages: Graph, Approvals, Events) |
                                                           +-------------------------------------+
```

---

## 🛡️ The 6-Stage Security Pipeline

| Stage | Name | Mechanism | Enforcement Authority |
|---|---|---|---|
| **Stage 1** | **Tool Integrity Hash** | Canonical JSON SHA-256 hash comparison against approved database baseline | **Hard Gate**: Fail-closed `BLOCK` on `NO_APPROVED_BASELINE` or `HASH_MISMATCH` (Rug-Pull prevention). |
| **Stage 2** | **Capability Graph Risk** | Typed-edge causal graph (`Agent → Tool → Resource → Action → Destination`) with NetworkX. Separates direct runtime paths from uninvoked potential paths. | Critical-path override triggers `BLOCK` (90.0) on unauthorized external exfiltration chains. |
| **Stage 3** | **Semantic Intent Risk** | Cosine similarity between user prompt embeddings and concise primary tool actions using `all-MiniLM-L6-v2`. | Inverted score `(1 - sim) * 100`. Flags prompt injection and out-of-context invocations. |
| **Stage 4** | **Behaviour Baseline** | Statistical baseline comparison across argument shapes, invocation cadence, and temporal features. | Scored 0–100 deviation scoring. |
| **Stage 5** | **Response Risk** | Post-execution response inspection for token leaks, system secrets, and exfiltration artifacts. | Post-call inspection before returning result to MCP host. |
| **Stage 6** | **Deterministic Risk Engine** | Hard rule ordering followed by multi-stage score aggregation: `max(Stage 2..5)`. | **The sole enforcement decision-maker**: `ALLOW` (<30.0), `HOLD` (30.0–69.9), or `BLOCK` (≥70.0). **No black-box LLM decision-making.** |

---

## ⚡ Key Highlights & Features

### 1. Controlled Admin Approval Workflow (HOLD State)
- When a tool call evaluates to `HOLD` (e.g., reading `.env`, accessing sensitive user tables, or borderline prompts), the proxy **pauses execution** asynchronously.
- The request enters the PostgreSQL approval queue (`pending_approvals`).
- A non-intrusive **2-second polling global banner** alerts administrators across all pages in the Streamlit SOC dashboard.
- **Admin Approve:** Downstream tool runs exactly once and securely returns the result to Claude.
- **Admin Reject:** Downstream execution is prevented, returning a clean security rejection.
- **Auto-Timeout & Replay Protection:** Pending requests auto-expire after 30 seconds and can never be re-executed or replayed.

### 2. Zero-Trust Server Lifecycle: "Adding != Trusting"
- Discovered downstream servers are registered in an **`UNTRUSTED`** state by default.
- Even if active, unapproved tools lack a cryptographic baseline (`NO_APPROVED_BASELINE`) and are blocked fail-closed by Stage 1.
- Only an explicit **`Trust & Register`** action canonicalizes tool schemas and writes approved SHA-256 baselines into PostgreSQL.

### 3. Streamlit SOC Dashboard (8 Dedicated Pages)
1. **Security Overview:** Real-time SOC metrics, fleet status, and incident trends.
2. **Live Runtime Monitor:** Live streaming of intercepted calls and latency tracking.
3. **Capability Graph:** Interactive 2D/3D visualization of tool, resource, and destination risk paths.
4. **Risk Analysis:** In-depth breakdown of capability, intent, and behavioral scores.
5. **MCP Servers:** Dynamic server discovery, registration, activation/deactivation, and fleet management.
6. **Security Events:** Searchable forensic audit log with immutable hash histories.
7. **Tool Baseline Inspector:** Side-by-side JSON diffs comparing observed vs. approved tool definitions.
8. **Admin Approvals:** Dedicated queue for pending `HOLD` calls with countdown timers and masked arguments.

### 4. 100% Benchmark Evaluation Success
- Evaluated against **48 real-world attack and baseline scenarios** covering 41 tools across 5 downstream servers:
  - **Pass Rate:** `100.0%` (48/48)
  - **False Positive Rate (FPR):** `0.0%`
  - **False Negative Rate (FNR):** `0.0%`
  - **Average Block Latency:** `28.8 ms` (Well within the ≤50 ms target)

---

## 📂 Repository Layout

```text
mcpath-proxy/
├── config/                         # Server definitions & security policies
│   ├── server_config.json          # Downstream server fleet registry
│   ├── capability_policy.json      # Stage 2 capability sensitivity & routing rules
│   └── intent_policy.json          # Stage 3 semantic embedding thresholds
├── frontend/streamlit_app/         # SOC Analyst & Security Dashboard
│   ├── app.py                      # Main entrypoint & real-time approval badge
│   ├── api_client.py               # REST client for FastAPI backend
│   ├── styles.py                   # High-contrast Cyberpunk/SOC dark theme
│   ├── components/                 # Global real-time approval banner fragment
│   └── pages/                      # 8 Dedicated SOC management pages
├── mcpath/
│   ├── backend/                    # Observability & Evidence API (FastAPI)
│   │   ├── app.py                  # FastAPI service entrypoint
│   │   ├── routes/                 # REST endpoints (servers, approvals, events, etc.)
│   │   └── persistence/            # Async SQLAlchemy models (PostgreSQL & SQLite)
│   ├── graph/                      # Capability graph modeling & inference
│   │   ├── capability_graph.py     # NetworkX causal graph representation
│   │   └── capability_inference.py # Automatic tool-to-resource inference
│   ├── pipeline/                   # Sequential Six-Stage Security Pipeline
│   │   ├── pipeline_runner.py      # Pre-call & post-call pipeline coordinator
│   │   └── stages/                 # Stage 1 to Stage 5 implementations
│   ├── proxy/                      # Low-level MCP Proxy Server
│   │   ├── server.py               # JSON-RPC interceptor & stdio handler
│   │   ├── client_manager.py       # Multi-server downstream connection manager
│   │   ├── control.py              # IPC control server for approval signals
│   │   └── approval_manager.py     # Asynchronous HOLD queue & timeout manager
│   └── risk_engine/                # Stage 6 Deterministic Decision Engine
│       ├── engine.py               # Hard gate & threshold evaluator
│       └── explainability.py       # Attributable evidence formatter
├── mock_servers/                   # Verification & simulation servers
│   ├── rugpullserver.py            # Simulates dynamic schema rug-pull attacks
│   ├── email_server.py             # Mock exfiltration destination
│   └── sample_server.py            # Reference MCP server
├── tests/                          # 141 comprehensive automated tests
├── evaluation/                     # 48-scenario benchmark evaluation suite
├── run_proxy.py                    # Stdio Proxy launch script
├── run_register.py                 # Tool trust & baseline registration utility
├── run_evaluation.py               # Automated benchmark evaluation runner
└── verify_real_servers.py          # Real-world multi-server verification script
```

---

## 🚀 Quickstart Guide

### 1. Prerequisites
- **Python 3.10+** (Python 3.11 recommended)
- **Node.js 18+ & npx** (for running standard MCP servers like filesystem and postgres)
- **PostgreSQL** (or automatic SQLite fallback)

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/AnoushkaI/MCPath.git
cd MCPath

# Create and activate virtual environment
python -m venv .venv
# On Windows:
.\.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
```

### 3. Configure `.env`
Edit your `.env` file with appropriate paths and database credentials:
```env
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/mcpath_db
FILESYSTEM_ALLOWED_PATHS=C:\projects\mcp-demos\filesystem
GIT_REPOSITORY_PATH=C:\projects\mcp-demos\GitRepo
POSTGRES_MCP_CONNECTION_STRING=postgresql://postgres:postgres@localhost:5432/mcpath_demo_db
```

---

## 💻 Running MCPath

### Option 1: Start the Stdio Proxy (for Claude Desktop / MCP Clients)
```bash
python run_proxy.py
```

To configure **Claude Desktop** to run through MCPath, add the proxy to your `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "mcpath-proxy": {
      "command": "python",
      "args": [
        "C:\\projects\\mcp proxy\\run_proxy.py"
      ]
    }
  }
}
```

### Option 2: Start the FastAPI Observability Backend
```bash
uvicorn mcpath.backend.app:app --host 127.0.0.1 --port 8000 --reload
```
- Interactive Swagger documentation: `http://127.0.0.1:8000/docs`

### Option 3: Start the Streamlit SOC Dashboard
```bash
streamlit run frontend/streamlit_app/app.py
```
- SOC Dashboard access: `http://localhost:8501`

---

## 🧪 Testing & Verification

### Running the Full Test Suite
MCPath includes 141 comprehensive tests verifying end-to-end proxying, hash verification, causal graph routing, admin approvals, and server state synchronizations:
```bash
pytest -v
```

### Running the 48-Scenario Evaluation Benchmark
Run the automated attack benchmark suite to evaluate detection precision, recall, and latency:
```bash
python run_evaluation.py
```

### Verifying Multi-Server Integration
Validate concurrent downstream connections across real Filesystem, Git, and PostgreSQL MCP servers:
```bash
python verify_real_servers.py
```

---

## 🔒 Security Model Summary

1. **Deterministic Authority**: Hard gates and threshold rules in Python determine every ALLOW/HOLD/BLOCK decision. An LLM never makes the final security verdict.
2. **Attributable Explainability**: Every event provides unambiguous evidence attribution across all 5 stages—no opaque, unexplainable 0–100 composite scores.
3. **Fail-Closed Guarantees**: Any tool lacking an approved cryptographic baseline or presenting a tampered schema is immediately blocked before invocation.
4. **Non-Intrusive In-Line Architecture**: Claude Desktop and standard MCP hosts require zero code changes or special plugins—MCPath conforms strictly to the standard MCP specification over stdio.

---

## 📄 License
This project is licensed under the Apache 2.0 License.
