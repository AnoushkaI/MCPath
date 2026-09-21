# MCPath: A Runtime Zero-Trust MCP Security Proxy

> **Architecture v2**: Sequential Risk-Pipeline Architecture for Tool-Integrity, Capability, Intent, Behaviour, and Response Verification.

MCPath sits directly in-line between any standard MCP Host (such as **Claude Desktop**, Cursor, Windsurf, or custom agent stacks) and downstream MCP servers. Every tool call passes through a fixed, ordered six-stage pipeline, culminating in a deterministic Risk Engine decision with attributable evidence across all stages.

```
+---------------------------+
| Claude Desktop / MCP Host |
+---------------------------+
              | (stdio MCP JSON-RPC)
              v
+---------------------------+     Live Observability      +-----------------+      +------------+
|       MCPath Proxy        | --------------------------> | FastAPI Backend | ---> | PostgreSQL |
+---------------------------+       (Non-blocking)        +-----------------+      +------------+
  1. Hash Check (Stage 1)                                                                |
  2. Capability Risk (Stage 2)                                                           v
  3. Intent Risk (Stage 3)                                                        +---------------+
  4. Behaviour Deviation (Stage 4)                                                |   Dashboard   |
  5. Response Risk (Stage 5)                                                      | (Admin / Sec) |
  6. Deterministic Risk Engine (Stage 6)                                          +---------------+
              |
              v (Forwarded only if ALLOW)
+---------------------------+
|        MCP Server         |
+---------------------------+
```

---

## Architectural Principles & Strict Boundaries

1. **No Custom Chatbot / Agent**: MCPath is strictly an in-line security proxy. Claude Desktop (or any standard MCP client) remains the unmodified conversational agent.
2. **Separation of Paths**:
   - **Live Enforcement Path**: `MCP Host -> MCPath Proxy -> MCP Server`. This path alone decides whether to allow, hold, or block calls.
   - **Observability Path**: `MCPath Proxy -> FastAPI Backend -> PostgreSQL -> Dashboard`. The dashboard is a read-only analyst interface and never influences live enforcement.
3. **Deterministic Risk Engine**: The final ALLOW / HOLD / BLOCK decision is produced by explicit hard gates and threshold logic in Python. **An LLM never makes the final enforcement decision.**
4. **Attributable Explainability (Section 7)**: Every decision produces a full evidence breakdown across all stages (no opaque 0-100 blended trust scores).
5. **Dynamic & Server-Agnostic**: Changing downstream MCP servers automatically updates tool discovery and rebuilds the capability graph without modifying pipeline code.

---

## Directory Structure

```text
mcpath/
├── config/             # Configuration loading (Pydantic Settings, JSON configs)
│   ├── settings.py
│   └── server_config.json
├── core/               # Shared utilities, exceptions, and stdio-safe logging
│   ├── logging.py      # Guaranteed routing of logs to sys.stderr (preserves stdout JSON-RPC)
│   └── exceptions.py   # SecurityGateViolation, HashMismatchError, DownstreamConnectionError
├── proxy/              # Core MCP-Native Proxy (Official MCP Python SDK)
│   ├── client_manager.py # Manages downstream MCP connection via stdio_client & ClientSession
│   ├── server.py       # Intercepting proxy server using lowlevel Server & stdio_server
│   ├── passthrough.py  # Passthrough router orchestrating client <-> proxy <-> downstream
│   └── run.py          # Stdio entrypoint for Claude Desktop and CLI
├── pipeline/           # Sequential Six-Stage Security Pipeline
│   ├── stage.py        # Base pipeline stage interface & PipelineContext
│   ├── stages/         # Individual stage implementations
│   │   ├── stage1_hash.py       # Stage 1: Tool Integrity Hash Check (SHA-256 canonical JSON)
│   │   ├── stage2_capability.py # Stage 2: Capability Risk scoring
│   │   ├── stage3_intent.py     # Stage 3: Semantic Intent Verification
│   │   ├── stage4_behaviour.py  # Stage 4: Behaviour Deviation against baseline
│   │   └── stage5_response.py   # Stage 5: Response Risk inspection
│   └── pipeline_runner.py       # Sequential pipeline coordinator
├── graph/              # Stage 2 Causal Capability Graph
│   └── capability_graph.py # NetworkX (Agent -> Tool -> Resource -> Action -> Destination)
├── baseline/           # Stage 4 Behaviour Baseline
│   └── behaviour_baseline.py # Statistical trace store for proxy-observable parameters
├── response/           # Stage 5 Response Inspector
│   └── inspector.py    # Regex pattern heuristics & secondary bounded LLM classifier
├── risk_engine/        # Stage 6 Deterministic Risk Engine
│   ├── models.py       # RiskScores, EnforcementDecision (ALLOW, HOLD, BLOCK), SecurityEventRecord
│   ├── engine.py       # Deterministic rule engine (hard gates first, then thresholds)
│   └── explainability.py # Section 7 attributable evidence formatter
├── backend/            # Observability & Evidence API (FastAPI)
│   ├── app.py          # FastAPI application & health check
│   ├── routes/         # REST endpoints for Overview, Events, and Server Switching
│   └── persistence/    # PostgreSQL / SQLite async engine and SQLAlchemy models
├── dashboard/          # Admin / Security Analyst UI (Streamlit / React)
│   └── app.py          # Observability dashboard tabs
├── evaluation/         # Benchmark & Evaluation Suite
│   ├── dataset.py      # Schema for labelled scenarios (normal, rug pull, capability chain, etc.)
│   ├── metrics.py      # Precision, Recall, F1, FPR, FNR, Latency ([TO BE MEASURED] default)
│   └── runner.py       # Evaluation runner across 5 attack categories
mock_servers/           # Reference / Mock MCP servers
│   └── sample_server.py # Test server with echo, calculate, read_customer (PII), send_email
tests/                  # Comprehensive Pytest suite
│   ├── test_passthrough.py       # End-to-end proxy and stdio passthrough verification
│   ├── test_pipeline_skeleton.py # Pipeline contracts and explainability format tests
│   └── test_backend_skeleton.py  # FastAPI routes and health tests
run_proxy.py            # Convenience script to start MCPath proxy
run_mock_server.py      # Convenience script to start mock MCP server
requirements.txt        # Python dependencies
.env.example            # Environment configuration template
```

---

## Installation

1. **Clone or navigate to the project directory**:
   ```bash
   cd "c:\projects\mcp proxy"
   ```

2. **Create and activate a virtual environment (optional but recommended)**:
   ```bash
   python -m venv venv
   .\venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize environment**:
   ```bash
   copy .env.example .env
   ```

---

## Running the Proxy

### Option A: Standalone Stdio Proxy (Default)
By default, MCPath connects to the reference mock server (`mock_servers/sample_server.py`):
```bash
python run_proxy.py
```
To run against a specific downstream server defined in `config/server_config.json`:
```bash
python run_proxy.py --server sample_reference_server --log-level INFO
```

### Option B: Connecting Claude Desktop to MCPath
Add MCPath as an MCP server in your Claude Desktop configuration (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "mcpath-secure-proxy": {
      "command": "python",
      "args": [
        "c:\\projects\\mcp proxy\\run_proxy.py",
        "--server",
        "sample_reference_server"
      ]
    }
  }
}
```
When Claude Desktop starts, it communicates with MCPath, and MCPath transparently intercepts and proxies all tool calls to the downstream MCP server.

---

## Running the FastAPI Observability Backend

```bash
uvicorn mcpath.backend.app:app --host 127.0.0.1 --port 8000 --reload
```
View Swagger API documentation at: `http://127.0.0.1:8000/docs`

---

## Testing & Verifying Passthrough (Day 1 Milestone)

Run the automated test suite with `pytest`:
```bash
pytest -v
```

This verifies the complete Day 1 milestone:
1. **Proxy Starts**: The MCP Server starts and accepts client connections.
2. **MCP Server Connects**: Downstream server connection is established via the official MCP SDK.
3. **`tools/list` Works**: Discovered downstream tools are returned to the client unmodified.
4. **`tools/call` Works**: Client calls `echo` and `calculate` through the proxy.
5. **Response Reaches Client**: Output from the downstream tool returns to the client intact.
