# MCPath: Project Context & Architecture Status

> **Persistent handoff document for AI coding agents.**
> *Rule for agents: Read this document before inspecting code or making changes. Update this document after completing any task to reflect the exact state of the codebase.*

---

## 1. Project Overview

- **What MCPath is**: A runtime Zero-Trust security proxy specifically built for the Model Context Protocol (MCP). It sits in-line between an MCP client (such as Claude Desktop, Cursor, Windsurf, or custom agent runtimes) and downstream MCP servers.
- **The Problem It Solves**: In standard MCP setups, clients blindly trust connected tool definitions, tool invocations, and server responses. This exposes AI systems to tool rug pulls (changing tool schemas/descriptions after approval), capability chain exploits (e.g. reading customer PII and exfiltrating via email), prompt injection/jailbreak intents, anomalous behavior deviations, and sensitive data leakage in tool outputs.
- **Where It Sits in MCP Architecture**: 
  - Standard setup: `MCP Client (Claude Desktop) <--- stdio/HTTP ---> MCP Server`
  - MCPath Multi-Server Architecture:
    ```
    Claude Desktop / Custom MCP Host
                  │
                  │ ONE stdio MCP connection (mcpath-proxy)
                  ▼
             MCPath Proxy
                  │
        ┌─────────┼─────────┐
        ▼         ▼         ▼
    Downstream  Downstream  Downstream
    MCP Client  MCP Client  MCP Client
    (Filesystem)  (Git)   (PostgreSQL)
                  │
                  ▼
          MCPath Security Pipeline
      Stage 1 → Stage 2 → Stage 3 → Stage 4
                  │
                  ▼
        Risk Engine (Phase 1: Pre-Execution)
                  │
                  ▼ (ONLY IF ALLOW)
        Target Downstream MCP Execution
                  │
                  ▼
              Stage 5 (Response Risk)
                  │
                  ▼
        Risk Engine (Phase 2: Post-Execution)
                  │
                  ▼
         Return Sanitized/Verified Response
    ```

---

## 2. Multi-Server Target Architecture & Core Components

```
+------------------------------------+
|  Claude Desktop / Custom MCP Host  |
+------------------------------------+
                  | (ONE stdio MCP JSON-RPC connection)
                  v
+------------------------------------+        Async Log Event        +-------------------------+      +-------------------+
|         MCPath Proxy Core          | ----------------------------> | FastAPI Backend Service | ---> |    PostgreSQL     |
+------------------------------------+     (Non-blocking write)      +-------------------------+      | (Primary Storage) |
  DownstreamClientManager                                                                             +-------------------+
    ├── Filesystem ClientSession                                                                                |
    ├── Git ClientSession                                                                                       v
    └── PostgreSQL ClientSession                                                                      +-------------------+
  Pipeline:                                                                                           | Streamlit / React |
    Phase 1 (Pre-Execution):                                                                          | Security Dashboard|
      Stage 1: Tool Integrity Hash Check (PostgreSQL Approved Baseline)                              +-------------------+
      Stage 2: Dynamic Capability Graph Risk
      Stage 3: Semantic Intent Verification
      Stage 4: Behaviour Deviation Detection
      Risk Engine Evaluation (ALLOW / HOLD / BLOCK)
    Phase 2 (Post-Execution):
      Target Downstream Subprocess Invocation (Only if ALLOW)
      Stage 5: Tool Response Risk Inspection
      Risk Engine Final Evaluation
```

### Core Subsystems & Components:
1. **Single Claude Connector**: Claude Desktop connects to exactly ONE `mcpath-proxy` server entry point without requiring any `--server` flags in Claude's configuration.
2. **Multi-Server Downstream Manager (`DownstreamClientManager`)**:
   - Maintains independent MCP client transports and sessions (`ClientSession`) for all configured downstream servers.
   - Fault-Isolated: A connection failure in one downstream server (e.g. Filesystem) does not terminate or impact others (Git or PostgreSQL).
   - Failed servers are logged in `unavailable_servers` and their tools are excluded from `tools/list`.
   - Never falls back to `sample_reference_server` (which is strictly for unit/regression tests).
3. **Aggregated Tool Catalog & Collision Handling**:
   - `tools/list` returns a single combined catalog across all healthy downstream servers.
   - Unique tools retain their original tool name, description, and input schema.
   - Colliding tools (identical name across multiple servers) are deterministically namespaced as `{server_name}_{tool_name}`.
   - An exact internal registry maps every `exposed_name -> (server_name, original_tool_name, tool_definition, approved_hash)`.
4. **Routed `tools/call`**:
   - Identifies the owning server from the exposed tool name.
   - Evaluates the call against the owning server's approved baseline hash in Stage 1.
   - Evaluates Stages 2-4 and Risk Engine Phase 1.
   - On ALLOW, routes invocation directly to the owning server's `ClientSession` using `original_tool_name`.
   - Tools belonging to Server A can NEVER be routed to Server B.
5. **Two-Phase Deterministic Risk Engine Enforcement**:
   - The Risk Engine is the SOLE deterministic enforcement authority. No LLM ever makes ALLOW/BLOCK/HOLD decisions.
   - Phase 1 (Pre-Execution): Evaluates Stages 1–4. If BLOCK/HOLD, stops execution immediately with zero downstream call.
   - Phase 2 (Post-Execution): If Phase 1 allowed and downstream tool executed, evaluates Stage 5 response risk and finalizes decision.
   - On Stage 1 Hard Block (hash mismatch or missing baseline), Stages 2–5 are explicitly recorded as `NOT_EXECUTED` (skipped).
6. **Dynamic Server Reloading (`POST /api/servers/reload`)**:
   - Reads current `server_config.json`, detects added/removed/changed servers.
   - Disconnects removed servers and establishes connections to newly added servers.
   - Rediscovers tools, recomputes collision mappings, and dynamically updates the capability graph.
   - Claude Desktop configuration remains completely unchanged.
7. **Observability Path**: `MCPath Proxy -> FastAPI Backend -> PostgreSQL -> Dashboard`. Emits structured `SecurityEventRecord`, `StageResultDB`, and `DecisionDB` records. The backend and dashboard are strictly read-only observers and have zero influence over live enforcement decisions.

---

## 3. Implemented So Far

### Current Milestone & Status
- **Current Milestone**: Multi-Server Architecture Complete — One Claude Connector proxying to Filesystem + Git + PostgreSQL.
- **All 28 automated tests passing** — unit tests for hash canonicalization, multi-server lifecycle, aggregated catalog, collision resolution, routing isolation, Stage 1 rug-pull blocking, fail-closed policy, dynamic reload, and backend endpoints.
- **Live Multi-Server & Real MCP Server Verification Confirmed** — `verify_real_servers.py` successfully connected to Filesystem, Git, and PostgreSQL simultaneously, aggregated 39 tools, routed calls through Stage 1 to each real server, and passed the controlled Claude Desktop rug-pull simulation.

### Working Features
- Single stdio proxy entrypoint for Claude Desktop (`run_proxy.py` / `mcpath.proxy.run`) managing multiple downstream servers.
- `DownstreamClientManager` with independent `AsyncExitStack` lifecycle per server, graceful fault isolation, and tool catalog aggregation.
- Deterministic namespace collision resolution: colliding tool names become `{server_name}_{tool_name}`; unique tools remain un-prefixed.
- Strict cross-server routing: tool calls route only to the owning server's `ClientSession` using the original tool name.
- Two-phase Risk Engine enforcement: pre-call (Stages 1-4) and post-call (Stage 5).
- Trusted Registration CLI (`python -m mcpath.register --all` or `--server <name>`) establishing approved baseline hashes in PostgreSQL.
- Discovery separation: runtime tool discovery and reload do NOT auto-approve hashes. Unapproved tools fail-closed with `NO_APPROVED_BASELINE`.
- Stage 1 Hash Integrity Check (`Stage1HashCheck`) with recursive JSON key sorting, canonicalization, SHA-256 hashing, and PostgreSQL `approved_hashes` lookup per `(server_name, tool_name)`.
- Dynamic controlled server reload endpoint (`POST /api/servers/reload`) refreshing active servers and rebuilding the capability graph without restarting Claude Desktop.
- PostgreSQL 8-table relational schema with SQLAlchemy models, foreign keys, unique constraints, and indexes.
- FastAPI backend application (`mcpath/backend/app.py`) with routes for overview, server inventory, tools, hashes, stage results, and reload.
- Real MCP server support:
  - `filesystem`: `cmd /c npx -y @modelcontextprotocol/server-filesystem ${FILESYSTEM_ALLOWED_PATHS}` (14 tools)
  - `git`: `uvx mcp-server-git --repository ${GIT_REPOSITORY_PATH}` (12 tools)
  - `postgres-mcp`: `cmd /c npx -y @microsoft/postgres-mcp@latest run` with `${POSTGRES_MCP_CONNECTION_STRING}` (13 tools)
  - Combined catalog: 39 tools exposed to Claude through one connection.

---

## 4. Claude Desktop Configuration

Claude Desktop requires ONLY ONE entry in its `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mcpath-proxy": {
      "command": "C:\\projects\\mcp proxy\\.venv\\Scripts\\python.exe",
      "args": [
        "C:\\projects\\mcp proxy\\run_proxy.py"
      ]
    }
  }
}
```

No `--server` arguments are required. MCPath automatically reads `config/server_config.json` and manages all configured active downstream servers (`filesystem`, `git`, `postgres-mcp`).

---

## 5. Security Pipeline & Evaluation Phases

The pipeline evaluates every intercepted call in two deterministic phases:

```
[Tool Call Received]
        │
        ▼
   [Stage 1: Tool Integrity Hash Check]
        │
        ├─► Mismatch / Missing Baseline ──► [BLOCK] (Downstream NOT called, Stages 2-5 marked NOT_EXECUTED)
        ▼ Match
   [Stage 2: Dynamic Capability Risk Graph]
        ▼
   [Stage 3: Semantic Intent Verification]
        ▼
   [Stage 4: Behaviour Deviation Detection]
        ▼
   [Risk Engine: Phase 1 Pre-Execution Evaluation]
        │
        ├─► Score >= Threshold / Hard Gate ──► [BLOCK / HOLD] (Downstream NOT called)
        ▼ ALLOW
   [Downstream MCP Execution] ──► Target server session invoked with original_tool_name
        │
        ▼ Tool Response
   [Stage 5: Response Risk Inspection]
        ▼
   [Risk Engine: Phase 2 Post-Execution Final Evaluation]
        │
        ├─► Response Leak Detected ──► [BLOCK / HOLD] (Response redacted or blocked)
        ▼ ALLOW
   [Return Response to Client]
```

| Stage | Name | Role & Question Answered | Status |
|---|---|---|---|
| **Stage 1** | **Tool Integrity Hash Check** | *"Has this tool's definition changed since it was approved?"* Computes SHA-256 over canonicalized JSON and compares against PostgreSQL `approved_hashes`. Mismatches trigger immediate hard block without evaluating later stages (stops tool rug pulls). Fail-closed on missing baseline/DB error. | **IMPLEMENTED** |
| **Stage 2** | **Capability Risk** | *"Can this tool access sensitive resources or chain to external exfiltration?"* Analyzes graph paths in NetworkX (Agent $\rightarrow$ Tool $\rightarrow$ Resource $\rightarrow$ Action $\rightarrow$ Destination) to produce risk score $[0, 100]$. Deterministic policy file (`config/capability_policy.json`), transition-based chain risk, critical override for sensitive $\rightarrow$ external paths, fail-safe unknown path elevated scoring. | **IMPLEMENTED** |
| **Stage 3** | **Intent Verification** | *"Does the requested tool call align with the user's explicit prompt?"* Compares embeddings of user prompt vs tool call semantics to detect prompt injection/jailbreak manipulation. | **SKELETON / READY FOR EXPANSION** |
| **Stage 4** | **Behaviour Deviation** | *"Is this call anomalous compared to historical baseline traces?"* Checks parameter sizes, invocation frequencies, and argument shapes against historical statistical baselines. | **SKELETON / READY FOR EXPANSION** |
| **Stage 5** | **Response Risk Inspection** | *"Does the downstream server output leak sensitive data (PII, API keys, credentials)?"* Inspects tool outputs using fast regex heuristics and optional secondary bounded classifier. | **SKELETON / READY FOR EXPANSION** |
| **Risk Engine** | **Deterministic Risk Engine** | *"What is the final enforcement decision?"* Evaluates hard-block gates first, then thresholds combined scores into `ALLOW`, `HOLD`, or `BLOCK`. Attaches complete explainability evidence. Evaluated in two phases: pre-call and post-call. | **IMPLEMENTED** |

---

## 6. How to Run and Verify

1. **Run full automated test suite (28 tests)**:
   ```powershell
   .venv\Scripts\python.exe -m pytest -v
   ```
2. **Run multi-server proxy tests specifically**:
   ```powershell
   .venv\Scripts\python.exe -m pytest tests/test_multi_server_proxy.py -v
   ```
3. **Run Trusted Registration for all configured servers**:
   ```powershell
   .venv\Scripts\python.exe -m mcpath.register --all
   ```
4. **Run Real Multi-Server End-to-End Verification (Filesystem + Git + PostgreSQL + Rug-Pull Test)**:
   ```powershell
   .venv\Scripts\python.exe verify_real_servers.py
   ```
5. **Run the Multi-Server Proxy for Claude Desktop**:
   ```powershell
   .venv\Scripts\python.exe run_proxy.py --log-level INFO
   ```
6. **Run FastAPI observability backend**:
   ```powershell
   .venv\Scripts\uvicorn.exe mcpath.backend.app:app --host 127.0.0.1 --port 8000 --reload
   ```
7. **Trigger Dynamic Server Reload**:
   ```powershell
   Invoke-RestMethod -Method POST -Uri "http://127.0.0.1:8000/api/servers/reload"
   ```

---

## 7. Recent Changes

- **2026-09-22 (Multi-Server Architecture Refactoring — 1 Claude Connector to Multiple Downstream MCP Servers)**:
  - **Single Claude Connector**: Updated `mcpath/proxy/run.py` and `mcpath/proxy/passthrough.py` so Claude Desktop connects via a single stdio connection to `run_proxy.py` without requiring server flags.
  - **Multi-Server Downstream Manager (`DownstreamClientManager`)**:
    - Replaced single-server management with concurrent multi-server session management using independent `AsyncExitStack` transports.
    - Added independent lifecycle management: failures in one downstream server do not affect others; failed servers are recorded in `unavailable_servers` and excluded from `tools/list`.
    - Added deterministic tool collision resolution: colliding tool names across servers are prefixed with `{server_name}_{tool_name}`; unique tool names remain unchanged.
    - Maintained exact exposed tool routing: `exposed_name -> (server_name, original_tool_name, raw_definition)`. Calls are routed to the owning server's `ClientSession` using `original_tool_name`. Tool calls on Server A can never reach Server B.
  - **Two-Phase Risk Engine Timing**:
    - Refactored `PipelineRunner` to execute in two explicit phases of the deterministic Risk Engine: Phase 1 Pre-Execution (Stages 1–4 -> Risk Engine decision) and Phase 2 Post-Execution (Stage 5 Response Risk -> Risk Engine final decision).
    - Hard blocks in Stage 1 immediately stop downstream execution and record Stages 2–5 as `NOT_EXECUTED` (status `SKIPPED`, `passed=False`).
  - **Dynamic Server Reloading**:
    - Added `reload()` method to `DownstreamClientManager` to detect added/removed servers, reconnect, rediscover tools, and update exposed mappings.
    - Added `POST /api/servers/reload` route in `mcpath/backend/routes/servers.py`.
    - Added `rebuild_for_all_servers()` and `remove_server()` to `CapabilityGraph` to dynamically represent configured servers.
  - **Discovery vs Approval Separation**: Verified that server reload and discovery do not create approved hashes in PostgreSQL. Unapproved tools fail-closed with `NO_APPROVED_BASELINE`.
  - **Comprehensive Test Suite & Verification**:
    - Created `tests/test_multi_server_proxy.py` covering multi-server startup, aggregated tool listing, collision namespacing, cross-server routing isolation, Stage 1 mismatch blocking, missing baseline fail-closed policy, independent server failure handling, and dynamic reload.
    - Total test suite raised to **28 passing automated tests** (100% pass).
    - Updated `verify_real_servers.py` to test one MCPath process connecting concurrently to Filesystem (`C:\projects\mcp-demos\filesystem`), Git (`C:\projects\mcp-demos\GitRepo`), and PostgreSQL (`mcpath_demo_db`). Verified 39 tools exposed, routed execution across all 3 servers, and passed the controlled Claude Desktop rug-pull simulation.
- **2026-09-23 (Day 3: Capability Risk Graph + Path Scoring)**:
  - **Deterministic Policy Separation**: Added `config/capability_policy.json` (policy v1.0.0) containing classification rules, transition-based chain risk definitions, path scoring weights (Data: 0.30, Action: 0.25, Exposure: 0.20, Chain: 0.25), configurable critical path override thresholds, and fail-safe unknown path configuration.
  - **Capability Inference Engine**: Implemented `CapabilityClassifier` deriving metadata strictly from manifest definitions without inventing unsupported capabilities; verified by negative tests.
  - **Dynamic NetworkX Causal Graph**: Implemented `CapabilityGraph` with typed nodes (`Agent`, `Tool`, `Data/Resource`, `Action`, `External Destination`) and typed edges (`CAN_CALL`, `READS`, `WRITES`, `FLOWS_TO`, `SENDS_TO`). Sinks enforce strict path completion.
  - **Transition-Based Chain Risk**: Computed chain risk based on security transition significance rather than raw graph length.
  - **Configurable Critical Path Override**: If sensitive data flows to external action and destination, classifies as `HIGH` independently of weighted score.
  - **Runtime Sequence Mapping & Fail-Closed Unknowns**: Maps active calls and call sequences against graph paths; reports `"CAPABILITY PATH: UNKNOWN / UNMODELED"` with elevated score (75.0) when no compatible path is found.
  - **Dynamic Server Reload**: Automatically rebuilds capability graph and recomputes paths when servers are added, changed, or removed.
  - **PostgreSQL Persistence & Observability**: Added `capability_nodes`, `capability_edges`, `capability_paths`, and enhanced `capabilities` tables with FastAPI routes (`/api/capabilities/policy`, `/api/capabilities/graph`, `/api/capabilities/paths`, `/api/capabilities/tools`) and Streamlit dashboard integration.
  - **Empirical Evaluation Benchmark**: Evaluated policy-v1 against a 30-path benchmark dataset (15 dangerous, 15 benign), reporting precision, recall, F1, FPR, and FNR.
  - **Comprehensive Verification**: Added `tests/test_capability_graph.py` (12 tests); full test suite elevated to **41 passing automated tests** (100% pass).

