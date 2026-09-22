# MCPath: Project Context & Architecture Status

> **Persistent handoff document for AI coding agents.**
> *Rule for agents: Read this document before inspecting code or making changes. Update this document after completing any task to reflect the exact state of the codebase.*

---

## 1. Project Overview

- **What MCPath is**: A runtime Zero-Trust security proxy specifically built for the Model Context Protocol (MCP). It sits in-line between an MCP client (such as Claude Desktop, Cursor, Windsurf, or custom agent runtimes) and downstream MCP servers.
- **The Problem It Solves**: In standard MCP setups, clients blindly trust connected tool definitions, tool invocations, and server responses. This exposes AI systems to tool rug pulls (changing tool schemas/descriptions after approval), capability chain exploits (e.g. reading customer PII and exfiltrating via email), prompt injection/jailbreak intents, anomalous behavior deviations, and sensitive data leakage in tool outputs.
- **Where It Sits in MCP Architecture**: 
  - Standard setup: `MCP Client (Claude Desktop) <--- stdio/HTTP ---> MCP Server`
  - MCPath setup: `MCP Client (Claude Desktop) <--- stdio ---> MCPath Proxy <--- stdio ---> MCP Server`
  - MCPath acts as an intercepting transparent reverse proxy using the official MCP Python SDK (`mcp`).

---

## 2. Current Architecture

```
+------------------------------------+
|  Claude Desktop / Custom MCP Host  |
+------------------------------------+
                  | (stdio MCP JSON-RPC)
                  v
+------------------------------------+        Async Log Event        +-------------------------+      +-------------------+
|         MCPath Proxy Core          | ----------------------------> | FastAPI Backend Service | ---> |    PostgreSQL     |
+------------------------------------+     (Non-blocking write)      +-------------------------+      | (SQLite fallback) |
  Stage 1: Tool Integrity Hash Check                                                                   +-------------------+
  Stage 2: Capability Risk Graph                                                                                 |
  Stage 3: Semantic Intent Verify                                                                                v
  Stage 4: Behaviour Deviation                                                                        +-------------------+
  Stage 5: Response Risk Inspection                                                                   | Streamlit / React |
  Stage 6: Deterministic Risk Engine                                                                  | Security Dashboard|
                  |                                                                                   +-------------------+
                  v (Forwarded ONLY on ALLOW)
+------------------------------------+
|        Downstream MCP Server       |
+------------------------------------+
```

### Core Subsystems & Components:
1. **Live Enforcement Path**: `MCP Client -> MCPath Proxy -> MCP Server`. Intercepts `tools/list` and `tools/call`. Evaluates requests through the 6-stage pipeline and forwards them only if the deterministic Risk Engine decides `ALLOW`.
2. **Observability Path (Separation of Concerns)**: `MCPath Proxy -> FastAPI Backend -> PostgreSQL -> Dashboard`. Emits structured `SecurityEventRecord`, `StageResultDB`, and `DecisionDB` payloads. The dashboard and backend are strictly read-only observers and have zero influence over live enforcement decisions.
3. **Six-Stage Security Pipeline**: Sequential evaluation pipeline running per tool call request and response.
4. **Causal Capability Graph ([CapabilityGraph](file:///c:/projects/mcp%20proxy/mcpath/graph/capability_graph.py#L24-L50))**: Built using NetworkX to map Agent $\rightarrow$ Tool $\rightarrow$ Resource $\rightarrow$ Action $\rightarrow$ External Destination relations and compute multi-hop risk.
5. **Attributable Explainability**: Every security event produces an itemized breakdown across all 6 stages (hard gates, individual risk scores, triggering reasons) rather than an opaque blended score.

---

## 3. Implemented So Far

### Current Milestone & Status
- **Current Milestone**: Day 2.1 Complete — Stage 1 End-to-End Lifecycle (Trusted Registration CLI, PostgreSQL Baseline Storage, Runtime Hash Verification, Rug-Pull Hard Blocking, Fail-Closed Policy).
- **All 22 automated tests passing** — unit tests for hash canonicalization, integration tests for the complete Stage 1 lifecycle (7 integration scenarios), proxy passthrough, pipeline skeleton, and backend REST endpoints.
- **Live PostgreSQL verification confirmed** — `verify_stage1_e2e.py` 100% succeeded against `localhost:5432/MCPath`.

### Working Features
- Full end-to-end stdio proxy passthrough using official MCP Python SDK (`mcp.server.lowlevel.Server` & `mcp.client.session.ClientSession`).
- **Trusted Registration CLI** (`python -m mcpath.register`): connects to configured MCP servers, calls `tools/list`, extracts security-relevant definition (`name`, `description`, `inputSchema`), canonicalizes deterministically, computes SHA-256, stores approved baseline in PostgreSQL. Idempotent — re-running with unchanged definition leaves records unchanged.
- Stage 1 Hash Integrity Check (`Stage1HashCheck`) with recursive JSON key sorting, canonicalization, SHA-256 hashing, and PostgreSQL `approved_hashes` lookup.
- **Separation of registration vs runtime**: `tools/list` interception caches definitions but does NOT auto-create approved hashes. Only `python -m mcpath.register` creates baseline records.
- Deterministic Stage 1 Hard Blocking on tool definition tampering (rug pulls), preventing downstream tool calls.
- **Strict Fail-Closed policy**: `NO_APPROVED_BASELINE` (tool not registered) = BLOCK. Database unavailability = BLOCK. Hash mismatch = BLOCK. Nothing passes silently.
- Complete PostgreSQL 8-table relational schema with SQLAlchemy models, foreign keys, unique constraints, and indexes (`servers`, `tools`, `approved_hashes`, `capabilities`, `baseline_traces`, `security_events`, `stage_results`, `decisions`).
- FastAPI backend application ([`mcpath/backend/app.py`](file:///c:/projects/mcp%20proxy/mcpath/backend/app.py)) with endpoints for health, overview metrics, server inventory, tool lists, approved hash management, security events, and stage results.
- Downstream server connection management via [`DownstreamClientManager`](file:///c:/projects/mcp%20proxy/mcpath/proxy/client_manager.py).
- **Real MCP server support** — Filesystem (npx), Git (uvx), Microsoft PostgreSQL (npx) servers are all configured and verified:
  - `filesystem`: `cmd /c npx -y @modelcontextprotocol/server-filesystem <path>` (14 tools, path from `FILESYSTEM_ALLOWED_PATHS`).
  - `git`: `uvx mcp-server-git --repository <path>` (12 tools, path from `GIT_REPOSITORY_PATH`).
  - `postgres-mcp`: `cmd /c npx -y @microsoft/postgres-mcp@latest run` (13 tools, connection URI from `POSTGRES_MCP_CONNECTION_STRING`, targeting isolated `mcpath_demo_db`).
  - Switching servers requires only a `--server <name>` flag; no pipeline code changes.
- **${VAR} env-var interpolation** in `server_config.json` args/env via `interpolate_server_config()` — machine-specific paths and credentials stay in `.env` only.
- Reference Mock MCP Server ([`mock_servers/sample_server.py`](file:///c:/projects/mcp%20proxy/mock_servers/sample_server.py)) providing `echo`, `calculate`, `read_customer` (sensitive PII), `send_email` (exfiltration endpoint), `summarize_repository`, and `delete_repository`. Kept strictly for test/regression fixtures (`sample_reference_server`).

### Important Files & Modules
- [`mcpath/pipeline/stages/stage1_hash.py`](file:///c:/projects/mcp%20proxy/mcpath/pipeline/stages/stage1_hash.py): Stage 1 Tool Integrity Hash Check implementation.
- [`mcpath/backend/persistence/models.py`](file:///c:/projects/mcp%20proxy/mcpath/backend/persistence/models.py): SQLAlchemy models for all 8 database tables.
- [`mcpath/backend/persistence/database.py`](file:///c:/projects/mcp%20proxy/mcpath/backend/persistence/database.py): Async database engine, session management, repository functions, and credential-redacting server registration.
- [`mcpath/backend/routes/`](file:///c:/projects/mcp%20proxy/mcpath/backend/routes/): FastAPI route modules for `overview`, `servers`, `events`, `hashes`, and `stage_results`.
- [`mcpath/proxy/server.py`](file:///c:/projects/mcp%20proxy/mcpath/proxy/server.py): Intercepting MCP server handlers for `list_tools` and `call_tool`.
- [`mcpath/proxy/client_manager.py`](file:///c:/projects/mcp%20proxy/mcpath/proxy/client_manager.py): Downstream MCP client manager (merges full OS env for Node/uvx subprocess compatibility).
- [`mcpath/proxy/passthrough.py`](file:///c:/projects/mcp%20proxy/mcpath/proxy/passthrough.py): Passthrough coordinator — calls `interpolate_server_config()` before launching subprocess.
- [`mcpath/config/settings.py`](file:///c:/projects/mcp%20proxy/mcpath/config/settings.py): Settings class with `FILESYSTEM_ALLOWED_PATHS`, `GIT_REPOSITORY_PATH`, `POSTGRES_MCP_CONNECTION_STRING`, and `interpolate_server_config()` utility.
- [`config/server_config.json`](file:///c:/projects/mcp%20proxy/config/server_config.json): Declarative server registry (filesystem, git, postgres-mcp, sample_reference_server).
- [`mcpath/pipeline/pipeline_runner.py`](file:///c:/projects/mcp%20proxy/mcpath/pipeline/pipeline_runner.py): Ordered stage execution coordinator with async DB logging.
- [`verify_real_servers.py`](file:///c:/projects/mcp%20proxy/verify_real_servers.py): Real-server end-to-end verification (full production flow for filesystem, git, postgres-mcp).
- [`verify_stage1_e2e.py`](file:///c:/projects/mcp%20proxy/verify_stage1_e2e.py): Stage 1 lifecycle verification against PostgreSQL.
- [`verify_day2.py`](file:///c:/projects/mcp%20proxy/verify_day2.py): Day 2.1 milestone verification script.

### How to Run and Verify
1. **Run full automated test suite (22 tests)**:
   ```powershell
   .venv\Scripts\python.exe -m pytest -v
   ```
2. **Run Trusted Registration (establish approved SHA-256 baselines in PostgreSQL)**:
   ```powershell
   # Register all configured servers (filesystem, git, postgres-mcp, sample)
   .venv\Scripts\python.exe -m mcpath.register --all

   # Register a specific server
   .venv\Scripts\python.exe -m mcpath.register --server filesystem
   .venv\Scripts\python.exe -m mcpath.register --server git
   .venv\Scripts\python.exe -m mcpath.register --server postgres-mcp
   ```
3. **Run real-server end-to-end verification (all 3 real servers + regression)**:
   ```powershell
   .venv\Scripts\python.exe verify_real_servers.py
   # Or a single server:
   .venv\Scripts\python.exe verify_real_servers.py --server postgres-mcp
   ```
4. **Run Stage 1 end-to-end live verification (against PostgreSQL)**:
   ```powershell
   .venv\Scripts\python.exe verify_stage1_e2e.py
   ```
5. **Run the proxy for a specific server**:
   ```powershell
   .venv\Scripts\python.exe run_proxy.py --server filesystem --log-level INFO
   .venv\Scripts\python.exe run_proxy.py --server git --log-level INFO
   .venv\Scripts\python.exe run_proxy.py --server postgres-mcp --log-level INFO
   .venv\Scripts\python.exe run_proxy.py --server sample_reference_server --log-level INFO
   ```l INFO
   ```
6. **Run FastAPI observability backend**:
   ```powershell
   .venv\Scripts\uvicorn.exe mcpath.backend.app:app --host 127.0.0.1 --port 8000 --reload
   ```

---

## 4. Security Pipeline

The 6-stage pipeline evaluates every intercepted call in fixed sequence:

| Stage | Name | Role & Question Answered | Status |
|---|---|---|---|
| **Stage 1** | **Tool Integrity Hash Check** | *"Has this tool's definition changed since it was approved?"* Computes SHA-256 over canonicalized JSON and compares against PostgreSQL `approved_hashes`. Mismatches trigger immediate hard block without evaluating later stages (stops tool rug pulls). Fail-closed on missing definition/DB error. | **IMPLEMENTED** (Full canonicalization, DB lookup, match/mismatch hard block, fail-closed policy) |
| **Stage 2** | **Capability Risk** | *"Can this tool access sensitive resources or chain to external exfiltration?"* Analyzes graph paths in NetworkX (Agent $\rightarrow$ Tool $\rightarrow$ Resource $\rightarrow$ Action $\rightarrow$ Destination) to produce risk score $[0, 100]$. | **PLANNED / SKELETON** (NetworkX skeleton in place; schema extraction & path scoring planned) |
| **Stage 3** | **Intent Verification** | *"Does the requested tool call align with the user's explicit prompt?"* Compares embeddings of user prompt vs tool call semantics to detect prompt injection/jailbreak manipulation. | **PLANNED / SKELETON** (Interface ready; embedding & cosine similarity model planned) |
| **Stage 4** | **Behaviour Deviation** | *"Is this call anomalous compared to historical baseline traces?"* Checks parameter sizes, invocation frequencies, and argument shapes against historical statistical baselines. | **PLANNED / SKELETON** (Trace schema & model ready; statistical scoring planned) |
| **Stage 5** | **Response Risk Inspection** | *"Does the downstream server output leak sensitive data (PII, API keys, credentials)?"* Inspects tool outputs using fast regex heuristics and optional secondary bounded classifier. | **PLANNED / SKELETON** (Regex heuristics & LLM classifier skeleton ready) |
| **Stage 6** | **Deterministic Risk Engine** | *"What is the final enforcement decision?"* Evaluates hard-block gates first, then thresholds combined scores into `ALLOW`, `HOLD`, or `BLOCK`. Attaches complete explainability evidence. | **IMPLEMENTED (Base)** (Rule engine, gate checking, and explainability formatting active) |

---

## 5. Decisions & Architectural Constraints

1. **Deterministic Risk Engine**: The final `ALLOW` / `HOLD` / `BLOCK` decision is 100% deterministic code. An LLM must **NEVER** independently make the enforcement decision.
2. **No Custom Chatbot / Agent**: MCPath is strictly a transparent security proxy. Claude Desktop (or other standard MCP host) remains the conversational agent.
3. **Read-Only Observability Path**: The dashboard and FastAPI backend observe security events; they cannot intercept or control live proxy enforcement.
4. **Preserve Official MCP SDK**: Always use standard `mcp` library protocols (`mcp.server.lowlevel`, `mcp.client.session.ClientSession`, stdio streams).
5. **No Blind 0-100 Blended Scores**: All decisions must preserve Section 7 attributable explainability with clear per-stage evidence.
6. **Fail-Closed Policy**: Database unavailability, unapproved tools, or missing hashes must trigger a hard block (`BLOCK`) rather than silently allowing execution.
7. **Dynamic & Server-Agnostic**: Switching downstream servers via `config/server_config.json` automatically discovers tools and computes approved hashes without modifying pipeline code.

---

## 6. Next Development & Roadmap

- **Current Stage**: Real MCP server support complete. Ready for Day 3 development (Stage 2 Capability Graph).
- **Immediate Next Tasks**:
  1. **Stage 2 Capability Graph Builder (Days 5-6)**:
     - Automatically parse tool parameters and descriptions to extract Resource, Action, and Destination nodes.
     - Connect graph edges (`CAN_CALL`, `READS`, `WRITES`, `FLOWS_TO`, `SENDS_TO`).
     - Calculate causal multi-hop path risk scores in NetworkX.
  2. **Stage 3 Intent Verification (Days 7-8)**:
     - Embed user prompts and tool actions to compute semantic similarity and detect indirect prompt injection.
  3. **Stage 4 Behaviour Baseline & Anomaly Detection (Days 9-10)**:
     - Implement statistical parameter tracking (length, schema deviation, call frequency).
  4. **Stage 5 Response Inspector (Day 11)**:
     - High-speed regex scanning for PII (SSN, credit cards, emails, private keys) on tool response text.
  5. **Admin Dashboard & Live Event Stream (Days 12-13)**:
     - Build dashboard UI to display live intercepted events, graph visualization, and stage breakdowns.

---

## 7. Recent Changes

- **2026-09-22 (Registry Cleanup & Microsoft PostgreSQL MCP Integration)**:
  - **Registry Cleanup**:
    - Kept `sample_reference_server` strictly as a test/regression fixture; removed obsolete `sample-server` from tests, scripts, and database.
    - Removed obsolete duplicate filesystem server (`filesystem_reference`) from PostgreSQL; maintained single canonical `filesystem` entry.
    - Investigated and resolved the persistence issue where `command`/`args` fields for filesystem, git, and fetch were empty: `verify_real_servers.py` had omitted command/args from `register_trusted_server_and_tools()`, causing `database.py` defaults to overwrite existing entries with `python`/`[]`. Fixed `database.py` to preserve existing command/args when updating, and updated registration callers to pass explicit command/args/env definitions.
    - Implemented `_sanitize_env_vars()` in `database.py` to redact sensitive credentials (passwords, tokens, keys, connection URIs) from stored environment variables in PostgreSQL tables.
  - **Microsoft PostgreSQL MCP Integration (`postgres-mcp`)**:
    - Replaced `fetch` with official `@microsoft/postgres-mcp` as the third real demo server.
    - Preserved MCPath server-agnostic architecture without any PostgreSQL-specific modifications to Stages 1–6.
    - Created an isolated `mcpath_demo_db` database and `mcpath_demo_user` role, with strict isolation preventing any access to MCPath's core database. Seeded demo tables (`demo_customers`, `demo_orders`).
    - Configured `postgres-mcp` via `config/server_config.json` and `.env` using `${POSTGRES_MCP_CONNECTION_STRING}` with zero hardcoded credentials in the repository.
    - Untracked `.env` from Git and added comprehensive exclusion rules to `.gitignore`.
    - Executed trusted registration discovering 13 tools and storing approved baseline hashes in PostgreSQL.
    - Confirmed tools are visible and directly suitable for Stage 2 capabilities:
      - **READ**: `postgres_mcp_query`
      - **WRITE/MODIFY**: `postgres_mcp_modify`
      - **Schema Access**: `postgres_mcp_db_context`
      - **Data Loading**: `postgres_mcp_bulk_load_csv`
    - Updated `verify_real_servers.py` to test `postgres-mcp` (`postgres_mcp_list_connection_profiles` tool call) alongside `filesystem`, `git`, and regression suite.
    - **Verification Result**: 100% pass across all real servers, Stage 1 live lifecycle, and all 22 automated unit/integration tests.


- **2026-09-22 (Real MCP Server Support)**:
  - Added `filesystem`, `git`, and `fetch` server entries to [`config/server_config.json`](file:///c:/projects/mcp%20proxy/config/server_config.json) using correct production commands.
    - Filesystem: `cmd /c npx -y @modelcontextprotocol/server-filesystem ${FILESYSTEM_ALLOWED_PATHS}` (14 tools)
    - Git: `uvx mcp-server-git --repository ${GIT_REPOSITORY_PATH}` (12 tools, no GitHub PAT)
    - Fetch: `uvx mcp-server-fetch` (1 tool, no credentials)
  - Added `FILESYSTEM_ALLOWED_PATHS` and `GIT_REPOSITORY_PATH` fields to `Settings` in [`settings.py`](file:///c:/projects/mcp%20proxy/mcpath/config/settings.py).
  - Added `interpolate_server_config()` utility to resolve `${VAR}` placeholders in server args/env at runtime from `.env` values.
  - Fixed `DownstreamClientManager` to merge full `os.environ` into subprocess env (required for Node/uvx on Windows to inherit PATH).
  - Updated `passthrough.py` and `register.py` to call `interpolate_server_config` before spawning the subprocess.
  - Created [`verify_real_servers.py`](file:///c:/projects/mcp%20proxy/verify_real_servers.py): full production verification (connect → tools/list → trusted registration → Stage 1 → tools/call) for all 3 real servers + regression check.
  - **Verification result**: All 3 real servers + 22 existing tests pass (100%).
- **2026-09-22 (Day 2.1 Milestone Completed)**:
  - Created Trusted Registration CLI [`mcpath/register.py`](file:///c:/projects/mcp%20proxy/mcpath/register.py): `python -m mcpath.register --all` or `--server <name>`. Connects to each MCP server, calls `tools/list`, extracts `{name, description, inputSchema}`, canonicalizes, computes SHA-256, upserts idempotent approved baseline record in PostgreSQL.
  - Enforced strict registration/runtime separation: `tools/list` interception in proxy only caches definitions for runtime lookup — it does NOT auto-create approved hashes. Approved hashes are ONLY created by the explicit registration CLI.
  - Created 7-test integration suite [`tests/test_stage1_end_to_end.py`](file:///c:/projects/mcp%20proxy/tests/test_stage1_end_to_end.py): registration creates baseline; unchanged definition passes; description tampering blocks; schema tampering blocks; JSON key reordering passes; missing baseline fails-closed; re-registration is idempotent.
  - Confirmed live end-to-end run `verify_stage1_e2e.py` against PostgreSQL 18.4 at `localhost:5432/MCPath` — 100% pass. 6 tools registered, hash-match PASS and rug-pull BLOCK both verified, security events audited in database.
  - Total test count raised from 15 → **22 passing tests** (pytest exit 0).
- **2026-09-21 (Day 2 Milestone Completed)**:
  - Created 8 SQLAlchemy database models (`servers`, `tools`, `approved_hashes`, `capabilities`, `baseline_traces`, `security_events`, `stage_results`, `decisions`) with relational constraints, indexes, and foreign keys.
  - Implemented async PostgreSQL database layer with `asyncpg` driver, connection lifecycle management, and repository methods.
  - Implemented Stage 1 Tool Integrity Hash Check with recursive key sorting canonicalization, SHA-256 hashing, and PostgreSQL `approved_hashes` lookup.
  - Added FastAPI persistence and inspection routes for `/api/hashes`, `/api/stage-results`, `/api/servers/{server_name}/tools`.
  - Created `verify_day2.py` milestone verification script demonstrating live rug-pull detection, blocking, and database audit recording.
- **2026-09-21 (Day 1 Milestone Completed)**:
  - Implemented core proxy server with lowlevel MCP server and downstream client session manager.
  - Added support for stdio JSON-RPC communication between Claude Desktop and downstream servers.
  - Created reference mock server with `echo`, `calculate`, `read_customer`, `send_email`, `summarize_repository`, `delete_repository`.
  - Built 6-stage pipeline architecture with base classes, context models, and pass-through runners.
  - Verified end-to-end functionality with standalone `verify_milestone.py`.

---

## 8. Known Issues & Real TODOs

- [ ] **Stage 2-5 Concrete Logic**: Stages 2 through 5 are currently operating in skeleton pass-through mode until their respective milestone days.
- [ ] **Alembic Migration Setup**: Schema currently initializes via SQLAlchemy `Base.metadata.create_all`; Alembic configuration can be added as schema grows.
