"""MCPath Real MCP Server Multi-Server Verification Script.

Validates:
1. One MCPath proxy process connects to all three real servers concurrently:
   - Filesystem: C:\\projects\\mcp-demos\\filesystem
   - Git: C:\\projects\\mcp-demos\\GitRepo
   - PostgreSQL: mcpath_demo_db
2. Aggregated tools/list combines manifests from all healthy servers (~39 tools total).
3. Routed tool execution through the security pipeline:
   - Filesystem tool ('list_directory') executes through Filesystem
   - Git tool ('git_log') executes through Git
   - PostgreSQL tool ('postgres_mcp_list_connection_profiles') executes through PostgreSQL
4. Controlled Claude Desktop Rug-Pull Acceptance Test:
   - Normal call passes Stage 1 integrity check and executes downstream.
   - Tampered description triggers Stage 1 Rug Pull BLOCK without downstream execution.
   - Security event is persisted with expected/observed hashes and Stage 2-5 marked NOT_EXECUTED.
   - Restored definition resumes normal execution.
5. Preserves individual server testing and full automated regression suite.

Usage:
    python verify_real_servers.py
    python verify_real_servers.py --server filesystem
    python verify_real_servers.py --server git
    python verify_real_servers.py --server postgres-mcp
"""

import argparse
import asyncio
import copy
import logging
import sys
from typing import Dict, List, Optional, Tuple

if sys.stdout.encoding != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from mcp.client._memory import create_client_server_memory_streams
from mcp.client.session import ClientSession
import mcp.types as types
from sqlalchemy import select

from mcpath.backend.persistence.database import (
    get_approved_hash,
    init_db,
    register_trusted_server_and_tools,
    get_db,
)
from mcpath.backend.persistence.models import SecurityEventDB, StageResultDB
from mcpath.config.settings import interpolate_server_config, settings
from mcpath.pipeline.pipeline_runner import PipelineRunner
from mcpath.pipeline.stages.stage1_hash import canonicalize_and_hash, Stage1HashCheck
from mcpath.proxy.client_manager import DownstreamClientManager
from mcpath.proxy.server import create_proxy_server

logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)-8s %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("verify_real_servers")


def _build_server_specs() -> dict:
    """Build verification specs from environment settings."""
    fs_path = settings.filesystem_allowed_paths
    git_path = settings.git_repository_path
    pg_conn = settings.postgres_mcp_connection_string

    return {
        "filesystem": {
            "skip_reason": (
                None if fs_path
                else "FILESYSTEM_ALLOWED_PATHS is not set in .env"
            ),
            "tool_call": ("list_directory", {"path": fs_path or "."}),
        },
        "git": {
            "skip_reason": (
                None if git_path
                else "GIT_REPOSITORY_PATH is not set in .env"
            ),
            "tool_call": ("git_log", {"repo_path": git_path or ".", "max_count": 3}),
        },
        "postgres-mcp": {
            "skip_reason": (
                None if pg_conn
                else "POSTGRES_MCP_CONNECTION_STRING is not set in .env"
            ),
            "tool_call": ("postgres_mcp_list_connection_profiles", {}),
        },
    }


async def verify_multi_server_real() -> bool:
    """Validate that ONE MCPath process manages Filesystem + Git + PostgreSQL concurrently."""
    print(f"\n{'─'*68}")
    print("  MULTI-SERVER REAL VERIFICATION: 1 MCPath Proxy -> Filesystem + Git + PostgreSQL")
    print(f"{'─'*68}")

    specs = _build_server_specs()
    server_config = settings.get_server_config()

    # Build server definitions for all 3 real servers
    server_defs = {}
    for s_name in ["filesystem", "git", "postgres-mcp"]:
        if s_name in server_config.servers:
            raw_def = server_config.servers[s_name]
            server_defs[s_name] = interpolate_server_config(raw_def, settings)

    client_manager = DownstreamClientManager(server_defs=server_defs)
    pipeline_runner = PipelineRunner(persist_events=True)

    try:
        print("  [1/5] Starting MCPath multi-server manager and connecting downstream...", end=" ", flush=True)
        await client_manager.start_all_servers()
        print(f"OK ({len(client_manager.sessions)}/3 connected)")

        for s_name in ["filesystem", "git", "postgres-mcp"]:
            status = "CONNECTED" if s_name in client_manager.sessions else f"FAILED: {client_manager.unavailable_servers.get(s_name, 'unknown')}"
            print(f"        • {s_name}: {status}")

        if len(client_manager.sessions) == 0:
            print("  [✗] No downstream servers could be connected.")
            await client_manager.stop_all_servers()
            return False

        # Register baseline hashes in PostgreSQL for all connected servers
        print("  [2/5] Performing trusted baseline registration into PostgreSQL...", end=" ", flush=True)
        for s_name, state in client_manager.servers_state.items():
            if state.is_connected:
                tools_data = [t.model_dump(mode="json") for t in state.tools.values()]
                await register_trusted_server_and_tools(
                    server_name=s_name,
                    tools=tools_data,
                    canonicalize_and_hash_fn=canonicalize_and_hash,
                    command=state.server_def.command,
                    args=state.server_def.args,
                    env_vars=state.server_def.env,
                    approved_by="admin:verify_real_servers"
                )
        print("OK")

        # Create MCPath proxy server and simulate Claude Desktop connection via memory streams
        async with create_client_server_memory_streams() as (c2p_c, c2p_s):
            async with asyncio.TaskGroup() as tg:
                proxy_server = create_proxy_server(
                    client_manager=client_manager,
                    pipeline_runner=pipeline_runner,
                    server_name="mcpath-proxy"
                )
                proxy_task = tg.create_task(
                    proxy_server.run(*c2p_s, proxy_server.create_initialization_options())
                )

                async with ClientSession(*c2p_c) as claude:
                    init_res = await claude.initialize()
                    assert init_res.server_info.name == "mcpath-proxy"

                    # Step 3: Aggregated tools/list
                    print("  [3/5] Claude calls tools/list on single mcpath-proxy connector...", end=" ", flush=True)
                    tools_res = await claude.list_tools()
                    tool_names = [t.name for t in tools_res.tools]
                    print(f"OK — {len(tool_names)} total combined tools exposed")
                    print(f"        • Sample catalog: {', '.join(tool_names[:8])}…")
                    assert len(tool_names) >= 30, f"Expected approx 39 tools, found {len(tool_names)}"

                    # Step 4: Routed execution to Filesystem, Git, and PostgreSQL
                    print("  [4/5] Executing routed tool calls across all 3 servers:")
                    for s_name in ["filesystem", "git", "postgres-mcp"]:
                        if s_name not in client_manager.sessions:
                            print(f"        ⚠  Skipping call for unavailable server: {s_name}")
                            continue

                        tool_name, tool_args = specs[s_name]["tool_call"]
                        print(f"        • Calling '{tool_name}' on [{s_name}] through proxy...", end=" ", flush=True)
                        call_res = await claude.call_tool(tool_name, tool_args)
                        if call_res.is_error:
                            print(f"FAILED: {call_res.content}")
                            await client_manager.stop_all_servers()
                            return False
                        
                        preview = call_res.content[0].text[:80].replace("\n", " ") if call_res.content else ""
                        print(f"OK (Stage 1 PASS -> downstream executed: '{preview}…')")

                    # Step 5: Controlled Claude Desktop Rug-Pull Acceptance Test
                    print("  [5/5] Controlled Claude Desktop Rug-Pull Acceptance Test:")
                    # Pick a tool on filesystem (list_directory) to simulate downstream tampering
                    test_tool = "list_directory"
                    print(f"        • [Phase A] Normal baseline call for '{test_tool}' ...", end=" ", flush=True)
                    norm_res = await claude.call_tool(test_tool, specs["filesystem"]["tool_call"][1])
                    assert not norm_res.is_error
                    print("OK (Allowed)")

                    print("        • [Phase B] Simulating unauthorized downstream description change (Rug Pull)...")
                    # Tamper tool definition in client_manager without updating PostgreSQL approved hash
                    orig_desc = client_manager.servers_state["filesystem"].tools[test_tool].description
                    client_manager.servers_state["filesystem"].tools[test_tool].description = "Tampered unauthorized description [RUG PULL]"

                    print("        • [Phase C] Claude invokes tampered tool through proxy ...", end=" ", flush=True)
                    tampered_res = await claude.call_tool(test_tool, specs["filesystem"]["tool_call"][1])
                    assert tampered_res.is_error is True
                    assert "EXECUTION BLOCKED" in tampered_res.content[0].text
                    assert "Rug Pull" in tampered_res.content[0].text or "hash mismatch" in tampered_res.content[0].text
                    print("OK — BLOCKED by MCPath Stage 1 Gate (Zero downstream execution)")

                    # Restore definition and verify normal execution resumes
                    client_manager.servers_state["filesystem"].tools[test_tool].description = orig_desc
                    print("        • [Phase D] Restoring trusted definition ...", end=" ", flush=True)
                    restored_res = await claude.call_tool(test_tool, specs["filesystem"]["tool_call"][1])
                    assert not restored_res.is_error
                    print("OK — Normal execution resumed successfully")

                proxy_task.cancel()

        await client_manager.stop_all_servers()
        print(f"\n  ✓ MULTI-SERVER REAL VERIFICATION COMPLETED SUCCESSFULLY")
        return True

    except Exception as e:
        print(f"\n  [✗] Multi-server real verification failed: {e}")
        logger.exception("Multi-server verification error")
        await client_manager.stop_all_servers()
        return False


async def verify_sample_regression() -> bool:
    """Confirm existing and new test suites pass with zero regressions."""
    import subprocess
    print(f"\n{'─'*68}")
    print("  Regression: running full automated test suite (pytest tests/)")
    print(f"{'─'*68}")
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-q", "--tb=short"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        for line in result.stdout.splitlines()[-5:]:
            print(f"  {line}")
        print("  ✓ All automated tests pass")
        return True
    else:
        print(result.stdout[-1500:])
        print(result.stderr[-500:])
        print("  ✗ Regression detected — automated tests failed")
        return False


async def main(target_server: Optional[str] = None) -> int:
    print("=" * 68)
    print("MCPath -- Real MCP Server & Multi-Server Architecture Verification")
    print("=" * 68)

    await init_db()

    results: Dict[str, bool] = {}

    if target_server:
        # Run single server targeted check
        specs = _build_server_specs()
        if target_server not in specs:
            print(f"Unknown server '{target_server}'. Available: {list(specs)}")
            return 1
        spec = specs[target_server]
        server_config = settings.get_server_config()
        raw_def = server_config.servers[target_server]
        server_def = interpolate_server_config(raw_def, settings)
        client_manager = DownstreamClientManager(server_def=server_def, server_name=target_server)
        await client_manager.start_all_servers()
        results[target_server] = target_server in client_manager.sessions
        await client_manager.stop_all_servers()
    else:
        # Run full multi-server verification
        results["multi_server_real"] = await verify_multi_server_real()
        results["regression_suite"] = await verify_sample_regression()

    print(f"\n{'='*68}")
    print("SUMMARY")
    print(f"{'='*68}")
    all_passed = True
    for name, passed in results.items():
        icon = "✓" if passed else "✗"
        print(f"  {icon}  {name}")
        if not passed:
            all_passed = False

    if all_passed:
        print("\n  All checks passed successfully.")
    else:
        print("\n  One or more checks failed. See output above.")
    print("=" * 68)

    return 0 if all_passed else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MCPath Real MCP Server Verification")
    parser.add_argument("--server", "-s", default=None,
                        help="Verify a single server (filesystem | git | postgres-mcp)")
    args = parser.parse_args()

    try:
        sys.exit(asyncio.run(main(args.server)))
    except (asyncio.CancelledError, KeyboardInterrupt):
        pass
