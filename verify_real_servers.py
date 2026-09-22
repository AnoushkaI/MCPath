"""MCPath Real MCP Server Verification Script.

Validates the full production flow for each configured real server:
  connect → initialize → tools/list → trusted registration (PostgreSQL)
  → tools/call → Stage 1 runtime hash verification → downstream execution

Servers tested: filesystem, git, postgres-mcp (+ sample_reference_server regression).

Skips a server gracefully when its required path/config is not set in .env,
but NEVER bypasses security checks or auto-trusts tool definitions.

Usage:
    python verify_real_servers.py
    python verify_real_servers.py --server filesystem
    python verify_real_servers.py --server git
    python verify_real_servers.py --server postgres-mcp
"""

import argparse
import asyncio
import logging
import sys
from typing import Optional

if sys.stdout.encoding != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


from mcpath.backend.persistence.database import (
    get_approved_hash,
    init_db,
    register_trusted_server_and_tools,
)
from mcpath.config.settings import interpolate_server_config, settings
from mcpath.pipeline.pipeline_runner import PipelineRunner
from mcpath.pipeline.stages.stage1_hash import canonicalize_and_hash
from mcpath.proxy.client_manager import DownstreamClientManager
from mcpath.proxy.server import create_proxy_server

from mcp.client._memory import create_client_server_memory_streams
from mcp.client.session import ClientSession

logging.basicConfig(
    level=logging.WARNING,
    format="%(levelname)-8s %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("verify_real_servers")


# ---------------------------------------------------------------------------
# Per-server verification spec
# ---------------------------------------------------------------------------

def _build_server_specs() -> dict:
    """Build verification specs. Evaluated at call-time so .env is already loaded."""
    fs_path = settings.filesystem_allowed_paths
    git_path = settings.git_repository_path
    pg_conn = settings.postgres_mcp_connection_string

    specs = {
        "filesystem": {
            "skip_reason": (
                None if fs_path
                else "FILESYSTEM_ALLOWED_PATHS is not set in .env — set it to an absolute path and re-run."
            ),
            # A safe read-only tool that lists directory contents
            "tool_call": ("list_directory", {"path": fs_path or "."}),
        },
        "git": {
            "skip_reason": (
                None if git_path
                else "GIT_REPOSITORY_PATH is not set in .env — set it to a local git repo path and re-run."
            ),
            # git_log gives a summary of recent commits — safe, read-only
            "tool_call": ("git_log", {"repo_path": git_path or ".", "max_count": 3}),
        },
        "postgres-mcp": {
            "skip_reason": (
                None if pg_conn
                else "POSTGRES_MCP_CONNECTION_STRING is not set in .env — set it to the demo DB URI and re-run."
            ),
            # Safe read-only tool that lists connection profiles
            "tool_call": ("postgres_mcp_list_connection_profiles", {}),
        },
    }

    # If fetch is still configured in server_config.json, keep it supported
    server_config = settings.get_server_config()
    if "fetch" in server_config.servers:
        specs["fetch"] = {
            "skip_reason": None,
            "tool_call": ("fetch", {"url": "https://example.com", "max_length": 500}),
        }

    return specs


# ---------------------------------------------------------------------------
# Core verification routine
# ---------------------------------------------------------------------------

async def verify_server(server_name: str, spec: dict) -> bool:
    """Run the full production verification flow for one server. Returns True on success."""
    skip = spec.get("skip_reason")
    if skip:
        print(f"\n  ⚠  SKIPPED: {server_name}")
        print(f"     {skip}")
        return True  # Not a failure — just not configured

    server_config = settings.get_server_config()
    if server_name not in server_config.servers:
        print(f"\n  ✗  MISSING: '{server_name}' is not defined in server_config.json")
        return False

    raw_def = server_config.servers[server_name]
    server_def = interpolate_server_config(raw_def, settings)
    tool_name, tool_args = spec["tool_call"]

    print(f"\n{'─'*68}")
    print(f"  Server: {server_name}")
    print(f"  Command: {server_def.command} {' '.join(server_def.args)}")
    print(f"{'─'*68}")

    client_manager = DownstreamClientManager(server_def, server_name=server_name)

    try:
        async with client_manager.session_context() as downstream_session:
            # ── Step 1: tools/list ──────────────────────────────────────────
            print(f"  [1/4] tools/list ...", end=" ", flush=True)
            tools_result = await client_manager.list_tools(downstream_session)
            tool_names = [t.name for t in tools_result.tools]
            print(f"OK — {len(tool_names)} tools: {', '.join(tool_names[:6])}{'…' if len(tool_names) > 6 else ''}")

            # ── Step 2: Trusted registration → PostgreSQL ───────────────────
            print(f"  [2/4] Trusted registration (Stage 1 baseline) ...", end=" ", flush=True)
            tools_data = [t.model_dump(mode="json") for t in tools_result.tools]
            synced = await register_trusted_server_and_tools(
                server_name=server_name,
                tools=tools_data,
                canonicalize_and_hash_fn=canonicalize_and_hash,
                command=server_def.command,
                args=server_def.args,
                env_vars=server_def.env,
                approved_by="admin:verify_real_servers",
            )
            print(f"OK — {len(synced)} hashes stored in PostgreSQL")

            # ── Step 3: Confirm hash is retrievable ─────────────────────────
            if tool_name in tool_names:
                stored_hash = await get_approved_hash(server_name, tool_name)
                if not stored_hash:
                    print(f"  [✗] PostgreSQL approved hash for '{tool_name}' not found after registration")
                    return False
                print(f"  [3/4] Approved hash for '{tool_name}': {stored_hash[:16]}…")
            else:
                # Tool specified in spec not available on this server — use first tool
                fallback_tool = tool_names[0] if tool_names else None
                if not fallback_tool:
                    print(f"  [3/4] No tools returned — cannot verify hash")
                    return False
                stored_hash = await get_approved_hash(server_name, fallback_tool)
                print(f"  [3/4] Approved hash for '{fallback_tool}' (fallback): {stored_hash[:16] if stored_hash else 'MISSING'}…")
                tool_name = fallback_tool
                tool_args = {}

            # ── Step 4: Runtime tools/call through proxy (Stage 1 enforced) ─
            print(f"  [4/4] tools/call '{tool_name}' through MCPath proxy ...", end=" ", flush=True)

            runner = PipelineRunner(persist_events=True)
            async with create_client_server_memory_streams() as (c2p_c, c2p_s):
                proxy_server = create_proxy_server(
                    client_manager=client_manager,
                    downstream_session=downstream_session,
                    pipeline_runner=runner,
                    server_name=f"mcpath-{server_name}",
                )

                async with asyncio.TaskGroup() as tg:
                    proxy_task = tg.create_task(
                        proxy_server.run(*c2p_s, proxy_server.create_initialization_options())
                    )

                    async with ClientSession(*c2p_c) as client:
                        await client.initialize()

                        result = await client.call_tool(tool_name, tool_args)

                    proxy_task.cancel()

            if result.is_error:
                print(f"ERROR")
                print(f"  [✗] tools/call returned is_error=True:")
                for c in result.content:
                    print(f"      {getattr(c, 'text', c)[:200]}")
                return False

            # Show a brief snippet of the result
            first_content = result.content[0] if result.content else None
            preview = ""
            if first_content:
                text = getattr(first_content, "text", str(first_content))
                preview = text[:120].replace("\n", " ")
            print(f"OK")
            print(f"  ✓ Stage 1 PASSED — downstream executed successfully")
            print(f"  ✓ Response preview: {preview}…")

    except Exception as e:
        print(f"\n  [✗] FAILED: {e}")
        logger.exception("Verification failed for %s", server_name)
        return False

    return True


# ---------------------------------------------------------------------------
# Sample-server regression guard
# ---------------------------------------------------------------------------

async def verify_sample_regression() -> bool:
    """Confirm existing sample_reference_server tests still pass (no regressions)."""
    import subprocess
    print(f"\n{'─'*68}")
    print("  Regression: running existing 22-test suite (pytest tests/)")
    print(f"{'─'*68}")
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-q", "--tb=short"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        # Show just the summary line
        for line in result.stdout.splitlines()[-5:]:
            print(f"  {line}")
        print("  ✓ All existing tests pass")
        return True
    else:
        print(result.stdout[-1500:])
        print(result.stderr[-500:])
        print("  ✗ Regression detected — existing tests failed")
        return False


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main(target_server: Optional[str] = None) -> int:
    print("=" * 68)
    print("MCPath -- Real MCP Server Verification")
    print("Full flow: connect -> tools/list -> trusted registration -> Stage 1 -> call")
    print("=" * 68)

    # Initialise DB tables (idempotent)
    await init_db()

    specs = _build_server_specs()
    if target_server:
        if target_server not in specs:
            print(f"Unknown server '{target_server}'. Available: {list(specs)}")
            return 1
        servers_to_check = {target_server: specs[target_server]}
    else:
        servers_to_check = specs

    results: dict[str, bool] = {}
    for name, spec in servers_to_check.items():
        results[name] = await verify_server(name, spec)

    # Regression check only when running all servers (or explicitly requested)
    if not target_server:
        results["_regression"] = await verify_sample_regression()

    # ── Summary ─────────────────────────────────────────────────────────────
    print(f"\n{'='*68}")
    print("SUMMARY")
    print(f"{'='*68}")
    all_passed = True
    for name, passed in results.items():
        label = "sample regression" if name == "_regression" else name
        icon = "✓" if passed else "✗"
        print(f"  {icon}  {label}")
        if not passed:
            all_passed = False

    if all_passed:
        print("\n  All checks passed.")
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
    except* (asyncio.CancelledError, KeyboardInterrupt):
        pass
