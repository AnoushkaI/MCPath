"""MCPath Trusted Registration CLI and Engine.

Connects to downstream MCP servers, discovers tools, canonicalizes definitions,
computes SHA-256 integrity hashes, and establishes the approved baseline in PostgreSQL.

Usage:
    python -m mcpath.register --server sample_reference_server
    python -m mcpath.register --all
"""

import argparse
import asyncio
import logging
import sys
from typing import Dict, List, Optional

if sys.stdout.encoding != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from mcpath.backend.persistence.database import init_db, register_trusted_server_and_tools
from mcpath.config.settings import settings, interpolate_server_config
from mcpath.core.logging import setup_logging
from mcpath.pipeline.stages.stage1_hash import canonicalize_and_hash
from mcpath.proxy.client_manager import DownstreamClientManager

logger = logging.getLogger("mcpath.register")


async def register_server_by_name(server_name: str) -> List[Dict[str, str]]:
    """Connect to a named downstream MCP server, discover its tools, and store approved baseline hashes."""
    config = settings.get_server_config()
    if server_name not in config.servers:
        raise ValueError(
            f"Server '{server_name}' not found in configuration ({settings.server_config_path}). "
            f"Available: {list(config.servers.keys())}"
        )

    server_def = config.servers[server_name]
    # Expand ${VAR} placeholders (FILESYSTEM_ALLOWED_PATHS, GIT_REPOSITORY_PATH, etc.)
    server_def = interpolate_server_config(server_def, settings)
    logger.info("Connecting to downstream server '%s' for trusted registration...", server_name)

    client_manager = DownstreamClientManager(server_def=server_def, server_name=server_name)
    async with client_manager.session_context() as session:
        tools_res = await session.list_tools()
        tools = [t.model_dump(mode="json") for t in tools_res.tools]
        logger.info("Discovered %d tools from '%s'", len(tools), server_name)

        synced = await register_trusted_server_and_tools(
            server_name=server_name,
            command=server_def.command,
            args=server_def.args,
            env_vars=server_def.env,
            tools=tools,
            canonicalize_and_hash_fn=canonicalize_and_hash,
            approved_by="admin:trusted_registration"
        )

        results = []
        for tool, approved_hash in synced:
            results.append({
                "tool_name": tool.name,
                "server_name": server_name,
                "hash_sha256": approved_hash.hash_sha256,
                "approved_by": approved_hash.approved_by,
                "is_active": approved_hash.is_active
            })

        return results


async def register_all_configured_servers() -> Dict[str, List[Dict[str, str]]]:
    """Register all configured MCP servers defined in server_config.json."""
    config = settings.get_server_config()
    all_results = {}
    for server_name in config.servers.keys():
        try:
            res = await register_server_by_name(server_name)
            all_results[server_name] = res
        except Exception as e:
            logger.error("Failed to register server '%s': %s", server_name, e)
            all_results[server_name] = []
    return all_results


def main():
    """CLI entrypoint for trusted tool registration."""
    parser = argparse.ArgumentParser(description="MCPath Trusted MCP Tool Registration")
    parser.add_argument(
        "--server",
        type=str,
        default=None,
        help="Name of the server to register from server_config.json"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Register all configured servers in server_config.json"
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level"
    )

    args = parser.parse_args()
    setup_logging(level=args.log_level)

    async def _run():
        await init_db()
        config = settings.get_server_config()

        target_server = args.server or config.active_server
        if args.all:
            print("=" * 70)
            print("MCPath Trusted Registration — All Configured Servers")
            print("=" * 70)
            results = await register_all_configured_servers()
            for s_name, tool_hashes in results.items():
                print(f"\nServer: {s_name} ({len(tool_hashes)} tools registered)")
                for item in tool_hashes:
                    print(f"  - [{item['tool_name']}] SHA-256: {item['hash_sha256']}")
        else:
            print("=" * 70)
            print(f"MCPath Trusted Registration — Server: '{target_server}'")
            print("=" * 70)
            tool_hashes = await register_server_by_name(target_server)
            print(f"\nSuccessfully registered {len(tool_hashes)} tools in PostgreSQL approved baseline:")
            for item in tool_hashes:
                print(f"  - [{item['tool_name']}] SHA-256: {item['hash_sha256']}")

        print("\n" + "=" * 70)
        print("Registration complete. Approved baseline hashes stored in PostgreSQL.")
        print("=" * 70)

    try:
        asyncio.run(_run())
    except Exception as e:
        print(f"Registration failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
