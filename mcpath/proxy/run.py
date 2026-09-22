"""MCPath Proxy Entrypoint.

Usage:
    python -m mcpath.proxy.run [--server <server1,server2...>] [--log-level <DEBUG|INFO|WARNING>]
"""

import argparse
import asyncio
import sys
from mcpath.core.logging import setup_logging
from mcpath.proxy.passthrough import PassthroughProxy


def main():
    parser = argparse.ArgumentParser(description="MCPath: Zero-Trust MCP Security Proxy")
    parser.add_argument(
        "--server", "-s",
        type=str,
        default=None,
        help="Optional server name or comma-separated list of servers to proxy (defaults to all active_servers)"
    )
    parser.add_argument("--log-level", "-l", type=str, default="INFO", help="Logging level (DEBUG, INFO, WARNING, ERROR)")
    parser.add_argument("--log-file", type=str, default=None, help="Optional log file path")
    args = parser.parse_args()

    # CRITICAL: stdio proxy logs must go to stderr
    setup_logging(level=args.log_level, log_to_file=args.log_file)

    server_names = [s.strip() for s in args.server.split(",")] if args.server else None
    proxy = PassthroughProxy(server_names=server_names)
    try:
        asyncio.run(proxy.run())
    except KeyboardInterrupt:
        sys.stderr.write("\nMCPath Proxy stopped by user.\n")
    except Exception as e:
        sys.stderr.write(f"\nMCPath Proxy exited with error: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
