"""MCPath Proxy Entrypoint.

Usage:
    python -m mcpath.proxy.run [--server <server_name>] [--log-level <DEBUG|INFO|WARNING>]
"""

import argparse
import asyncio
import sys
from mcpath.core.logging import setup_logging
from mcpath.proxy.passthrough import PassthroughProxy


def main():
    parser = argparse.ArgumentParser(description="MCPath: Zero-Trust MCP Security Proxy")
    parser.add_argument("--server", "-s", type=str, default=None, help="Name of server defined in server_config.json")
    parser.add_argument("--log-level", "-l", type=str, default="INFO", help="Logging level (DEBUG, INFO, WARNING, ERROR)")
    parser.add_argument("--log-file", type=str, default=None, help="Optional log file path")
    args = parser.parse_args()

    # CRITICAL: stdio proxy logs must go to stderr
    setup_logging(level=args.log_level, log_to_file=args.log_file)

    proxy = PassthroughProxy(server_name=args.server)
    try:
        asyncio.run(proxy.run())
    except KeyboardInterrupt:
        sys.stderr.write("\nMCPath Proxy stopped by user.\n")
    except Exception as e:
        sys.stderr.write(f"\nMCPath Proxy exited with error: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
