"""Convenience root script to launch the MCPath Security Proxy.

Usage:
    python run_proxy.py [--server <server_name>] [--log-level <INFO|DEBUG>]
"""

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from mcpath.proxy.run import main

if __name__ == "__main__":
    main()
