"""Logging configuration for MCPath.

CRITICAL ARCHITECTURAL REQUIREMENT:
When operating as an MCP stdio proxy, stdout is strictly reserved for JSON-RPC messages.
All application logs, diagnostic messages, and security audit prints MUST be routed
exclusively to sys.stderr or dedicated log files to avoid stream corruption.
"""

import logging
import sys
from typing import Optional


def setup_logging(
    level: str = "INFO",
    log_to_file: Optional[str] = None
) -> logging.Logger:
    """Configure structured logging for MCPath."""
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Avoid duplicate handlers if called multiple times
    root_logger.handlers.clear()

    # Formatter for stderr output
    formatter = logging.Formatter(
        fmt="[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # All console logs go to sys.stderr
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(numeric_level)
    stderr_handler.setFormatter(formatter)
    root_logger.addHandler(stderr_handler)

    # Optional file logger
    if log_to_file:
        file_handler = logging.FileHandler(log_to_file, encoding="utf-8")
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    logger = logging.getLogger("mcpath")
    logger.debug("MCPath logging initialized with level=%s", level)
    return logger
