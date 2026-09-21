"""Custom exceptions for MCPath."""


class MCPathError(Exception):
    """Base exception for all MCPath errors."""
    pass


class ConfigurationError(MCPathError):
    """Raised when configuration is invalid or missing."""
    pass


class DownstreamConnectionError(MCPathError):
    """Raised when connection to downstream MCP server fails."""
    pass


class SecurityGateViolation(MCPathError):
    """Raised when a security check hard-blocks a tool execution."""
    def __init__(self, stage: str, reason: str, details: dict | None = None):
        super().__init__(f"Security Gate Blocked at [{stage}]: {reason}")
        self.stage = stage
        self.reason = reason
        self.details = details or {}


class HashMismatchError(SecurityGateViolation):
    """Stage 1: Tool definition changed after approval (rug pull)."""
    def __init__(self, tool_name: str, expected_hash: str, observed_hash: str):
        super().__init__(
            stage="Stage 1 - Hash Check",
            reason=f"Tool definition changed for '{tool_name}'",
            details={"tool_name": tool_name, "expected_hash": expected_hash, "observed_hash": observed_hash}
        )
