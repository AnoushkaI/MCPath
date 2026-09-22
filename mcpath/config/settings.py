"""Configuration settings for MCPath."""

from pathlib import Path
from typing import Any, Dict
import json
import os
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class ServerDefinition(BaseSettings):
    """Configuration for a single downstream MCP server."""
    command: str
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)


class ServerConfig(BaseSettings):
    """Collection of configured downstream MCP servers."""
    active_server: str = "sample_reference_server"
    servers: dict[str, ServerDefinition] = Field(default_factory=dict)

    @classmethod
    def load_from_file(cls, path: str | Path) -> "ServerConfig":
        file_path = Path(path)
        if not file_path.is_absolute():
            file_path = (PROJECT_ROOT / file_path).resolve()
        if not file_path.exists():
            return cls()
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(**data)


class Settings(BaseSettings):
    """Global MCPath configuration."""
    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

    env: str = Field(default="development", alias="MCPATH_ENV")
    log_level: str = Field(default="INFO", alias="MCPATH_LOG_LEVEL")
    server_config_path: str = Field(default="config/server_config.json", alias="MCPATH_SERVER_CONFIG")

    # Database URLs
    database_url: str = Field(
        default="postgresql+asyncpg://postgres:postgres@localhost:5432/mcpath",
        alias="DATABASE_URL"
    )
    sqlite_fallback_url: str = Field(
        default="sqlite+aiosqlite:///mcpath.db",
        alias="SQLITE_FALLBACK_URL"
    )

    # Backend API
    backend_host: str = Field(default="127.0.0.1", alias="BACKEND_HOST")
    backend_port: int = Field(default=8000, alias="BACKEND_PORT")

    # Pipeline Thresholds
    intent_similarity_threshold: float = Field(default=0.70, alias="INTENT_SIMILARITY_THRESHOLD")
    behaviour_deviation_threshold: float = Field(default=0.60, alias="BEHAVIOUR_DEVIATION_THRESHOLD")
    response_risk_threshold: float = Field(default=0.65, alias="RESPONSE_RISK_THRESHOLD")

    # Optional model keys for Stage 5 secondary classifier
    anthropic_api_key: str | None = Field(default=None, alias="ANTHROPIC_API_KEY")

    # Real downstream MCP server configuration.
    # Set these in .env — no defaults to avoid accidentally granting access to
    # unintended paths. Leave blank to skip the corresponding server.
    filesystem_allowed_paths: str = Field(default="", alias="FILESYSTEM_ALLOWED_PATHS")
    git_repository_path: str = Field(default="", alias="GIT_REPOSITORY_PATH")
    postgres_mcp_connection_string: str = Field(default="", alias="POSTGRES_MCP_CONNECTION_STRING")

    def get_server_config(self) -> ServerConfig:
        p = Path(self.server_config_path)
        if not p.is_absolute():
            p = (PROJECT_ROOT / p).resolve()
        return ServerConfig.load_from_file(p)


def interpolate_server_config(server_def: "ServerDefinition", s: "Settings") -> "ServerDefinition":
    """Expand ${VAR} placeholders in a ServerDefinition's args and env values.

    Placeholder resolution:
      1. Settings fields loaded from .env (FILESYSTEM_ALLOWED_PATHS, GIT_REPOSITORY_PATH, …).
      2. Raw OS environment (os.environ) as a fallback for anything else.

    Keeps machine-specific paths and credentials out of server_config.json while
    allowing the config to remain fully declarative. Unresolved ${VAR} tokens are
    left unchanged so errors surface clearly in logs rather than silently.
    """
    import re

    # Build lookup: start with full OS environment so spawned subprocesses inherit PATH.
    lookup: dict[str, str] = dict(os.environ)

    # Overlay settings fields (already incorporate .env values) so they take precedence.
    for field_name, field_info in Settings.model_fields.items():
        alias = field_info.alias or field_name
        value = getattr(s, field_name, None)
        if value is not None:
            lookup[str(alias)] = str(value)
            lookup[field_name.upper()] = str(value)  # also accept UPPER_FIELD_NAME form

    def _expand(text: str) -> str:
        def _replace(m: re.Match) -> str:
            return lookup.get(m.group(1), m.group(0))  # leave unresolved ${VAR} unchanged
        return re.sub(r"\$\{([^}]+)\}", _replace, text)

    return ServerDefinition(
        command=server_def.command,
        args=[_expand(a) for a in server_def.args],
        env={k: _expand(v) for k, v in server_def.env.items()},
    )


settings = Settings()
