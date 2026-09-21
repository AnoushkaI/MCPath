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

    def get_server_config(self) -> ServerConfig:
        p = Path(self.server_config_path)
        if not p.is_absolute():
            p = (PROJECT_ROOT / p).resolve()
        return ServerConfig.load_from_file(p)


settings = Settings()
