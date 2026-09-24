"""Configuration for the Aegis IDPS backend service.

Global settings (environment, logging) come from :class:`aegis_shared.config.AegisSettings`;
backend-specific settings use the ``AEGIS_BACKEND_`` prefix and database settings
the ``AEGIS_DB_`` prefix, mirroring ``.env.example``.
"""

from __future__ import annotations

from functools import lru_cache
from urllib.parse import quote_plus

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import SettingsConfigDict

from aegis_shared.config import AegisSettings


class BackendSettings(AegisSettings):
    """HTTP/API settings for the backend process."""

    model_config = SettingsConfigDict(
        env_prefix="AEGIS_BACKEND_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    host: str = Field(default="127.0.0.1", description="Bind address for the API server.")
    port: int = Field(default=8000, ge=1, le=65535, description="Bind port for the API server.")
    cors_origins: list[str] = Field(
        default_factory=list,
        description="Allowed browser origins (comma-separated). Empty by default: the "
        "administrator UI is a native desktop application, not a browser page.",
    )
    api_key: SecretStr | None = Field(
        default=None,
        description="Shared secret for agent/sensor ingestion. Never logged.",
    )

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        """Accept a comma-separated string from the environment as well as a list."""
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value


class DatabaseSettings(AegisSettings):
    """PostgreSQL connection settings."""

    model_config = SettingsConfigDict(
        env_prefix="AEGIS_DB_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    host: str = "127.0.0.1"
    port: int = Field(default=5432, ge=1, le=65535)
    name: str = "aegis"
    user: str = "aegis"
    password: SecretStr = SecretStr("")
    echo: bool = Field(default=False, description="Echo SQL to the log stream (debug only).")

    @property
    def sqlalchemy_url(self) -> str:
        """SQLAlchemy connection URL for the PostgreSQL database.

        Credentials are URL-encoded so that special characters in a password do
        not corrupt the DSN.
        """
        user = quote_plus(self.user)
        password = quote_plus(self.password.get_secret_value())
        return f"postgresql+psycopg://{user}:{password}@{self.host}:{self.port}/{self.name}"


@lru_cache(maxsize=1)
def get_backend_settings() -> BackendSettings:
    """Return the process-wide backend settings (loaded once)."""
    return BackendSettings()


@lru_cache(maxsize=1)
def get_database_settings() -> DatabaseSettings:
    """Return the process-wide database settings (loaded once)."""
    return DatabaseSettings()


__all__ = [
    "BackendSettings",
    "DatabaseSettings",
    "get_backend_settings",
    "get_database_settings",
]
