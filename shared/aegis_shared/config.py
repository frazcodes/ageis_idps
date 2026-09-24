"""Typed, environment-driven configuration shared by every Aegis component.

Every component settings class subclasses :class:`AegisSettings`, which loads from
``AEGIS_*`` environment variables and, for local development only, an optional
``.env`` file. Secrets are never given in-code defaults: use
:class:`pydantic.SecretStr` for credentials and fail loudly when a required value
is missing in production.

Naming convention (see ``.env.example``): ``AEGIS_<COMPONENT>_<SETTING>``.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

#: Accepted log level names, ordered from least to most verbose.
LogLevel = str


class Environment(StrEnum):
    """Deployment environment the component is running in."""

    DEVELOPMENT = "development"
    TESTING = "testing"
    PRODUCTION = "production"

    @property
    def is_production(self) -> bool:
        """Whether this is the production environment."""
        return self is Environment.PRODUCTION


class AegisSettings(BaseSettings):
    """Base settings for any Aegis component.

    Subclasses add component-specific fields. Unknown ``AEGIS_*`` variables are
    ignored so that a single ``.env`` can be shared by the whole monorepo.
    """

    model_config = SettingsConfigDict(
        env_prefix="AEGIS_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    environment: Environment = Field(
        default=Environment.DEVELOPMENT,
        description="Deployment environment; drives safety defaults.",
    )
    log_level: str = Field(default="INFO", description="Root log level.")
    log_json: bool = Field(
        default=False,
        description="Emit structured JSON logs (recommended in production).",
    )

    @property
    def is_production(self) -> bool:
        """Whether the component is running in production."""
        return self.environment.is_production

    @property
    def is_development(self) -> bool:
        """Whether the component is running in development."""
        return self.environment is Environment.DEVELOPMENT


@lru_cache(maxsize=1)
def get_settings() -> AegisSettings:
    """Return the process-wide global settings (loaded once)."""
    return AegisSettings()


__all__ = ["AegisSettings", "Environment", "LogLevel", "get_settings"]
