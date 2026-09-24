"""Typed configuration for the deterministic incident correlator.

Defaults are intentionally conservative and documented:

* ``window_seconds`` (300, i.e. 5 minutes) bounds how far apart related activity
  may be. Activity from hours apart is never correlated.
* ``min_findings`` (2) is the minimum number of related findings required before
  an incident is formed, so a single isolated finding stays a finding.
* ``correlation_version`` is a non-empty label stamped into incident reasoning.

Environment prefix: ``AEGIS_CORRELATION_``.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import SettingsConfigDict

from aegis_shared.config import AegisSettings


class CorrelationSettings(AegisSettings):
    """Bounded, deterministic parameters for incident correlation."""

    model_config = SettingsConfigDict(
        env_prefix="AEGIS_CORRELATION_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    correlation_version: str = Field(
        default="1",
        min_length=1,
        max_length=32,
        description="Label stamped on incidents; bump when the correlation rules change.",
    )

    window_seconds: int = Field(
        default=300,
        ge=1,
        le=86400,
        description="Maximum seconds between related findings on the same host.",
    )

    min_findings: int = Field(
        default=2,
        ge=2,
        le=100,
        description="Minimum related findings required before an incident is formed.",
    )

    host_network_correlation_window_seconds: int = Field(
        default=300,
        ge=1,
        le=86400,
        description=(
            "Maximum seconds between host-side and network-side findings on the "
            "same host for them to be correlated as related evidence."
        ),
    )


@lru_cache(maxsize=1)
def get_correlation_settings() -> CorrelationSettings:
    """Return the process-wide correlation settings (loaded once)."""
    return CorrelationSettings()


__all__ = ["CorrelationSettings", "get_correlation_settings"]
