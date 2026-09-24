"""Typed configuration for the local threat-intelligence / IOC layer.

Defaults are intentionally conservative:

* ``enabled`` is ``True`` but ``indicators`` is empty by default, so the layer
  never matches until an operator explicitly configures indicators (the same
  "empty criteria never matches" convention the detection rules use).
* Indicators are supplied as ``type:value`` entries, e.g. ``ip:203.0.113.30``,
  ``domain:example.test`` or ``file_hash:<sha256>``. No real malicious
  indicators are shipped; only reserved/documentation values belong in tests.
* ``source`` labels where the indicators came from; ``default_confidence`` and
  ``default_severity`` describe them when a richer feed is not available.

This is a local, static source. No external download, API call or credential is
performed or stored. Environment prefix: ``AEGIS_THREAT_INTEL_``.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import SettingsConfigDict

from aegis_shared.config import AegisSettings
from aegis_shared.enums import Severity


class ThreatIntelSettings(AegisSettings):
    """Local indicator configuration and defaults for the IOC layer."""

    model_config = SettingsConfigDict(
        env_prefix="AEGIS_THREAT_INTEL_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    enabled: bool = Field(
        default=True,
        description="Master switch for IOC matching. With no indicators, never matches.",
    )

    indicators: list[str] = Field(
        default_factory=list,
        description=(
            "Locally configured indicators as 'type:value' (ip, domain, file_hash). "
            "Empty = the layer never matches."
        ),
    )

    source: str = Field(
        default="configured",
        max_length=128,
        description="Provenance label recorded on indicators/matches from this source.",
    )

    default_confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Confidence recorded on configured indicators without an explicit value.",
    )

    default_severity: Severity = Field(
        default=Severity.MEDIUM,
        description="Severity recorded on configured indicators without an explicit value.",
    )

    @field_validator("indicators", mode="before")
    @classmethod
    def _split_indicators(cls, value: object) -> object:
        """Accept a comma-separated string from the environment as well as a list."""
        if isinstance(value, str):
            raw = value.strip()
            if not raw or raw.startswith("["):
                return value if raw else []
            return [item.strip() for item in raw.split(",") if item.strip()]
        return value

    @field_validator("indicators")
    @classmethod
    def _clean_indicators(cls, value: list[str]) -> list[str]:
        return [item.strip() for item in value if item.strip()]

    @field_validator("source")
    @classmethod
    def _clean_source(cls, value: str) -> str:
        return value.strip() or "configured"


@lru_cache(maxsize=1)
def get_threat_intel_settings() -> ThreatIntelSettings:
    """Return the process-wide threat-intelligence settings (loaded once)."""
    return ThreatIntelSettings()


__all__ = ["ThreatIntelSettings", "get_threat_intel_settings"]
