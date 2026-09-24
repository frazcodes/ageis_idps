"""Configuration for the Aegis network sensor.

Capture is **disabled by default** and no interface is selected by default.
Enabling capture without naming an interface is a configuration error: guessing
an interface would risk capturing on the wrong link.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Self

from pydantic import Field, field_validator, model_validator
from pydantic_settings import SettingsConfigDict

from aegis_shared.config import AegisSettings


class SensorSettings(AegisSettings):
    """Settings for a single network sensor instance."""

    model_config = SettingsConfigDict(
        env_prefix="AEGIS_SENSOR_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    sensor_id: str = Field(
        default="",
        description="Stable sensor identifier. Empty falls back to 'sensor-<interface>'.",
    )
    interface: str = Field(default="", description="Capture interface, e.g. eth0. Empty = none.")
    promiscuous: bool = Field(
        default=False,
        description="Put the interface in promiscuous mode (requires privileges).",
    )
    capture_enabled: bool = Field(
        default=False,
        description="Master switch for packet capture. Disabled until explicitly enabled.",
    )
    capture_filter: str = Field(
        default=(
            "(ip or ip6) and not port 5353 and not port 1900 and not arp"
            " and not port 5355 and not port 137 and not port 138"
            " and not port 427"
        ),
        description=(
            "BPF capture filter applied at the driver level. Drops ARP, "
            "mDNS (5353), SSDP (1900), LLMNR (5355), NetBIOS (137/138), "
            "and SAP (427) to reduce Python-side processing. "
            "Override via AEGIS_SENSOR_CAPTURE_FILTER or set empty to "
            "capture everything."
        ),
    )
    max_packets_per_run: int = Field(
        default=200,
        ge=1,
        le=1_000_000,
        description="Upper bound on packets processed in a single capture run.",
    )
    max_packet_bytes: int = Field(
        default=65535,
        ge=64,
        le=262144,
        description="Packets larger than this are skipped (processing bound).",
    )
    capture_timeout_seconds: float = Field(
        default=0.2,
        ge=0.05,
        le=30.0,
        description="Max seconds per capture run. Prevents UI freeze on low-traffic interfaces.",
    )
    local_addresses: list[str] = Field(
        default_factory=list,
        description="Local interface addresses used to determine flow direction. "
        "Empty = direction stays 'unknown'. Comma-separated in the environment.",
    )
    flow_window_seconds: int = Field(
        default=10,
        ge=1,
        le=3600,
        description="Aggregation window for future flow summarisation (unused today).",
    )

    @field_validator("local_addresses", mode="before")
    @classmethod
    def _split_addresses(cls, value: object) -> object:
        """Accept a comma-separated string from the environment as well as a list."""
        if isinstance(value, str):
            raw = value.strip()
            if not raw or raw.startswith("["):
                return value if raw else []
            return [item.strip() for item in raw.split(",") if item.strip()]
        return value

    @model_validator(mode="after")
    def _require_interface_when_capturing(self) -> Self:
        if self.capture_enabled and not self.interface.strip():
            raise ValueError(
                "capture_enabled requires an explicit interface; "
                "automatic interface selection is not performed"
            )
        return self


@lru_cache(maxsize=1)
def get_sensor_settings() -> SensorSettings:
    """Return the process-wide sensor settings (loaded once)."""
    return SensorSettings()


__all__ = ["SensorSettings", "get_sensor_settings"]
