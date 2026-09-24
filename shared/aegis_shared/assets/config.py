"""Typed configuration for the asset / network-identity layer.

All limits are bounded so in-memory state cannot grow without limit. Defaults are
sized for a single-host FYP/demo deployment. Environment prefix:
``AEGIS_ASSETS_``.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import SettingsConfigDict

from aegis_shared.config import AegisSettings


class AssetSettings(AegisSettings):
    """Bounded limits for the asset registry and baseline."""

    model_config = SettingsConfigDict(
        env_prefix="AEGIS_ASSETS_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    enabled: bool = Field(
        default=True,
        description="Master switch for asset/peer observation.",
    )
    max_assets: int = Field(
        default=64,
        ge=1,
        le=100_000,
        description="Maximum assets retained (oldest last_seen evicted first).",
    )
    max_peers: int = Field(
        default=2048,
        ge=1,
        le=1_000_000,
        description="Maximum network peers retained (oldest last_seen evicted first).",
    )
    max_services_per_asset: int = Field(
        default=256,
        ge=1,
        le=100_000,
        description="Maximum observed services retained per asset.",
    )
    max_tracked_flows: int = Field(
        default=4096,
        ge=1,
        le=1_000_000,
        description="Maximum flow ids tracked for incremental peer counters.",
    )
    baseline_max_entries: int = Field(
        default=8192,
        ge=1,
        le=10_000_000,
        description="Maximum known-entity entries retained per baseline kind.",
    )
    active_window_seconds: int = Field(
        default=300,
        ge=1,
        le=86400,
        description="How long after last_seen an asset is still considered active.",
    )


@lru_cache(maxsize=1)
def get_asset_settings() -> AssetSettings:
    """Return the process-wide asset settings (loaded once)."""
    return AssetSettings()


__all__ = ["AssetSettings", "get_asset_settings"]
