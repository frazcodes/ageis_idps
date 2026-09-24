"""Asset / network-identity context for Aegis.

Builds a bounded, factual view of the hosts Aegis observes, their observed
listening services and their network peers, plus a bounded baseline that answers
"have we seen this before?". This is **context**, not a verdict: a new
observation is not a malicious one.
"""

from __future__ import annotations

from aegis_shared.assets.config import AssetSettings, get_asset_settings
from aegis_shared.assets.models import (
    AssetIdentity,
    AssetSnapshot,
    AssetStatus,
    NetworkPeer,
    ObservedService,
)
from aegis_shared.assets.registry import AssetRegistry
from aegis_shared.assets.runtime import (
    clear_active_asset_snapshot,
    get_active_asset_snapshot,
    set_active_asset_snapshot,
)

__all__ = [
    "AssetIdentity",
    "AssetRegistry",
    "AssetSettings",
    "AssetSnapshot",
    "AssetStatus",
    "NetworkPeer",
    "ObservedService",
    "clear_active_asset_snapshot",
    "get_active_asset_snapshot",
    "get_asset_settings",
    "set_active_asset_snapshot",
]
