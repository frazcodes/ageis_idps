"""A tiny registry for the current asset snapshot.

The integrated runtime updates assets as part of its bounded poll cycle; this
registry lets it publish the latest read-only snapshot so the desktop can inspect
it without creating a second store or a database.

Publishing or reading the snapshot has no side effects: it never starts
monitoring, capture, detection, scoring or response.
"""

from __future__ import annotations

from aegis_shared.assets.models import AssetSnapshot

_active: AssetSnapshot | None = None


def set_active_asset_snapshot(snapshot: AssetSnapshot | None) -> None:
    """Publish (or clear) the current asset snapshot for read-only observers."""
    global _active
    _active = snapshot


def get_active_asset_snapshot() -> AssetSnapshot | None:
    """Return the published asset snapshot, or ``None`` when none is published."""
    return _active


def clear_active_asset_snapshot() -> None:
    """Clear the published asset snapshot. Observers will show no assets."""
    global _active
    _active = None


__all__ = [
    "clear_active_asset_snapshot",
    "get_active_asset_snapshot",
    "set_active_asset_snapshot",
]
