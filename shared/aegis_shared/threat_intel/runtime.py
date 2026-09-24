"""A tiny registry for the current IOC matches.

The integrated runtime matches observables as part of its bounded poll cycle;
this registry lets it publish the current in-memory matches so that read-only
observers - such as the desktop investigation/incident views - can inspect them
without creating a second store or a database.

Publishing or reading matches has no side effects: it never starts monitoring,
capture, matching, scoring, correlation or response.
"""

from __future__ import annotations

from aegis_shared.threat_intel.models import IOCMatch

_active: tuple[IOCMatch, ...] | None = None


def set_active_ioc_matches(matches: tuple[IOCMatch, ...] | None) -> None:
    """Publish (or clear) the current IOC matches for read-only observers."""
    global _active
    _active = tuple(matches) if matches is not None else None


def get_active_ioc_matches() -> tuple[IOCMatch, ...]:
    """Return the published IOC matches, or an empty tuple when none are published."""
    return _active or ()


def clear_active_ioc_matches() -> None:
    """Clear the published IOC matches. Observers will show no match."""
    global _active
    _active = None


__all__ = ["clear_active_ioc_matches", "get_active_ioc_matches", "set_active_ioc_matches"]
