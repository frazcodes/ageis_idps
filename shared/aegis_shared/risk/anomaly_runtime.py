"""A tiny registry for the latest ML anomaly signals.

Anomaly detection (host and network) produces :class:`AnomalySignal` objects for
canonical events. The integrated runtime computes them as part of its bounded
poll cycle; this registry lets it publish the most recent signals so that
read-only observers - such as the desktop investigation view - can look them up
by ``event_id`` without re-running any model or creating a second event store.

Publishing or reading signals has no side effects: it never starts monitoring,
capture, evaluation loops, scoring, detection, correlation or response.
"""

from __future__ import annotations

from aegis_shared.risk.models import AnomalySignal

_active: dict[str, AnomalySignal] | None = None


def set_active_anomaly_signals(signals: dict[str, AnomalySignal] | None) -> None:
    """Publish (or clear) the latest anomaly signals for read-only observers."""
    global _active
    _active = dict(signals) if signals is not None else None


def get_active_anomaly_signals() -> dict[str, AnomalySignal]:
    """Return the published signals, or an empty mapping when none are published."""
    return _active or {}


def clear_active_anomaly_signals() -> None:
    """Clear the published signals. Observers will show no anomaly."""
    global _active
    _active = None


__all__ = [
    "clear_active_anomaly_signals",
    "get_active_anomaly_signals",
    "set_active_anomaly_signals",
]
