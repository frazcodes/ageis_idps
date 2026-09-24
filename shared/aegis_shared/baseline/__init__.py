"""Deterministic, bounded baseline of known network entities.

Provides KNOWN vs NEW context for IPs, hosts, destinations, ports and
relationships. It is contextual only - it never produces a verdict, score or
response. **A new observation is not a malicious one.**
"""

from __future__ import annotations

from aegis_shared.baseline.baseline import (
    DEFAULT_BASELINE_MAX_ENTRIES,
    KnownState,
    NetworkBaseline,
    ObservationKind,
    utc_now,
)

__all__ = [
    "DEFAULT_BASELINE_MAX_ENTRIES",
    "KnownState",
    "NetworkBaseline",
    "ObservationKind",
    "utc_now",
]
