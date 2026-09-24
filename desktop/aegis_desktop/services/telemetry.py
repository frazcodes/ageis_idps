"""Bounded in-memory telemetry history for dashboard visualization.

Stores aggregate metric samples from the existing runtime polling cycle.
Each sample captures a point-in-time snapshot of network, security and risk
metrics.  No packet payloads, credentials, command lines or file contents
are stored.

The store is bounded (default 120 points) and evicts oldest samples first.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

#: Maximum number of telemetry samples retained.
MAX_TELEMETRY_POINTS: int = 120


@dataclass(frozen=True)
class TelemetrySample:
    """One point-in-time aggregate metric sample."""

    timestamp: datetime
    packets: int | None
    bytes: int | None
    flows: int | None
    active_flows: int | None
    events: int
    findings: int
    high_risk_findings: int
    open_incidents: int
    risk_score: int | None


class TelemetryHistory:
    """Bounded, append-only in-memory telemetry history.

    When the store reaches ``max_points`` the oldest sample is evicted.
    """

    def __init__(self, max_points: int = MAX_TELEMETRY_POINTS) -> None:
        self._max = max_points
        self._samples: list[TelemetrySample] = []

    @property
    def count(self) -> int:
        """Current number of stored samples."""
        return len(self._samples)

    def add(self, sample: TelemetrySample) -> None:
        """Append a sample, evicting the oldest when at capacity."""
        self._samples.append(sample)
        if len(self._samples) > self._max:
            self._samples = self._samples[-self._max :]

    def samples(self) -> tuple[TelemetrySample, ...]:
        """Return all samples, oldest first (chronological order)."""
        return tuple(self._samples)

    def latest(self) -> TelemetrySample | None:
        """Return the most recent sample, or ``None`` if empty."""
        return self._samples[-1] if self._samples else None

    def clear(self) -> None:
        """Remove all samples."""
        self._samples.clear()


__all__ = ["MAX_TELEMETRY_POINTS", "TelemetryHistory", "TelemetrySample"]
