"""Deterministic, bounded network baseline (known-entity memory).

The baseline answers factual "have we observed this before?" questions about
entities already present in Aegis telemetry: IPs, hosts, destinations, ports and
communication relationships. It keeps a bounded amount of recent memory and
provides KNOWN vs NEW context.

It never produces a verdict, never scores and never blocks. A NEW observation is
simply one not seen before - it is not "malicious".
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from aegis_shared.logging import get_logger

logger = get_logger(__name__)

#: Default bound on entries retained per observation kind.
DEFAULT_BASELINE_MAX_ENTRIES = 8192


class ObservationKind(StrEnum):
    """The kinds of known entity the baseline tracks."""

    IP = "ip"
    HOST = "host"
    DESTINATION = "destination"
    PORT = "port"
    DESTINATION_PORT = "destination_port"
    RELATIONSHIP = "relationship"


@dataclass(frozen=True)
class KnownState:
    """First/last seen and observation count for one known entity."""

    first_seen: datetime
    last_seen: datetime
    count: int


@dataclass
class _Seen:
    first_seen: datetime
    last_seen: datetime
    count: int = 0


class NetworkBaseline:
    """Bounded, deterministic known-entity memory."""

    def __init__(self, *, max_entries: int = DEFAULT_BASELINE_MAX_ENTRIES) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be at least 1")
        self._max_entries = max_entries
        self._kinds: dict[ObservationKind, OrderedDict[str, _Seen]] = {
            kind: OrderedDict() for kind in ObservationKind
        }

    @property
    def max_entries(self) -> int:
        """Maximum entries retained per kind."""
        return self._max_entries

    def observe(self, kind: ObservationKind, key: str, timestamp: datetime) -> bool:
        """Record an observation; return ``True`` when it was known beforehand."""
        if not key:
            return False
        bucket = self._kinds[kind]
        existing = bucket.get(key)
        known_before = existing is not None
        if existing is None:
            bucket[key] = _Seen(first_seen=timestamp, last_seen=timestamp, count=1)
        else:
            existing.last_seen = timestamp
            existing.count += 1
        bucket.move_to_end(key)
        while len(bucket) > self._max_entries:
            bucket.popitem(last=False)
        return known_before

    def is_known(self, kind: ObservationKind, key: str) -> bool:
        """Whether ``key`` has been observed before."""
        return key in self._kinds[kind]

    def count(self, kind: ObservationKind, key: str) -> int:
        """Number of times ``key`` has been observed (0 when unknown)."""
        seen = self._kinds[kind].get(key)
        return seen.count if seen is not None else 0

    def known_count(self, kind: ObservationKind) -> int:
        """Number of distinct known entities of ``kind``."""
        return len(self._kinds[kind])

    def known_state(self, kind: ObservationKind, key: str) -> KnownState | None:
        """Return the known state for ``key``, or ``None`` when unknown."""
        seen = self._kinds[kind].get(key)
        if seen is None:
            return None
        return KnownState(first_seen=seen.first_seen, last_seen=seen.last_seen, count=seen.count)

    def keys(self, kind: ObservationKind) -> Iterator[str]:
        """Iterate the known keys of ``kind`` (deterministic insertion order)."""
        return iter(tuple(self._kinds[kind]))

    def counts(self) -> dict[str, int]:
        """Distinct known-entity counts per kind (deterministic)."""
        return {kind.value: len(bucket) for kind, bucket in self._kinds.items()}

    def clear(self) -> None:
        """Drop all known state (runtime stop)."""
        for bucket in self._kinds.values():
            bucket.clear()


def utc_now() -> datetime:
    """Return the current UTC time (kept here so callers share one source)."""
    return datetime.now(UTC)


__all__ = [
    "DEFAULT_BASELINE_MAX_ENTRIES",
    "KnownState",
    "NetworkBaseline",
    "ObservationKind",
    "utc_now",
]
