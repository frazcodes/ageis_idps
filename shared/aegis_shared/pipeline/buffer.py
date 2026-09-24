"""Bounded, thread-safe, in-memory event buffer.

Overflow policy
---------------
The buffer is a strict FIFO queue with a fixed capacity. When full, the
**oldest** event is evicted to make room for the newest. This is deterministic,
keeps memory strictly bounded, and favours recent telemetry. Evictions are
counted in :attr:`dropped`.

Thread safety
-------------
Every public method takes an internal lock, so one buffer instance is safe to
share between threads. Lock order is always pipeline -> buffer; the buffer never
calls back into the pipeline, so this cannot deadlock.

Nothing here touches disk or the network.
"""

from __future__ import annotations

import threading
from collections import deque
from collections.abc import Iterable

from aegis_shared.pipeline.models import EventEnvelope

#: Conservative default capacity. ~1k small events is well under a megabyte.
DEFAULT_MAX_EVENTS = 1000


class EventBuffer:
    """A bounded FIFO buffer of :class:`EventEnvelope` objects."""

    def __init__(self, max_events: int = DEFAULT_MAX_EVENTS) -> None:
        if max_events < 1:
            raise ValueError("max_events must be at least 1")
        self._max = max_events
        self._items: deque[EventEnvelope] = deque()
        self._lock = threading.Lock()
        self._appended = 0
        self._dropped = 0

    @property
    def capacity(self) -> int:
        """Maximum number of events the buffer will hold."""
        return self._max

    @property
    def appended(self) -> int:
        """Total events ever appended (including those later dropped)."""
        with self._lock:
            return self._appended

    @property
    def dropped(self) -> int:
        """Total events evicted because the buffer was full."""
        with self._lock:
            return self._dropped

    @property
    def is_empty(self) -> bool:
        """Whether the buffer currently holds no events."""
        with self._lock:
            return not self._items

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)

    def append(self, envelope: EventEnvelope) -> int:
        """Append one event; return the number evicted (0 or 1)."""
        with self._lock:
            return self._append_locked(envelope)

    def extend(self, envelopes: Iterable[EventEnvelope]) -> int:
        """Append many events atomically; return the total number evicted."""
        dropped = 0
        with self._lock:
            for envelope in envelopes:
                dropped += self._append_locked(envelope)
        return dropped

    def drain(self) -> list[EventEnvelope]:
        """Remove and return all buffered events in FIFO order."""
        with self._lock:
            items = list(self._items)
            self._items.clear()
            return items

    def peek(self) -> list[EventEnvelope]:
        """Return a copy of the buffered events in FIFO order, without removing."""
        with self._lock:
            return list(self._items)

    def clear(self) -> None:
        """Discard all buffered events. Cumulative counters are preserved."""
        with self._lock:
            self._items.clear()

    def _append_locked(self, envelope: EventEnvelope) -> int:
        dropped = 0
        if len(self._items) >= self._max:
            self._items.popleft()
            self._dropped += 1
            dropped = 1
        self._items.append(envelope)
        self._appended += 1
        return dropped


__all__ = ["DEFAULT_MAX_EVENTS", "EventBuffer"]
