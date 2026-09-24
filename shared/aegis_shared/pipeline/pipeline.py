"""A generic in-memory event pipeline.

Flow::

    producer -> SecurityEvent -> validate -> bounded dedup -> bounded buffer -> drain
                                                                                 |
                                                            (future exporter / backend)

Design properties
-----------------
* **Canonical events only.** The pipeline transports
  :class:`aegis_shared.events.SecurityEvent`; it never invents a second schema.
* **Validation before admission.** Structurally invalid events are rejected and
  counted; they never enter the buffer.
* **Bounded everything.** The buffer and the duplicate-ID window are both
  bounded, so memory cannot grow without limit.
* **Stable ordering.** Events are appended in submission order and drained in
  FIFO order; they are never reordered by timestamp, and equal timestamps keep
  insertion order. No claim is made about global distributed ordering.
* **Conservative dedup.** Only an exact repeat of a previously seen ``event_id``
  is rejected. No heuristic or content-based deduplication is performed, so
  legitimate events are never silently dropped. The dedup window is bounded and
  evicts oldest-first.
* **No I/O.** Nothing is written to disk, transmitted, executed or blocked on.

Component-specific pipelines (host, network) subclass this and add only their
producer adapters.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Callable, Iterable
from datetime import UTC, datetime

from aegis_shared.events import SecurityEvent
from aegis_shared.pipeline.buffer import DEFAULT_MAX_EVENTS, EventBuffer
from aegis_shared.pipeline.models import EventEnvelope, PipelineStats, SubmitResult
from aegis_shared.pipeline.validation import validate_event

#: How many recent event IDs are remembered for exact-duplicate rejection.
DEFAULT_DEDUP_WINDOW = 4096


class EventPipeline:
    """Validate, deduplicate and buffer canonical events in memory."""

    def __init__(
        self,
        *,
        max_events: int = DEFAULT_MAX_EVENTS,
        dedup_window: int = DEFAULT_DEDUP_WINDOW,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if dedup_window < 1:
            raise ValueError("dedup_window must be at least 1")
        self._buffer = EventBuffer(max_events)
        self._dedup_window = dedup_window
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._lock = threading.RLock()
        self._clock: Callable[[], datetime] = clock or (lambda: datetime.now(UTC))
        self._accepted = 0
        self._rejected = 0
        self._dropped = 0
        self._duplicates = 0
        self._next_sequence = 0

    @property
    def capacity(self) -> int:
        """Maximum number of buffered events."""
        return self._buffer.capacity

    @property
    def dedup_window(self) -> int:
        """How many recent event IDs are remembered for duplicate rejection."""
        return self._dedup_window

    @property
    def is_empty(self) -> bool:
        """Whether the buffer currently holds no events."""
        return self._buffer.is_empty

    def __len__(self) -> int:
        return len(self._buffer)

    def submit(self, event: SecurityEvent) -> SubmitResult:
        """Validate and admit a single event.

        Returns a :class:`SubmitResult`; rejected events are counted but not
        raised, so one bad event never stops a batch.
        """
        validation = validate_event(event)
        if not validation.valid:
            with self._lock:
                self._rejected += 1
            return SubmitResult(accepted=False, reason=validation.summary())

        with self._lock:
            event_id = event.event_id
            if event_id in self._seen:
                self._rejected += 1
                self._duplicates += 1
                return SubmitResult(accepted=False, reason="duplicate_event_id")

            self._remember(event_id)
            sequence = self._next_sequence
            self._next_sequence += 1
            envelope = EventEnvelope(sequence=sequence, enqueued_at=self._clock(), event=event)
            dropped = self._buffer.append(envelope)
            self._accepted += 1
            self._dropped += dropped
            return SubmitResult(accepted=True, sequence=sequence)

    def submit_all(self, events: Iterable[SecurityEvent]) -> list[SubmitResult]:
        """Submit many events in order, returning one result per event."""
        return [self.submit(event) for event in events]

    def drain(self) -> list[EventEnvelope]:
        """Remove and return all buffered envelopes in FIFO order."""
        return self._buffer.drain()

    def peek(self) -> list[EventEnvelope]:
        """Return buffered envelopes in FIFO order without removing them."""
        return self._buffer.peek()

    def clear(self) -> None:
        """Discard buffered events. Cumulative counters are preserved."""
        self._buffer.clear()

    @property
    def stats(self) -> PipelineStats:
        """A consistent snapshot of the pipeline counters."""
        with self._lock:
            return PipelineStats(
                accepted=self._accepted,
                rejected=self._rejected,
                dropped=self._dropped,
                duplicates=self._duplicates,
                buffered=len(self._buffer),
                capacity=self._buffer.capacity,
                next_sequence=self._next_sequence,
            )

    def _remember(self, event_id: str) -> None:
        """Record an ID for duplicate detection, evicting the oldest past the window."""
        self._seen[event_id] = None
        while len(self._seen) > self._dedup_window:
            self._seen.popitem(last=False)


__all__ = ["DEFAULT_DEDUP_WINDOW", "EventPipeline"]
