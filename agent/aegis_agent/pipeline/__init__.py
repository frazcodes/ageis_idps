"""Host event pipeline foundation.

A small, typed, in-memory transport for the canonical
:class:`aegis_shared.events.SecurityEvent` produced by the host monitors.

The transport core is :mod:`aegis_shared.pipeline`; this package re-exports it
for backward compatibility and adds the host-monitor adapters.

Public API
----------
* :class:`HostEventPipeline` - shared pipeline + host monitor adapters.
* :class:`EventBuffer` - bounded thread-safe FIFO buffer.
* :class:`EventEnvelope` - canonical event plus pipeline transport metadata.
* :class:`PipelineStats` / :class:`SubmitResult` - counters and outcomes.
* :func:`validate_event` - deterministic schema/data validation.
* :func:`collect_monitor_events` - adapt process/port/file changes into events.

This is an internal transport foundation only: it is **not** a SIEM, database,
detection engine or response system, and it performs no network transmission.
"""

from __future__ import annotations

from aegis_agent.pipeline.collectors import (
    collect_file_events,
    collect_monitor_events,
    collect_port_events,
    collect_process_events,
)
from aegis_agent.pipeline.pipeline import DEFAULT_DEDUP_WINDOW, HostEventPipeline
from aegis_shared.pipeline import (
    DEFAULT_MAX_EVENTS,
    EventBuffer,
    EventEnvelope,
    PipelineStats,
    SubmitResult,
    ValidationIssue,
    ValidationResult,
    is_valid,
    validate_event,
)

__all__ = [
    "DEFAULT_DEDUP_WINDOW",
    "DEFAULT_MAX_EVENTS",
    "EventBuffer",
    "EventEnvelope",
    "HostEventPipeline",
    "PipelineStats",
    "SubmitResult",
    "ValidationIssue",
    "ValidationResult",
    "collect_file_events",
    "collect_monitor_events",
    "collect_port_events",
    "collect_process_events",
    "is_valid",
    "validate_event",
]
