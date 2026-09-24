"""Generic in-memory event pipeline shared by Aegis producers.

This is the transport core reused by the host agent and the network sensor. It
carries the canonical :class:`aegis_shared.events.SecurityEvent` and performs no
I/O: no disk, no network, no database. Component-specific pipelines subclass
:class:`EventPipeline` and add their own producer adapters.
"""

from __future__ import annotations

from aegis_shared.pipeline.buffer import DEFAULT_MAX_EVENTS, EventBuffer
from aegis_shared.pipeline.models import EventEnvelope, PipelineStats, SubmitResult
from aegis_shared.pipeline.pipeline import DEFAULT_DEDUP_WINDOW, EventPipeline
from aegis_shared.pipeline.runtime import (
    clear_active_pipeline,
    get_active_pipeline,
    set_active_pipeline,
)
from aegis_shared.pipeline.validation import (
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
    "EventPipeline",
    "PipelineStats",
    "SubmitResult",
    "ValidationIssue",
    "ValidationResult",
    "clear_active_pipeline",
    "get_active_pipeline",
    "is_valid",
    "set_active_pipeline",
    "validate_event",
]
