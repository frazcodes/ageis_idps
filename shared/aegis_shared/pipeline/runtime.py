"""A tiny registry for the process-wide event pipeline.

No integrated event-producing runtime exists yet (that is a later architectural
step). This registry lets an embedder publish the pipeline it is running so that
read-only observers - such as the desktop Events page - can inspect buffered
events without creating a second event store or starting anything themselves.

Publishing or reading a pipeline has no side effects: it never starts monitoring,
capture, detection, scoring or transmission.
"""

from __future__ import annotations

from aegis_shared.pipeline.pipeline import EventPipeline

_active: EventPipeline | None = None


def set_active_pipeline(pipeline: EventPipeline | None) -> None:
    """Publish (or clear) the process-wide pipeline for read-only observers."""
    global _active
    _active = pipeline


def get_active_pipeline() -> EventPipeline | None:
    """Return the published pipeline, or ``None`` when no runtime is running."""
    return _active


def clear_active_pipeline() -> None:
    """Clear the published pipeline. Read-only observers will show "not running"."""
    global _active
    _active = None


__all__ = ["clear_active_pipeline", "get_active_pipeline", "set_active_pipeline"]
