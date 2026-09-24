"""A tiny registry for the process-wide detection engine.

No integrated detection runtime exists yet (that is a later architectural step).
This registry lets an embedder publish the engine it is running so that read-only
observers - such as the desktop Detections page - can locate it without creating
a second engine or starting anything.

Publishing or reading an engine has no side effects: it never starts monitoring,
capture, evaluation loops, ML, scoring or response.
"""

from __future__ import annotations

from aegis_shared.detection.engine import DetectionEngine

_active: DetectionEngine | None = None


def set_active_engine(engine: DetectionEngine | None) -> None:
    """Publish (or clear) the process-wide detection engine for observers."""
    global _active
    _active = engine


def get_active_engine() -> DetectionEngine | None:
    """Return the published engine, or ``None`` when no runtime is running."""
    return _active


def clear_active_engine() -> None:
    """Clear the published engine. Observers will show "Not running"."""
    global _active
    _active = None


__all__ = ["clear_active_engine", "get_active_engine", "set_active_engine"]
