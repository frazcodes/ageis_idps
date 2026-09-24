"""A tiny registry for the process-wide risk engine.

No integrated risk runtime exists yet (that is a later architectural step). This
registry lets an embedder publish the engine it is running so that read-only
observers - such as the desktop Risk page - can locate it without creating a
second engine or starting anything.

Publishing or reading an engine has no side effects: it never starts monitoring,
capture, evaluation loops, scoring by itself, ML, correlation or response.
"""

from __future__ import annotations

from aegis_shared.risk.engine import RiskEngine

_active: RiskEngine | None = None


def set_active_risk_engine(engine: RiskEngine | None) -> None:
    """Publish (or clear) the process-wide risk engine for observers."""
    global _active
    _active = engine


def get_active_risk_engine() -> RiskEngine | None:
    """Return the published engine, or ``None`` when no runtime is running."""
    return _active


def clear_active_risk_engine() -> None:
    """Clear the published engine. Observers will show "Not running"."""
    global _active
    _active = None


__all__ = ["clear_active_risk_engine", "get_active_risk_engine", "set_active_risk_engine"]
