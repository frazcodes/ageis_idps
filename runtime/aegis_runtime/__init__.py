"""The minimal in-process Aegis runtime.

An orchestrator that owns lifecycle and connects the existing components::

    enabled host monitors ─┐
                           ├─► RuntimeEventPipeline ─► DetectionEngine ─► RiskEngine
    network sensor ────────┘            │
                                        └─► peek() (desktop observes read-only)

It adds no security logic of its own - no rules, no risk formulas, no collectors,
no event schema, no network normalization and no response policy. It is off by
default and single-threaded.
"""

from __future__ import annotations

from aegis_runtime.models import NetworkSensorLike, PollResult, RuntimeState
from aegis_runtime.pipeline import RuntimeEventPipeline
from aegis_runtime.runtime import AegisRuntime

__all__ = [
    "AegisRuntime",
    "NetworkSensorLike",
    "PollResult",
    "RuntimeEventPipeline",
    "RuntimeState",
]
