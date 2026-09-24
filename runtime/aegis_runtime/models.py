"""Result and state models for the minimal Aegis runtime.

These are small, immutable value objects owned by the orchestrator. They are not a
second event store: the runtime keeps only the most recent cycle's counters and
outcomes, and the canonical events live in the existing event pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


class RuntimeState(StrEnum):
    """Lifecycle state of the runtime."""

    STOPPED = "stopped"
    RUNNING = "running"


class NetworkSensorLike(Protocol):
    """Structural type for the optional network producer.

    The real :class:`aegis_network_sensor.sensor.NetworkSensor` satisfies this; a
    test double can too, so the runtime never has to import scapy unless capture
    is actually enabled.
    """

    def capture(self, *, count: int | None = ...) -> object:  # pragma: no cover - protocol
        ...


@dataclass(frozen=True)
class PollResult:
    """Outcome of one bounded runtime cycle."""

    host_events: int = 0
    network_events: int = 0
    #: Events accepted by the pipeline this cycle (host + network).
    submitted: int = 0
    findings: int = 0
    assessments: int = 0
    #: Names of producers that failed this cycle (never exception details).
    errors: tuple[str, ...] = ()

    @property
    def is_empty(self) -> bool:
        """Whether the cycle produced no events, findings or assessments."""
        return self.submitted == 0 and self.findings == 0 and self.assessments == 0


__all__ = ["NetworkSensorLike", "PollResult", "RuntimeState"]
