"""Transport models for the shared event pipeline.

The pipeline does **not** define an event schema. It wraps the canonical
:class:`aegis_shared.events.SecurityEvent` in a minimal transport envelope and
reports operational counters. The envelope adds only what the canonical event
does not carry and what an exporter will need: a monotonic per-pipeline sequence
number and the time the event entered the pipeline.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aegis_shared.events import SecurityEvent


def _ensure_aware_utc(value: datetime | None, field_name: str) -> datetime | None:
    """Reject naive timestamps and normalise aware ones to UTC."""
    if value is None:
        return None
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{field_name} must be timezone-aware UTC")
    return value.astimezone(UTC)


class EventEnvelope(BaseModel):
    """A canonical event plus the pipeline's transport metadata."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    #: Monotonic sequence assigned by the pipeline, starting at 0.
    sequence: int = Field(ge=0)
    enqueued_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    event: SecurityEvent

    @field_validator("enqueued_at")
    @classmethod
    def _enqueued_at_is_aware(cls, value: datetime | None, info: Any) -> datetime | None:
        return _ensure_aware_utc(value, info.field_name)

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible mapping of the envelope and nested event."""
        return self.model_dump(mode="json")


class SubmitResult(BaseModel):
    """Outcome of submitting a single event to a pipeline."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    accepted: bool
    #: Why the event was rejected (``None`` when accepted).
    reason: str | None = None
    #: Assigned sequence number when accepted.
    sequence: int | None = None


class PipelineStats(BaseModel):
    """Cumulative pipeline counters plus a live buffer size."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    accepted: int = Field(ge=0)
    rejected: int = Field(ge=0)
    dropped: int = Field(ge=0)
    #: Subset of ``rejected`` caused by a repeated ``event_id``.
    duplicates: int = Field(ge=0)
    buffered: int = Field(ge=0)
    capacity: int = Field(ge=0)
    next_sequence: int = Field(ge=0)

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible mapping."""
        return self.model_dump(mode="json")


__all__ = ["EventEnvelope", "PipelineStats", "SubmitResult"]
