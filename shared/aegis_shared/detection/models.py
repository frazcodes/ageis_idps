"""The detection finding model.

A finding explains *why* a rule matched one event. It is deliberately small: it
does not duplicate the whole :class:`~aegis_shared.events.SecurityEvent`, only the
fields needed for explanation and traceability. ``event_id`` links back to the
original telemetry.

Findings are data only - they never trigger a response.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aegis_shared.enums import EventCategory, EventType, Severity


def _ensure_aware_utc(value: datetime | None, field_name: str) -> datetime | None:
    """Reject naive timestamps and normalise aware ones to UTC."""
    if value is None:
        return None
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{field_name} must be timezone-aware UTC")
    return value.astimezone(UTC)


class DetectionFinding(BaseModel):
    """A deterministic finding produced by a rule for one event."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    #: Deterministic identity: ``"<rule_id>:<event_id>"``.
    finding_id: str = Field(min_length=1, max_length=160)
    rule_id: str = Field(min_length=1, max_length=64)
    rule_name: str = Field(min_length=1, max_length=128)
    severity: Severity
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=1024)

    # --- Traceability back to the source telemetry -----------------------
    event_id: str = Field(min_length=1, max_length=64)
    event_type: EventType
    category: EventCategory
    timestamp: datetime
    host_id: str | None = Field(default=None, max_length=128)

    #: Observed facts that justify the match; values are strings for stable JSON.
    evidence: dict[str, str] = Field(default_factory=dict)
    tags: tuple[str, ...] = ()

    @field_validator("timestamp")
    @classmethod
    def _timestamp_is_aware(cls, value: datetime | None, info: Any) -> datetime | None:
        return _ensure_aware_utc(value, info.field_name)

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible mapping."""
        return self.model_dump(mode="json")


__all__ = ["DetectionFinding"]
