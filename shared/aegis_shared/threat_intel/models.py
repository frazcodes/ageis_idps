"""Immutable threat-intelligence indicator and match models.

A :class:`ThreatIndicator` is a locally configured observable value (IP, domain
or file hash) with provenance, confidence and severity. An :class:`IOCMatch`
records that an observable already present in Aegis telemetry matched one
enabled indicator.

An IOC match is **context for investigation**, never proof of malicious
activity, attacker attribution or compromise. No payload or sensitive data is
stored - only the matched observable value and the indicator's metadata.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aegis_shared.enums import EventCategory, EventType, IndicatorType, Severity


def _ensure_aware_utc(value: datetime | None, field_name: str) -> datetime | None:
    """Reject naive timestamps and normalise aware ones to UTC."""
    if value is None:
        return None
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{field_name} must be timezone-aware UTC")
    return value.astimezone(UTC)


class ThreatIndicator(BaseModel):
    """One locally configured threat-intelligence indicator."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    #: Deterministic identity derived from the type and normalized value.
    indicator_id: str = Field(min_length=1, max_length=64)
    indicator_type: IndicatorType
    #: The normalized observable value (lowercased domain/hash, canonical IP).
    value: str = Field(min_length=1, max_length=512)
    #: Where the indicator came from (e.g. a configured local feed label).
    source: str = Field(min_length=1, max_length=128)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    severity: Severity = Severity.MEDIUM
    description: str | None = Field(default=None, max_length=512)
    enabled: bool = True
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    @field_validator("first_seen", "last_seen")
    @classmethod
    def _timestamps_are_aware(cls, value: datetime | None, info: Any) -> datetime | None:
        return _ensure_aware_utc(value, info.field_name)

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible mapping."""
        return self.model_dump(mode="json")


class IOCMatch(BaseModel):
    """One observable that matched an enabled indicator (context only)."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    #: Deterministic identity derived from indicator, observed value and event.
    match_id: str = Field(min_length=1, max_length=64)
    indicator_id: str = Field(min_length=1, max_length=64)
    indicator_type: IndicatorType
    #: The observed value from telemetry that matched the indicator.
    observed_value: str = Field(min_length=1, max_length=512)
    source: str = Field(min_length=1, max_length=128)
    confidence: float = Field(ge=0.0, le=1.0)
    severity: Severity
    matched_at: datetime
    event_id: str = Field(min_length=1, max_length=64)
    #: Telemetry metadata for traceability (never attribution).
    event_type: EventType
    category: EventCategory
    host_id: str | None = Field(default=None, max_length=128)
    description: str | None = Field(default=None, max_length=512)

    @field_validator("matched_at")
    @classmethod
    def _matched_at_is_aware(cls, value: datetime | None, info: Any) -> datetime | None:
        return _ensure_aware_utc(value, info.field_name)

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible mapping."""
        return self.model_dump(mode="json")


__all__ = ["IOCMatch", "ThreatIndicator"]
