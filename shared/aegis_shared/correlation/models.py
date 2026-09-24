"""The security incident model.

A :class:`SecurityIncident` is the deterministic grouping of *related* security
activity - multiple findings/events observed on the same host within a bounded
time window - into one reviewable unit. It is a **correlation** result, not a
verdict: it never asserts malware, an attacker, attribution or a technique.

It references the existing :class:`~aegis_shared.detection.models.DetectionFinding`,
:class:`~aegis_shared.events.SecurityEvent` and
:class:`~aegis_shared.risk.models.RiskAssessment` by ID only; those models are
never copied or re-derived here.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aegis_shared.enums import IncidentStatus, RiskLevel


def _ensure_aware_utc(value: datetime | None, field_name: str) -> datetime | None:
    """Reject naive timestamps and normalise aware ones to UTC."""
    if value is None:
        return None
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{field_name} must be timezone-aware UTC")
    return value.astimezone(UTC)


class SecurityIncident(BaseModel):
    """A deterministic correlation of related security activity on one host."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    #: Deterministic identity derived from the correlated finding IDs.
    incident_id: str = Field(min_length=1, max_length=64)
    host_id: str = Field(min_length=1, max_length=128)

    created_at: datetime
    updated_at: datetime

    #: Lifecycle status. Response state is intentionally not modelled yet.
    status: IncidentStatus = IncidentStatus.OPEN

    #: Related finding IDs, in deterministic order.
    finding_ids: tuple[str, ...] = ()
    #: Related event IDs (unique, deterministic order).
    event_ids: tuple[str, ...] = ()
    #: Related risk-assessment IDs, in deterministic order.
    risk_assessment_ids: tuple[str, ...] = ()

    #: Derived from the highest related assessment; never invented.
    risk_score: int = Field(default=0, ge=0, le=100)
    risk_level: RiskLevel = RiskLevel.INFORMATIONAL

    #: Neutral, evidence-based summary. Never an attribution.
    summary: str = Field(min_length=1, max_length=512)
    #: Why these items were grouped, in neutral terminology.
    correlation_reason: str = Field(min_length=1, max_length=512)

    @field_validator("created_at", "updated_at")
    @classmethod
    def _timestamps_are_aware(cls, value: datetime | None, info: Any) -> datetime | None:
        return _ensure_aware_utc(value, info.field_name)

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible mapping."""
        return self.model_dump(mode="json")


class HostNetworkCorrelation(BaseModel):
    """Related host-side and network-side findings on the same host.

    This records that host and network security findings were observed on the
    same host within a bounded time window. It is **evidence of temporal and
    host proximity only** - it never asserts that a process caused network
    activity, that the host is compromised, or any attack attribution. It
    references existing findings/events by ID and introduces no new score.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    #: Deterministic identity derived from the host and the related finding IDs.
    correlation_id: str = Field(min_length=1, max_length=64)
    host_id: str = Field(min_length=1, max_length=128)
    created_at: datetime

    #: Related host-side finding IDs, in deterministic order.
    host_finding_ids: tuple[str, ...] = ()
    #: Related network-side finding IDs, in deterministic order.
    network_finding_ids: tuple[str, ...] = ()
    #: Related event IDs (unique, deterministic order).
    event_ids: tuple[str, ...] = ()

    #: The configured correlation window applied (seconds).
    window_seconds: int = Field(ge=1)

    #: Neutral, evidence-based summary. Never an attribution.
    summary: str = Field(min_length=1, max_length=512)
    #: Why the evidence was correlated, in neutral terminology.
    reason: str = Field(min_length=1, max_length=512)

    @field_validator("created_at")
    @classmethod
    def _created_at_is_aware(cls, value: datetime | None, info: Any) -> datetime | None:
        return _ensure_aware_utc(value, info.field_name)

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible mapping."""
        return self.model_dump(mode="json")


__all__ = ["HostNetworkCorrelation", "SecurityIncident"]
