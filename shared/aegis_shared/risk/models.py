"""Typed models for the explainable risk-assessment layer.

:class:`RiskAssessment` is a standalone assessment of one event. It is distinct
from the 0-1 ``RiskAssessment`` context block embedded in a
:class:`aegis_shared.events.SecurityEvent`: this model is the deterministic,
explainable output of the risk engine and carries its own contributors and
scoring version.

Findings are referenced by ID and summarised in :class:`RiskContributor`; the
whole :class:`~aegis_shared.detection.models.DetectionFinding` is never copied.

A risk assessment is **not** proof of compromise and never triggers a response.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aegis_shared.enums import RiskLevel, Severity


def _ensure_aware_utc(value: datetime | None, field_name: str) -> datetime | None:
    """Reject naive timestamps and normalise aware ones to UTC."""
    if value is None:
        return None
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{field_name} must be timezone-aware UTC")
    return value.astimezone(UTC)


class AnomalySignal(BaseModel):
    """A future ML/anomaly input - a typed extension point, not an implementation.

    No ML library is required to construct or carry this. Today the engine records
    a supplied signal but does not add it to the score.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    source: str = Field(min_length=1, max_length=128)
    score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    model_version: str = Field(min_length=1, max_length=64)
    reason: str | None = Field(default=None, max_length=512)

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible mapping."""
        return self.model_dump(mode="json")


class RiskContributor(BaseModel):
    """One finding's contribution to an assessment."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str = Field(min_length=1, max_length=160)
    rule_id: str = Field(min_length=1, max_length=64)
    severity: Severity
    contribution: int = Field(ge=0, le=100)
    reason: str = Field(min_length=1, max_length=512)

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible mapping."""
        return self.model_dump(mode="json")


class RiskAssessment(BaseModel):
    """A deterministic, explainable risk assessment of one event."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    #: Deterministic identity: ``"<scoring_version>:<event_id>"``.
    assessment_id: str = Field(min_length=1, max_length=160)
    event_id: str = Field(min_length=1, max_length=64)
    host_id: str | None = Field(default=None, max_length=128)

    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    #: Highest contributing finding severity, or ``info`` when there are none.
    severity: Severity

    #: Human-readable explanation, one entry per contributor.
    reasons: tuple[str, ...] = ()
    #: All contributing finding IDs, in the same deterministic order as contributors.
    finding_ids: tuple[str, ...] = ()
    contributors: tuple[RiskContributor, ...] = ()

    scoring_version: str = Field(min_length=1, max_length=32)
    timestamp: datetime
    #: Future ML input, carried through unmodified (``None`` today).
    anomaly: AnomalySignal | None = None

    @field_validator("timestamp")
    @classmethod
    def _timestamp_is_aware(cls, value: datetime | None, info: Any) -> datetime | None:
        return _ensure_aware_utc(value, info.field_name)

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible mapping."""
        return self.model_dump(mode="json")


__all__ = ["AnomalySignal", "RiskAssessment", "RiskContributor"]
