"""Typed configuration for the deterministic risk-scoring engine.

Defaults are intentionally conservative and documented:

* severity weights rise with severity (info 0, low 10, medium 25, high 40,
  critical 60);
* thresholds map the 0-100 score onto :class:`~aegis_shared.enums.RiskLevel`
  (low 10, medium 25, high 40, critical 60);
* each finding's contribution is capped (default 100, i.e. the severity weight);
* the scoring version is a non-empty label stamped on every assessment.

Weights and thresholds are non-negative and bounded; negative risk is impossible.
Environment prefix: ``AEGIS_RISK_``.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Self

from pydantic import Field, model_validator
from pydantic_settings import SettingsConfigDict

from aegis_shared.config import AegisSettings
from aegis_shared.enums import Severity


class RiskSettings(AegisSettings):
    """Weights, thresholds and version for deterministic risk scoring."""

    model_config = SettingsConfigDict(
        env_prefix="AEGIS_RISK_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    scoring_version: str = Field(
        default="1",
        min_length=1,
        max_length=32,
        description="Label stamped on every assessment; bump when the algorithm changes.",
    )

    # --- Per-severity contribution weights (0-100) -----------------------
    weight_info: int = Field(default=0, ge=0, le=100)
    weight_low: int = Field(default=10, ge=0, le=100)
    weight_medium: int = Field(default=25, ge=0, le=100)
    weight_high: int = Field(default=40, ge=0, le=100)
    weight_critical: int = Field(default=60, ge=0, le=100)

    #: Upper bound on a single finding's contribution.
    max_contribution_per_finding: int = Field(default=100, ge=0, le=100)

    # --- Score thresholds (1-100, strictly increasing) -------------------
    threshold_low: int = Field(default=10, ge=1, le=100)
    threshold_medium: int = Field(default=25, ge=1, le=100)
    threshold_high: int = Field(default=40, ge=1, le=100)
    threshold_critical: int = Field(default=60, ge=1, le=100)

    @model_validator(mode="after")
    def _thresholds_are_ordered(self) -> Self:
        if not (
            self.threshold_low
            < self.threshold_medium
            < self.threshold_high
            < self.threshold_critical
        ):
            raise ValueError("risk thresholds must satisfy low < medium < high < critical")
        return self

    @property
    def severity_weights(self) -> dict[Severity, int]:
        """Deterministic mapping from finding severity to a numeric weight."""
        return {
            Severity.INFO: self.weight_info,
            Severity.LOW: self.weight_low,
            Severity.MEDIUM: self.weight_medium,
            Severity.HIGH: self.weight_high,
            Severity.CRITICAL: self.weight_critical,
        }


@lru_cache(maxsize=1)
def get_risk_settings() -> RiskSettings:
    """Return the process-wide risk settings (loaded once)."""
    return RiskSettings()


__all__ = ["RiskSettings", "get_risk_settings"]
