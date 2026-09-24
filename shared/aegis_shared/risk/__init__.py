"""Explainable, deterministic risk scoring.

Combines detection findings (today) and a future anomaly signal (extension point)
into a bounded 0-100 :class:`~aegis_shared.risk.models.RiskAssessment` with
per-finding contributors.

This layer is separate from detection because *how risky an observation is* is a
policy decision distinct from *whether a rule matched*. It is deterministic,
stateless and passive - no ML, no correlation, no response.

**Detection finding != risk assessment != confirmed compromise.**
"""

from __future__ import annotations

from aegis_shared.risk.anomaly_runtime import (
    clear_active_anomaly_signals,
    get_active_anomaly_signals,
    set_active_anomaly_signals,
)
from aegis_shared.risk.config import RiskSettings, get_risk_settings
from aegis_shared.risk.engine import AssessmentItem, RiskEngine
from aegis_shared.risk.models import AnomalySignal, RiskAssessment, RiskContributor
from aegis_shared.risk.runtime import (
    clear_active_risk_engine,
    get_active_risk_engine,
    set_active_risk_engine,
)
from aegis_shared.risk.scoring import (
    MAX_RISK_SCORE,
    combine_contributions,
    risk_level_for_score,
    severity_contribution,
)

__all__ = [
    "MAX_RISK_SCORE",
    "AnomalySignal",
    "AssessmentItem",
    "RiskAssessment",
    "RiskContributor",
    "RiskEngine",
    "RiskSettings",
    "clear_active_anomaly_signals",
    "clear_active_risk_engine",
    "combine_contributions",
    "get_active_anomaly_signals",
    "get_active_risk_engine",
    "get_risk_settings",
    "risk_level_for_score",
    "set_active_anomaly_signals",
    "set_active_risk_engine",
    "severity_contribution",
]
