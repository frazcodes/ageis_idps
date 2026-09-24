"""Pure, deterministic scoring functions.

The algorithm (version ``1``):

1. Each finding contributes ``min(weight[severity], max_contribution_per_finding)``.
2. Contributions are summed and the total is clamped to ``0-100``.
3. The level is the highest threshold the score reaches.

The formula is additive **and bounded**: a per-finding cap plus a hard total cap
of 100 mean many findings cannot produce unbounded or negative risk. It is
stateless, side-effect-free and produces identical output for identical input.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from aegis_shared.enums import RiskLevel, Severity

#: Hard upper bound of any risk score.
MAX_RISK_SCORE = 100


def severity_contribution(
    severity: Severity,
    *,
    weights: Mapping[Severity, int],
    max_contribution: int,
) -> int:
    """Return the bounded contribution of a finding's severity."""
    weight = int(weights.get(severity, 0))
    if weight < 0:
        weight = 0
    return min(weight, max(0, max_contribution))


def combine_contributions(contributions: Iterable[int]) -> int:
    """Sum contributions, clamping to ``0-100``."""
    total = sum(max(0, int(value)) for value in contributions)
    return max(0, min(MAX_RISK_SCORE, total))


def risk_level_for_score(
    score: int,
    *,
    low: int,
    medium: int,
    high: int,
    critical: int,
) -> RiskLevel:
    """Map a 0-100 score onto a :class:`RiskLevel` using explicit thresholds."""
    if score >= critical:
        return RiskLevel.CRITICAL
    if score >= high:
        return RiskLevel.HIGH
    if score >= medium:
        return RiskLevel.MEDIUM
    if score >= low:
        return RiskLevel.LOW
    return RiskLevel.INFORMATIONAL


__all__ = [
    "MAX_RISK_SCORE",
    "combine_contributions",
    "risk_level_for_score",
    "severity_contribution",
]
