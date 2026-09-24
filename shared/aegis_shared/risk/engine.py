"""The deterministic, explainable risk engine.

The engine consumes canonical events and their
:class:`~aegis_shared.detection.models.DetectionFinding` objects. It does not
know or care how findings were produced, performs no I/O, no ML and no response,
and holds no state: the same event, findings and configuration always yield the
same assessment.

For a future ML integration point, an :class:`~aegis_shared.risk.models.AnomalySignal`
may be supplied. It is recorded on the assessment but does **not** affect the
score today.
"""

from __future__ import annotations

from collections.abc import Iterable

from aegis_shared.detection.models import DetectionFinding
from aegis_shared.enums import Severity
from aegis_shared.events import SecurityEvent
from aegis_shared.risk.config import RiskSettings
from aegis_shared.risk.models import AnomalySignal, RiskAssessment, RiskContributor
from aegis_shared.risk.scoring import (
    combine_contributions,
    risk_level_for_score,
    severity_contribution,
)

#: A batch item: one event with the findings produced for it.
AssessmentItem = tuple[SecurityEvent, Iterable[DetectionFinding]]


class RiskEngine:
    """Produce deterministic, explainable risk assessments."""

    def __init__(self, settings: RiskSettings | None = None) -> None:
        self._settings = settings or RiskSettings()

    @property
    def settings(self) -> RiskSettings:
        """The settings this engine scores with."""
        return self._settings

    def assess(
        self,
        event: SecurityEvent,
        findings: Iterable[DetectionFinding],
        *,
        anomaly_signal: AnomalySignal | None = None,
    ) -> RiskAssessment:
        """Assess one event and its findings.

        Raises:
            ValueError: if a finding does not belong to ``event`` or if two
                findings share an ID (never silently double-counted).
        """
        finding_list = list(findings)
        self._validate(event, finding_list)

        # Deterministic contributor order regardless of input order.
        ordered = sorted(finding_list, key=lambda finding: finding.finding_id)
        contributors = tuple(self._contributor(finding) for finding in ordered)
        score = combine_contributions(contributor.contribution for contributor in contributors)

        return RiskAssessment(
            assessment_id=f"{self._settings.scoring_version}:{event.event_id}",
            event_id=event.event_id,
            host_id=event.host.host_id if event.host is not None else None,
            risk_score=score,
            risk_level=risk_level_for_score(
                score,
                low=self._settings.threshold_low,
                medium=self._settings.threshold_medium,
                high=self._settings.threshold_high,
                critical=self._settings.threshold_critical,
            ),
            severity=self._overall_severity(ordered),
            reasons=tuple(contributor.reason for contributor in contributors),
            finding_ids=tuple(contributor.finding_id for contributor in contributors),
            contributors=contributors,
            scoring_version=self._settings.scoring_version,
            timestamp=event.timestamp,
            anomaly=anomaly_signal,
        )

    def assess_many(
        self,
        items: Iterable[AssessmentItem],
        *,
        anomaly_signals: dict[str, AnomalySignal] | None = None,
    ) -> tuple[RiskAssessment, ...]:
        """Assess many ``(event, findings)`` items, preserving input order.

        No cross-event correlation is performed and results are never reordered by
        score.  When *anomaly_signals* is supplied, the signal matching each
        event's ``event_id`` is passed to :meth:`assess`; missing keys are treated
        as ``None``.
        """
        signals = anomaly_signals or {}
        return tuple(
            self.assess(event, findings, anomaly_signal=signals.get(event.event_id))
            for event, findings in items
        )

    def _contributor(self, finding: DetectionFinding) -> RiskContributor:
        contribution = severity_contribution(
            finding.severity,
            weights=self._settings.severity_weights,
            max_contribution=self._settings.max_contribution_per_finding,
        )
        reason = (
            f"{finding.rule_id} ({finding.severity.value}) contributed "
            f"{contribution}: {finding.title}"
        )
        return RiskContributor(
            finding_id=finding.finding_id,
            rule_id=finding.rule_id,
            severity=finding.severity,
            contribution=contribution,
            reason=reason,
        )

    @staticmethod
    def _overall_severity(findings: list[DetectionFinding]) -> Severity:
        return max(
            (finding.severity for finding in findings),
            key=lambda severity: severity.rank,
            default=Severity.INFO,
        )

    @staticmethod
    def _validate(event: SecurityEvent, findings: list[DetectionFinding]) -> None:
        seen: set[str] = set()
        for finding in findings:
            if finding.event_id != event.event_id:
                raise ValueError(
                    f"finding {finding.finding_id!r} does not belong to event {event.event_id!r}"
                )
            if finding.finding_id in seen:
                raise ValueError(f"duplicate finding id: {finding.finding_id!r}")
            seen.add(finding.finding_id)


__all__ = ["AssessmentItem", "RiskEngine"]
