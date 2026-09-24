"""The deterministic, explainable incident correlator.

The correlator groups *related* security activity into
:class:`~aegis_shared.correlation.models.SecurityIncident` objects. It is
stateless, passive and performs no I/O: the same findings/assessments and
configuration always produce identical incidents.

Correlation rules
-----------------
1. **Same host.** Only findings that share a non-empty ``host_id`` are grouped.
   Findings without a host ID are never correlated.
2. **Bounded time proximity.** Within a host, findings are ordered by time and
   clustered so each cluster spans at most ``window_seconds``.
3. **Multiple signals.** A cluster forms an incident only when it contains at
   least ``min_findings`` findings. A single isolated finding does not create an
   incident.

Risk and language
-----------------
* Incident risk is copied from the **highest existing** related risk assessment
  (``risk_score`` and ``risk_level``). No new weights are invented and nothing is
  summed beyond the existing 0-100 bound. With no related assessment the incident
  carries ``0`` / ``informational``.
* Reasons and summaries use neutral, evidence-based language ("related security
  findings", "correlated findings", "combined evidence"). The correlator never
  asserts malware, an attacker, attribution, a technique or a confirmed attack.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable

from aegis_shared.correlation.config import CorrelationSettings
from aegis_shared.correlation.models import SecurityIncident
from aegis_shared.detection.models import DetectionFinding
from aegis_shared.enums import EventCategory, IncidentStatus, RiskLevel
from aegis_shared.events import SecurityEvent
from aegis_shared.risk.models import RiskAssessment

#: Neutral category labels used in reasons (never attributions).
_CATEGORY_LABELS = {
    EventCategory.HOST: "host",
    EventCategory.NETWORK: "network",
}


class IncidentCorrelator:
    """Group related findings on the same host within a bounded time window."""

    def __init__(self, settings: CorrelationSettings | None = None) -> None:
        self._settings = settings or CorrelationSettings()

    @property
    def settings(self) -> CorrelationSettings:
        """The settings this correlator groups with."""
        return self._settings

    def correlate(
        self,
        events: Iterable[SecurityEvent],
        findings: Iterable[DetectionFinding],
        assessments: Iterable[RiskAssessment] = (),
    ) -> tuple[SecurityIncident, ...]:
        """Return incidents for related findings, in deterministic order.

        Findings are grouped by ``host_id`` then clustered by the correlation
        window. Clusters with fewer than ``min_findings`` findings are ignored.
        """
        event_by_id = {event.event_id: event for event in events}
        assessment_by_event = {a.event_id: a for a in assessments}

        incidents: list[SecurityIncident] = []
        for host_id in sorted(self._hosts_with_findings(findings)):
            host_findings = self._findings_for_host(findings, host_id)
            for cluster in self._cluster(host_findings):
                if len(cluster) < self._settings.min_findings:
                    continue
                incidents.append(
                    self._build_incident(host_id, cluster, event_by_id, assessment_by_event)
                )
        return tuple(incidents)

    # ------------------------------------------------------------------
    # Grouping helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _hosts_with_findings(findings: Iterable[DetectionFinding]) -> set[str]:
        return {
            finding.host_id
            for finding in findings
            if finding.host_id is not None and finding.host_id != ""
        }

    @staticmethod
    def _findings_for_host(
        findings: Iterable[DetectionFinding], host_id: str
    ) -> list[DetectionFinding]:
        # Deterministic order: time, then finding_id as a stable tie-breaker.
        return sorted(
            (f for f in findings if f.host_id == host_id),
            key=lambda f: (f.timestamp, f.finding_id),
        )

    def _cluster(self, findings: list[DetectionFinding]) -> list[list[DetectionFinding]]:
        """Split ordered findings into clusters spanning at most the window."""
        clusters: list[list[DetectionFinding]] = []
        current: list[DetectionFinding] = []
        for finding in findings:
            if not current:
                current = [finding]
                continue
            span = (finding.timestamp - current[0].timestamp).total_seconds()
            if span <= self._settings.window_seconds:
                current.append(finding)
            else:
                clusters.append(current)
                current = [finding]
        if current:
            clusters.append(current)
        return clusters

    # ------------------------------------------------------------------
    # Incident construction
    # ------------------------------------------------------------------

    def _build_incident(
        self,
        host_id: str,
        cluster: list[DetectionFinding],
        event_by_id: dict[str, SecurityEvent],
        assessment_by_event: dict[str, RiskAssessment],
    ) -> SecurityIncident:
        finding_ids = tuple(sorted(f.finding_id for f in cluster))
        event_ids = tuple(sorted({f.event_id for f in cluster}))

        related_assessments = tuple(
            assessment_by_event[event_id]
            for event_id in event_ids
            if event_id in assessment_by_event
        )
        risk_assessment_ids = tuple(
            sorted(a.assessment_id for a in related_assessments)
        )

        risk_score, risk_level = self._incident_risk(related_assessments)

        created_at = min(f.timestamp for f in cluster)
        updated_at = max(f.timestamp for f in cluster)

        return SecurityIncident(
            incident_id=self._incident_id(host_id, finding_ids),
            host_id=host_id,
            created_at=created_at,
            updated_at=updated_at,
            status=IncidentStatus.OPEN,
            finding_ids=finding_ids,
            event_ids=event_ids,
            risk_assessment_ids=risk_assessment_ids,
            risk_score=risk_score,
            risk_level=risk_level,
            summary=self._summary(host_id, cluster),
            correlation_reason=self._reason(cluster),
        )

    @staticmethod
    def _incident_risk(
        assessments: tuple[RiskAssessment, ...],
    ) -> tuple[int, RiskLevel]:
        """Highest existing related risk, or a neutral default.

        Reuses the existing assessments verbatim - no new weights, no summing
        beyond the existing 0-100 bound.
        """
        if not assessments:
            return 0, RiskLevel.INFORMATIONAL
        highest = max(assessments, key=lambda a: a.risk_score)
        return highest.risk_score, highest.risk_level

    @staticmethod
    def _incident_id(host_id: str, finding_ids: tuple[str, ...]) -> str:
        payload = f"{host_id}|{'|'.join(finding_ids)}".encode()
        digest = hashlib.sha1(payload, usedforsecurity=False).hexdigest()
        return f"INC-{digest[:16]}"

    @staticmethod
    def _summary(host_id: str, cluster: list[DetectionFinding]) -> str:
        return (
            f"{len(cluster)} related security findings were correlated on "
            f"host {host_id}."
        )

    def _reason(self, cluster: list[DetectionFinding]) -> str:
        categories = sorted({f.category for f in cluster}, key=lambda c: c.value)
        labels = [_CATEGORY_LABELS.get(c, c.value) for c in categories]
        window = self._settings.window_seconds
        if len(labels) == 1:
            scope = f"{labels[0]} findings"
        else:
            scope = f"{', '.join(labels[:-1])} and {labels[-1]} findings"
        return (
            f"Related {scope} were observed on the same host within the "
            f"configured correlation window ({window}s)."
        )


__all__ = ["IncidentCorrelator"]
