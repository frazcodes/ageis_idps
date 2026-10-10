"""Incidents adapter: correlated security incidents -> UI-friendly data.

Strictly read-only. It reads the current incidents published by the running
runtime through the process-wide incident registry and enriches them, for the
detail view only, with the related findings/events already buffered in the
existing event pipeline and any published ML anomaly signals. Incidents are the
single source of truth: none are fabricated in the GUI.

The one demo-mode addition: incidents (and their related findings) injected by
the threat-simulation playbooks are overlaid on the published registry so a
presentation stays populated after *Stop Monitoring* clears the runtime state.
They are read from the demo module, never generated here.

It never starts a producer, never runs a correlation/detection/scoring loop,
never drains shared state and never performs a response.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

from aegis_desktop.services.correlation import CorrelationEvidence, collect_correlations
from aegis_desktop.services.processes import MISSING
from aegis_desktop.services.threat_intel import IOCMatchView, threat_intel_for_events
from aegis_shared.logging import get_logger

if TYPE_CHECKING:  # pragma: no cover - typing only
    from aegis_shared.correlation import SecurityIncident
    from aegis_shared.detection import DetectionFinding
    from aegis_shared.events import SecurityEvent
    from aegis_shared.risk import AnomalySignal

logger = get_logger(__name__)

#: Non-sensitive message shown when incidents cannot be read.
INCIDENT_ERROR = "Unable to read security incidents"
#: Shown when the runtime is not producing incidents.
INCIDENT_RUNTIME_NOT_RUNNING = "Incident Correlation: Not running"


@dataclass(frozen=True)
class IncidentRow:
    """One incident, flattened for display and sorting."""

    incident_id: str
    created_at: datetime
    updated_at: datetime
    host_id: str
    status: str
    risk_score: int
    risk_level: str
    finding_count: int
    finding_ids: tuple[str, ...]
    event_ids: tuple[str, ...]
    risk_assessment_ids: tuple[str, ...]
    summary: str
    correlation_reason: str


@dataclass(frozen=True)
class IncidentPosture:
    """Read-only view of incident correlation state."""

    running: bool
    incidents: int


@dataclass(frozen=True)
class IncidentFindingView:
    """One related finding shown in the incident detail view."""

    finding_id: str
    rule_id: str
    severity: str
    title: str
    evidence: dict[str, str] | tuple[tuple[str, str], ...] = ()
    timestamp: datetime | None = None
    host_id: str | None = None


@dataclass(frozen=True)
class IncidentEventView:
    """One related event shown in the incident detail view."""

    event_id: str
    event_type: str
    category: str
    timestamp: datetime | None = None


@dataclass(frozen=True)
class IncidentAnomalyView:
    """Read-only view of an ML anomaly signal related to an incident."""

    source: str
    score: float
    model_version: str
    reason: str | None


@dataclass(frozen=True)
class IncidentSnapshotView:
    """Read-only view of current incidents plus correlation posture."""

    available: bool
    error: str | None
    collected_at: datetime | None
    posture: IncidentPosture
    rows: tuple[IncidentRow, ...]
    incidents: tuple[SecurityIncident, ...] = ()
    findings: tuple[IncidentFindingView, ...] = ()
    events: tuple[IncidentEventView, ...] = ()
    anomalies: tuple[IncidentAnomalyView, ...] = ()
    correlations: tuple[CorrelationEvidence, ...] = ()
    ioc_matches: tuple[IOCMatchView, ...] = ()

    @property
    def count(self) -> int:
        """Number of incidents in the view."""
        return len(self.rows)

    def incident_by_id(self, incident_id: str) -> SecurityIncident | None:
        """Return the incident with ``incident_id``, if present."""
        for incident in self.incidents:
            if incident.incident_id == incident_id:
                return incident
        return None


def _simulated_incidents() -> tuple[SecurityIncident, ...]:
    """Demo incidents injected by the threat-simulation playbooks (guarded)."""
    try:
        from aegis_desktop.threat_sim import simulated_incidents

        return simulated_incidents()
    except Exception as exc:  # pragma: no cover - only without the demo module
        logger.debug("Simulated incident overlay unavailable: %s", exc)
        return ()


def _simulated_findings() -> tuple[DetectionFinding, ...]:
    """Demo findings injected by the threat-simulation playbooks (guarded)."""
    try:
        from aegis_desktop.threat_sim import simulated_findings

        return simulated_findings()
    except Exception as exc:  # pragma: no cover - only without the demo module
        logger.debug("Simulated finding overlay unavailable: %s", exc)
        return ()


def _default_incidents() -> tuple[SecurityIncident, ...]:
    """Return published incidents plus the demo overlay (read-only)."""
    from aegis_shared.correlation import get_active_incidents

    published = get_active_incidents()
    demo = _simulated_incidents()
    if not demo:
        return published
    seen = {incident.incident_id for incident in published}
    extra = tuple(incident for incident in demo if incident.incident_id not in seen)
    return (*published, *extra) if extra else published


def _default_events() -> list[SecurityEvent]:
    """Return the events currently buffered in the existing pipeline."""
    from aegis_shared.pipeline import get_active_pipeline

    pipeline = get_active_pipeline()
    if pipeline is None:
        return []
    return [envelope.event for envelope in pipeline.peek()]


def _default_findings_by_id() -> dict[str, DetectionFinding]:
    """Evaluate the active detection engine over buffered events (read-only).

    Demo findings are merged in so a simulated incident still shows its related
    evidence in the detail view after the runtime has been stopped.
    """
    from aegis_shared.detection import get_active_engine

    engine = get_active_engine()
    findings: dict[str, DetectionFinding] = {}
    if engine is not None:
        for finding in engine.evaluate_many(_default_events()):
            findings[finding.finding_id] = finding
    for finding in _simulated_findings():
        findings.setdefault(finding.finding_id, finding)
    return findings


def _default_anomalies() -> dict[str, AnomalySignal]:
    """Return the latest published ML anomaly signals (read-only)."""
    from aegis_shared.risk import get_active_anomaly_signals

    return get_active_anomaly_signals()


def _to_row(incident: SecurityIncident) -> IncidentRow:
    return IncidentRow(
        incident_id=incident.incident_id,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        host_id=incident.host_id,
        status=incident.status.value,
        risk_score=incident.risk_score,
        risk_level=incident.risk_level.value,
        finding_count=len(incident.finding_ids),
        finding_ids=tuple(incident.finding_ids),
        event_ids=tuple(incident.event_ids),
        risk_assessment_ids=tuple(incident.risk_assessment_ids),
        summary=incident.summary,
        correlation_reason=incident.correlation_reason,
    )


def collect_incident_view(
    *,
    incidents_provider: Callable[[], tuple[SecurityIncident, ...]] | None = None,
    events_provider: Callable[[], Iterable[SecurityEvent]] | None = None,
    findings_provider: Callable[[], dict[str, DetectionFinding]] | None = None,
    anomalies_provider: Callable[[], dict[str, AnomalySignal]] | None = None,
    correlations_provider: Callable[[], Any] | None = None,
    ioc_matcher_provider: Callable[[], Any] | None = None,
) -> IncidentSnapshotView:
    """Read the current incidents, enriched with their related evidence.

    All sources are read-only and guarded. With no incidents published, an
    honest empty view is returned - never synthetic incidents.
    """
    try:
        incidents = tuple((incidents_provider or _default_incidents)())
    except Exception as exc:
        logger.warning("Reading incidents failed: %s", exc)
        return IncidentSnapshotView(
            available=False,
            error=INCIDENT_ERROR,
            collected_at=None,
            posture=IncidentPosture(running=False, incidents=0),
            rows=(),
        )

    running = incidents_provider is not None or _runtime_present()
    rows = tuple(_to_row(incident) for incident in incidents)
    collected_at = rows[-1].updated_at if rows else None

    # Enrich with related evidence for the detail view (best-effort).
    related_finding_ids = {fid for incident in incidents for fid in incident.finding_ids}
    related_event_ids = {eid for incident in incidents for eid in incident.event_ids}

    findings: tuple[IncidentFindingView, ...] = ()
    events: tuple[IncidentEventView, ...] = ()
    anomalies: tuple[IncidentAnomalyView, ...] = ()
    try:
        finding_map = (findings_provider or _default_findings_by_id)()
        findings = tuple(
            IncidentFindingView(
                finding_id=f.finding_id,
                rule_id=f.rule_id,
                severity=f.severity.value,
                title=f.title,
                evidence=dict(f.evidence),
                timestamp=f.timestamp,
                host_id=f.host_id,
            )
            for fid, f in sorted(finding_map.items())
            if fid in related_finding_ids
        )
    except Exception as exc:
        logger.warning("Reading related findings failed: %s", exc)

    try:
        all_events = list((events_provider or _default_events)())
        events = tuple(
            IncidentEventView(
                event_id=e.event_id,
                event_type=e.event_type.value,
                category=e.category.value,
                timestamp=getattr(e, "timestamp", None),
            )
            for e in all_events
            if e.event_id in related_event_ids
        )
    except Exception as exc:
        logger.warning("Reading related events failed: %s", exc)
        all_events = []

    try:
        anomaly_map = (anomalies_provider or _default_anomalies)()
        anomalies = tuple(
            IncidentAnomalyView(
                source=signal.source,
                score=signal.score,
                model_version=signal.model_version,
                reason=signal.reason,
            )
            for event_id, signal in sorted(anomaly_map.items())
            if event_id in related_event_ids
        )
    except Exception as exc:
        logger.warning("Reading related anomaly signals failed: %s", exc)

    try:
        correlations = collect_correlations(provider=correlations_provider)
    except Exception as exc:
        logger.warning("Reading host/network correlations failed: %s", exc)
        correlations = ()

    ioc_matches: tuple[IOCMatchView, ...] = ()
    try:
        related_events = [e for e in all_events if e.event_id in related_event_ids]
        ioc_matches = threat_intel_for_events(
            related_events, matcher_provider=ioc_matcher_provider
        )
    except Exception as exc:
        logger.warning("Reading IOC matches failed: %s", exc)

    return IncidentSnapshotView(
        available=True,
        error=None,
        collected_at=collected_at,
        posture=IncidentPosture(running=running, incidents=len(rows)),
        rows=rows,
        incidents=incidents,
        findings=findings,
        events=events,
        anomalies=anomalies,
        correlations=correlations,
        ioc_matches=ioc_matches,
    )


def _runtime_present() -> bool:
    """Whether a runtime-owned source appears to be publishing state."""
    from aegis_shared.pipeline import get_active_pipeline

    return get_active_pipeline() is not None


def describe_incident(incident: SecurityIncident) -> dict[str, str]:
    """Return a structured, safe, read-only view of one incident."""
    details: dict[str, str] = {
        "incident_id": incident.incident_id,
        "status": incident.status.value,
        "host_id": incident.host_id,
        "created_at": incident.created_at.isoformat(),
        "updated_at": incident.updated_at.isoformat(),
        "risk_score": str(incident.risk_score),
        "risk_level": incident.risk_level.value,
        "summary": incident.summary,
        "correlation_reason": incident.correlation_reason,
        "finding_count": str(len(incident.finding_ids)),
    }
    if incident.finding_ids:
        details["finding_ids"] = ", ".join(incident.finding_ids) or MISSING
    if incident.event_ids:
        details["event_ids"] = ", ".join(incident.event_ids) or MISSING
    if incident.risk_assessment_ids:
        details["risk_assessment_ids"] = ", ".join(incident.risk_assessment_ids) or MISSING
    return details


__all__ = [
    "INCIDENT_ERROR",
    "INCIDENT_RUNTIME_NOT_RUNNING",
    "IncidentAnomalyView",
    "IncidentEventView",
    "IncidentFindingView",
    "IncidentPosture",
    "IncidentRow",
    "IncidentSnapshotView",
    "collect_incident_view",
    "describe_incident",
]
