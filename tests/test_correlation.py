"""Focused tests for security event correlation and incident formation (Step 21).

Exercises the deterministic :class:`IncidentCorrelator`, the runtime incident
registry and the desktop Incidents service/page using locally constructed
findings, events and risk assessments. No real telemetry, privileges, threads or
persistence is used.
"""

from __future__ import annotations

import os
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest

from aegis_shared.correlation import (
    CorrelationSettings,
    IncidentCorrelator,
    clear_active_incidents,
    get_active_incidents,
)
from aegis_shared.detection import DetectionFinding
from aegis_shared.enums import (
    EventCategory,
    EventType,
    IncidentStatus,
    RiskLevel,
    Severity,
    SourceKind,
)
from aegis_shared.events import HostRef, SecurityEvent, SourceRef
from aegis_shared.risk import AnomalySignal, RiskAssessment, RiskEngine

_TS = datetime(2026, 6, 1, 10, 0, 0, tzinfo=UTC)


# --- Helpers ---------------------------------------------------------------


def _event(
    event_id: str,
    *,
    event_type: EventType = EventType.PROCESS_STARTED,
    host_id: str | None = "host-1",
    timestamp: datetime = _TS,
) -> SecurityEvent:
    return SecurityEvent.create(
        event_id=event_id,
        event_type=event_type,
        source=SourceRef(kind=SourceKind.AGENT, id="agent"),
        timestamp=timestamp,
        host=HostRef(host_id=host_id) if host_id else None,
    )


def _finding(
    event_id: str,
    *,
    host_id: str | None = "host-1",
    rule_id: str = "AEGIS-PROC-001",
    event_type: EventType = EventType.PROCESS_STARTED,
    timestamp: datetime = _TS,
) -> DetectionFinding:
    category = EventCategory(event_type.value.split(".", 1)[0])
    return DetectionFinding(
        finding_id=f"{rule_id}:{event_id}",
        rule_id=rule_id,
        rule_name=rule_id,
        severity=Severity.MEDIUM,
        title="Finding",
        description="A deterministic finding.",
        event_id=event_id,
        event_type=event_type,
        category=category,
        timestamp=timestamp,
        host_id=host_id,
    )


def _assess(event: SecurityEvent, findings: tuple[DetectionFinding, ...]) -> RiskAssessment:
    return RiskEngine().assess(event, findings)


@pytest.fixture(autouse=True)
def _clean_incidents() -> Generator[None, None, None]:
    clear_active_incidents()
    yield
    clear_active_incidents()


# --- 1. Single finding does not create an incident -------------------------


def test_single_finding_creates_no_incident() -> None:
    event = _event("e1")
    finding = _finding("e1")
    correlator = IncidentCorrelator()

    incidents = correlator.correlate([event], [finding], [_assess(event, (finding,))])

    assert incidents == ()


# --- 2. Two related findings on the same host create an incident -----------


def test_related_findings_create_incident() -> None:
    e1, e2 = _event("e1"), _event("e2", event_type=EventType.PORT_LISTENING)
    f1 = _finding("e1")
    f2 = _finding("e2", rule_id="AEGIS-LISTEN-001", event_type=EventType.PORT_LISTENING)
    correlator = IncidentCorrelator()

    incidents = correlator.correlate([e1, e2], [f1, f2], [_assess(e1, (f1,)), _assess(e2, (f2,))])

    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.host_id == "host-1"
    assert incident.status is IncidentStatus.OPEN


# --- 3. Findings outside the window remain separate ------------------------


def test_findings_outside_window_are_separate() -> None:
    early = _TS
    late = _TS + timedelta(seconds=3600)  # far beyond the 300s default window
    f1 = _finding("e1", timestamp=early)
    f2 = _finding("e2", timestamp=late)
    correlator = IncidentCorrelator()

    incidents = correlator.correlate([], [f1, f2])

    # Neither cluster meets the 2-finding minimum.
    assert incidents == ()


def test_cluster_forms_within_window() -> None:
    late = _TS + timedelta(seconds=100)  # within the 300s window
    f1 = _finding("e1", timestamp=_TS)
    f2 = _finding("e2", timestamp=late)
    correlator = IncidentCorrelator()

    incidents = correlator.correlate([], [f1, f2])

    assert len(incidents) == 1


# --- 4. Different hosts are not correlated ---------------------------------


def test_different_hosts_are_not_correlated() -> None:
    f1 = _finding("e1", host_id="host-1")
    f2 = _finding("e2", host_id="host-2")
    correlator = IncidentCorrelator()

    incidents = correlator.correlate([], [f1, f2])

    assert incidents == ()


# --- 5. Incident contains correct finding IDs ------------------------------


def test_incident_contains_finding_ids() -> None:
    f1 = _finding("e1")
    f2 = _finding("e2", rule_id="AEGIS-LISTEN-001", event_type=EventType.PORT_LISTENING)
    correlator = IncidentCorrelator()

    incident = correlator.correlate([], [f1, f2])[0]

    assert incident.finding_ids == tuple(sorted((f1.finding_id, f2.finding_id)))


# --- 6. Incident contains correct event IDs --------------------------------


def test_incident_contains_event_ids() -> None:
    f1 = _finding("e1")
    f2 = _finding("e2", rule_id="AEGIS-LISTEN-001", event_type=EventType.PORT_LISTENING)
    correlator = IncidentCorrelator()

    incident = correlator.correlate([], [f1, f2])[0]

    assert incident.event_ids == ("e1", "e2")


# --- 7. Incident risk uses existing assessments without exceeding 100 ------


def test_incident_risk_uses_existing_highest_score() -> None:
    e1, e2 = _event("e1"), _event("e2", event_type=EventType.PORT_LISTENING)
    f1 = _finding("e1")
    f2 = _finding("e2", rule_id="AEGIS-LISTEN-001", event_type=EventType.PORT_LISTENING)
    a1 = _assess(e1, (f1,))
    a2 = _assess(e2, (f2,))
    correlator = IncidentCorrelator()

    incident = correlator.correlate([e1, e2], [f1, f2], [a1, a2])[0]

    expected = max(a1.risk_score, a2.risk_score)
    assert incident.risk_score == expected
    assert 0 <= incident.risk_score <= 100
    assert incident.risk_level is max((a1, a2), key=lambda a: a.risk_score).risk_level
    assert incident.risk_assessment_ids == tuple(sorted((a1.assessment_id, a2.assessment_id)))


def test_incident_without_assessments_is_informational() -> None:
    f1 = _finding("e1")
    f2 = _finding("e2", rule_id="AEGIS-LISTEN-001", event_type=EventType.PORT_LISTENING)
    correlator = IncidentCorrelator()

    incident = correlator.correlate([], [f1, f2])[0]

    assert incident.risk_score == 0
    assert incident.risk_level is RiskLevel.INFORMATIONAL
    assert incident.risk_assessment_ids == ()


# --- 8. Correlation reason is deterministic / evidence-based ---------------


def test_correlation_reason_is_evidence_based() -> None:
    f1 = _finding("e1")  # host
    f2 = _finding("e2", rule_id="AEGIS-LISTEN-001", event_type=EventType.PORT_LISTENING)
    correlator = IncidentCorrelator()

    incident = correlator.correlate([], [f1, f2])[0]

    reason = incident.correlation_reason.lower()
    assert "same host" in reason
    assert "correlation window" in reason
    for forbidden in ("malware", "attacker", "compromised", "apt", "ddos"):
        assert forbidden not in reason


def test_incident_id_is_deterministic() -> None:
    f1 = _finding("e1")
    f2 = _finding("e2", rule_id="AEGIS-LISTEN-001", event_type=EventType.PORT_LISTENING)
    correlator = IncidentCorrelator()

    first = correlator.correlate([], [f1, f2])[0]
    second = correlator.correlate([], [f1, f2])[0]

    assert first.incident_id == second.incident_id


# --- 9. Runtime produces / clears active incidents -------------------------


def test_runtime_publishes_and_clears_incidents() -> None:
    from aegis_agent.monitors.port.models import PortChanges, PortRecord
    from aegis_agent.monitors.process.models import ProcessChanges, ProcessRecord
    from aegis_network_sensor.config import SensorSettings
    from aegis_runtime import AegisRuntime
    from aegis_shared.detection import DetectionEngine, DetectionSettings, clear_active_engine
    from aegis_shared.enums import AddressFamily, TransportProtocol
    from aegis_shared.pipeline import clear_active_pipeline
    from aegis_shared.risk import clear_active_risk_engine
    from tests.test_runtime import FakePortMonitor, FakeProcessMonitor, _agent

    clear_active_pipeline()
    clear_active_engine()
    clear_active_risk_engine()

    detection = DetectionEngine.from_settings(
        DetectionSettings(
            suspicious_process_path_patterns=["*evil*"],
            suspicious_listen_ports=[8080],
        )
    )
    process = FakeProcessMonitor(
        ProcessChanges(
            started=(ProcessRecord(pid=1, executable_path="C:\\evil\\x.exe", create_time=_TS),)
        )
    )
    port = FakePortMonitor(
        PortChanges(
            started=(
                PortRecord(
                    protocol=TransportProtocol.TCP,
                    address_family=AddressFamily.IPV4,
                    local_port=8080,
                    status="LISTEN",
                ),
            )
        )
    )
    runtime = AegisRuntime(
        agent_settings=_agent(enable_process_monitor=True, enable_port_monitor=True),
        sensor_settings=SensorSettings(capture_enabled=False),
        detection_engine=detection,
        process_monitor=cast(Any, process),
        port_monitor=cast(Any, port),
    )
    runtime.start()
    runtime.poll_once()

    incidents = get_active_incidents()
    # Two related host findings on the same host within the window -> one incident.
    assert len(incidents) == 1
    assert len(incidents[0].finding_ids) >= 2

    runtime.stop()
    assert get_active_incidents() == ()

    clear_active_pipeline()
    clear_active_engine()
    clear_active_risk_engine()


# --- 10. Desktop service shows a real incident -----------------------------


def test_desktop_service_shows_real_incident() -> None:
    pytest.importorskip("PySide6", reason="desktop extra not installed")
    from aegis_desktop.services.incidents import collect_incident_view
    from aegis_shared.correlation import set_active_incidents

    f1 = _finding("e1")
    f2 = _finding("e2", rule_id="AEGIS-LISTEN-001", event_type=EventType.PORT_LISTENING)
    incident = IncidentCorrelator().correlate([], [f1, f2])[0]
    set_active_incidents((incident,))

    view = collect_incident_view(
        incidents_provider=lambda: (incident,),
        findings_provider=lambda: {f1.finding_id: f1, f2.finding_id: f2},
        events_provider=lambda: (),
        anomalies_provider=lambda: {
            "e1": AnomalySignal(
                source="host_behavior",
                score=0.9,
                confidence=1.0,
                model_version="1.0.0",
            )
        },
    )

    assert view.available is True
    assert view.count == 1
    row = view.rows[0]
    assert row.incident_id == incident.incident_id
    assert row.finding_count == 2
    assert view.findings  # related findings resolved
    assert view.anomalies and view.anomalies[0].source == "host_behavior"


def test_desktop_page_renders_incident() -> None:
    pytest.importorskip("PySide6", reason="desktop extra not installed")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from aegis_desktop.app import create_application
    from aegis_desktop.pages.incidents import IncidentsPage
    from aegis_desktop.services.incidents import IncidentSnapshotView, collect_incident_view

    app = create_application([])
    assert app is not None

    f1 = _finding("e1")
    f2 = _finding("e2", rule_id="AEGIS-LISTEN-001", event_type=EventType.PORT_LISTENING)
    incident = IncidentCorrelator().correlate([], [f1, f2])[0]

    def provider() -> IncidentSnapshotView:
        return collect_incident_view(
            incidents_provider=lambda: (incident,),
            findings_provider=lambda: {f1.finding_id: f1, f2.finding_id: f2},
            events_provider=lambda: (),
            anomalies_provider=lambda: {},
        )

    page = IncidentsPage(provider=provider)
    page.refresh()

    assert page.row_count() == 1
    assert page.incident_count_text() == "Incidents: 1"

    page.show_detail_for(page.row_at(0))
    keys = page.detail_keys()
    assert "Incident Id" in keys
    assert "Reason" in keys
    assert "Risk Score" in keys
    assert "ML Anomaly" in keys
    assert "Timeline Stages" in keys
    assert "Forensic Storyline" in keys
    values = page.detail_values()
    assert "No ML anomaly signal available" in values
    assert page.timeline_stage_count() >= 2
    assert "Forensic Chain" in page.timeline_storyline_text()


def test_desktop_page_empty_state_when_no_incidents() -> None:
    pytest.importorskip("PySide6", reason="desktop extra not installed")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from aegis_desktop.app import create_application
    from aegis_desktop.pages.incidents import IncidentsPage
    from aegis_desktop.services.incidents import collect_incident_view

    app = create_application([])
    assert app is not None

    page = IncidentsPage(provider=lambda: collect_incident_view(incidents_provider=lambda: ()))
    page.refresh()

    assert page.row_count() == 0
    assert "No correlated security incidents available" in page._detail_hint.text()


def test_correlation_settings_window_is_configurable() -> None:
    settings = CorrelationSettings(window_seconds=60, min_findings=2)
    correlator = IncidentCorrelator(settings)

    within = _TS + timedelta(seconds=30)
    beyond = _TS + timedelta(seconds=90)
    f1 = _finding("e1", timestamp=_TS)
    f2 = _finding("e2", timestamp=within)
    f3 = _finding("e3", timestamp=beyond)

    incidents = correlator.correlate([], [f1, f2, f3])

    # e1+e2 cluster (30s apart) -> 1 incident; e3 is 90s from cluster start -> alone.
    assert len(incidents) == 1


def test_desktop_page_chronological_attack_timeline_ordering_and_deltas() -> None:
    pytest.importorskip("PySide6", reason="desktop extra not installed")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from aegis_desktop.app import create_application
    from aegis_desktop.pages.incidents import IncidentsPage
    from aegis_desktop.services.incidents import IncidentSnapshotView, collect_incident_view
    from aegis_shared.risk import AnomalySignal

    app = create_application([])
    assert app is not None

    t0 = _TS
    t1 = _TS + timedelta(seconds=2)
    t2 = _TS + timedelta(seconds=5)

    f1 = _finding("e1", rule_id="PORT_SCAN_TCP", timestamp=t0)
    f2 = _finding("e2", rule_id="SUSPICIOUS_EXEC_CMD", timestamp=t1)
    f3 = _finding("e3", rule_id="NET_C2_BEACON", timestamp=t2)

    incident = IncidentCorrelator().correlate([], [f1, f2, f3])[0]
    anom = AnomalySignal(
        source="unsupervised_autoencoder",
        score=0.91,
        confidence=0.85,
        model_version="1.0.0",
        reason="Divergent command payload",
    )

    def provider() -> IncidentSnapshotView:
        return collect_incident_view(
            incidents_provider=lambda: (incident,),
            findings_provider=lambda: {f1.finding_id: f1, f2.finding_id: f2, f3.finding_id: f3},
            events_provider=lambda: (),
            anomalies_provider=lambda: {"e1": anom},
        )

    page = IncidentsPage(provider=provider)
    page.refresh()
    assert page.row_count() == 1

    page.show_detail_for(page.row_at(0))

    # Milestones should include: 3 findings + 1 ML anomaly + 1 correlation = 5 milestones
    assert page.timeline_stage_count() == 5

    # Storyline narrative should capture the sequence
    story = page.timeline_storyline_text()
    assert "RECONNAISSANCE" in story
    assert "EXECUTION" in story
    assert "COMMAND & CONTROL" in story
    assert "ML ANOMALY" in story
    assert "CORRELATION" in story

    # Verify milestones in page._current_milestones
    milestones = getattr(page, "_current_milestones", [])
    assert len(milestones) == 5

    # Check chronological ordering
    timestamps = [m.timestamp for m in milestones]
    assert timestamps == sorted(timestamps)

    # First milestone should be Reconnaissance at t0
    assert milestones[0].stage_category == "RECONNAISSANCE"
    assert milestones[0].timestamp == t0

    # Second milestone should be Execution at t1
    assert milestones[1].stage_category == "EXECUTION"
    assert milestones[1].timestamp == t1

    # Third milestone should be C2 at t2
    assert milestones[2].stage_category == "COMMAND & CONTROL"
    assert milestones[2].timestamp == t2

