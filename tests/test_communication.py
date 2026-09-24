"""Focused tests for multi-signal suspicious-communication detection (Step 27).

Exercises the deterministic :class:`SuspiciousCommunicationAnalyzer`, its runtime
integration into the existing finding/risk/incident path, and the desktop
investigation view. Only factual metadata is used; no capture or payloads.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest

from aegis_shared.detection import (
    RULE_NETWORK_COMMUNICATION,
    CommunicationObservation,
    CommunicationSignal,
    CommunicationSignalType,
    SuspiciousCommunicationAnalyzer,
)
from aegis_shared.enums import (
    EventCategory,
    EventType,
    NetworkDirection,
    Severity,
    TransportProtocol,
)
from aegis_shared.pipeline import clear_active_pipeline
from aegis_shared.risk import clear_active_risk_engine

_TS = datetime(2026, 6, 1, 10, 0, 0, tzinfo=UTC)


def _obs(
    *signal_types: CommunicationSignalType,
    event_id: str = "e1",
    remote_ip: str = "10.0.0.77",
    remote_port: int = 4444,
    related: tuple[str, ...] = (),
) -> CommunicationObservation:
    signals = tuple(
        CommunicationSignal(signal_type=kind, source="test", observed=True, description="x")
        for kind in signal_types
    )
    return CommunicationObservation(
        host_id="host-1",
        event_id=event_id,
        event_type=EventType.FLOW_SUMMARY,
        category=EventCategory.NETWORK,
        timestamp=_TS,
        local_ip="10.0.0.5",
        remote_ip=remote_ip,
        remote_port=remote_port,
        protocol=TransportProtocol.TCP,
        direction=NetworkDirection.OUTBOUND,
        signals=signals,
        related_finding_ids=related,
    )


def _analyzer(**kwargs: int) -> SuspiciousCommunicationAnalyzer:
    return SuspiciousCommunicationAnalyzer(**kwargs)  # type: ignore[arg-type]


# --- 1. A single weak signal never produces a finding -----------------------


def test_single_relationship_signal_no_finding() -> None:
    analyzer = _analyzer()
    assert analyzer.analyze([_obs(CommunicationSignalType.NEW_RELATIONSHIP)]) == ()


def test_single_port_signal_no_finding() -> None:
    analyzer = _analyzer()
    assert analyzer.analyze([_obs(CommunicationSignalType.NEW_DESTINATION_PORT)]) == ()


# --- 3. Two independent signals produce a finding ---------------------------


def test_two_signals_produce_finding() -> None:
    analyzer = _analyzer()
    findings = analyzer.analyze(
        [
            _obs(
                CommunicationSignalType.NEW_RELATIONSHIP,
                CommunicationSignalType.NEW_DESTINATION_PORT,
            )
        ]
    )
    assert len(findings) == 1
    assert findings[0].rule_id == RULE_NETWORK_COMMUNICATION
    assert findings[0].severity is Severity.LOW
    assert findings[0].evidence["signal_count"] == "2"


# --- 4. New relationship + network anomaly ----------------------------------


def test_relationship_plus_anomaly() -> None:
    analyzer = _analyzer()
    findings = analyzer.analyze(
        [
            _obs(
                CommunicationSignalType.NEW_RELATIONSHIP,
                CommunicationSignalType.NETWORK_ANOMALY,
            )
        ]
    )
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM


# --- 5. New relationship + new destination ----------------------------------


def test_relationship_plus_new_destination() -> None:
    analyzer = _analyzer()
    findings = analyzer.analyze(
        [
            _obs(
                CommunicationSignalType.NEW_RELATIONSHIP,
                CommunicationSignalType.NEW_DESTINATION,
            )
        ]
    )
    assert len(findings) == 1


# --- 6. Host evidence + network evidence ------------------------------------


def test_host_evidence_plus_network_evidence() -> None:
    analyzer = _analyzer()
    findings = analyzer.analyze(
        [
            _obs(
                CommunicationSignalType.NEW_RELATIONSHIP,
                CommunicationSignalType.HOST_EVIDENCE,
            )
        ]
    )
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM


# --- 7. IOC context does not create a duplicate finding ---------------------


def test_ioc_context_suppresses_communication_finding() -> None:
    analyzer = _analyzer()
    findings = analyzer.analyze(
        [
            _obs(
                CommunicationSignalType.IOC_MATCH,
                CommunicationSignalType.NEW_RELATIONSHIP,
                CommunicationSignalType.NETWORK_ANOMALY,
            )
        ]
    )
    assert findings == ()  # the existing IOC finding remains primary evidence


# --- 8. Behavioral findings are reused (related finding IDs) ----------------


def test_behavioral_reused_in_related_ids() -> None:
    analyzer = _analyzer()
    findings = analyzer.analyze(
        [
            _obs(
                CommunicationSignalType.NEW_RELATIONSHIP,
                CommunicationSignalType.BEHAVIORAL,
                related=("AEGIS-NET-005:flow-1",),
            )
        ]
    )
    assert len(findings) == 1
    assert "AEGIS-NET-005:flow-1" in findings[0].evidence["related_finding_ids"]


# --- 9. Deterministic finding ID --------------------------------------------


def test_deterministic_finding_id() -> None:
    analyzer = _analyzer()
    first = analyzer.analyze(
        [
            _obs(
                CommunicationSignalType.NEW_RELATIONSHIP,
                CommunicationSignalType.NEW_DESTINATION_PORT,
            )
        ]
    )
    second = analyzer.analyze(
        [
            _obs(
                CommunicationSignalType.NEW_RELATIONSHIP,
                CommunicationSignalType.NEW_DESTINATION_PORT,
            )
        ]
    )
    assert first[0].finding_id == second[0].finding_id


# --- 10. Repeated observations are deduplicated -----------------------------


def test_repeated_observations_deduplicated() -> None:
    analyzer = _analyzer()
    observations = [
        _obs(
            CommunicationSignalType.NEW_RELATIONSHIP,
            CommunicationSignalType.NEW_DESTINATION_PORT,
            event_id="e1",
        ),
        _obs(
            CommunicationSignalType.NEW_RELATIONSHIP,
            CommunicationSignalType.NEW_DESTINATION_PORT,
            event_id="e2",
        ),
    ]
    findings = analyzer.analyze(observations)
    assert len(findings) == 1  # same relationship => one finding


# --- 11. Severity is deterministic ------------------------------------------


def test_severity_is_deterministic() -> None:
    analyzer = _analyzer()
    high = analyzer.analyze(
        [
            _obs(
                CommunicationSignalType.NETWORK_ANOMALY,
                CommunicationSignalType.HOST_EVIDENCE,
            )
        ]
    )
    low = analyzer.analyze(
        [
            _obs(
                CommunicationSignalType.NEW_RELATIONSHIP,
                CommunicationSignalType.NEW_DESTINATION,
            )
        ]
    )
    assert high[0].severity is Severity.HIGH
    assert low[0].severity is Severity.LOW


def test_min_signals_is_configurable() -> None:
    analyzer = _analyzer(min_signals=3)
    findings = analyzer.analyze(
        [
            _obs(
                CommunicationSignalType.NEW_RELATIONSHIP,
                CommunicationSignalType.NEW_DESTINATION_PORT,
            )
        ]
    )
    assert findings == ()  # only 2 signals, threshold is 3


# --- 12/13. Runtime integration: finding -> risk -> incident ----------------


def test_runtime_communication_finding_reaches_risk_and_incident() -> None:
    pytest.importorskip("scapy.layers.inet", reason="scapy not installed")
    from scapy.layers.inet import IP, TCP

    from aegis_agent.monitors.process.models import ProcessChanges, ProcessRecord
    from aegis_network_sensor.config import SensorSettings
    from aegis_network_sensor.sensor import NetworkSensor
    from aegis_runtime import AegisRuntime
    from aegis_shared.correlation import get_active_incidents
    from aegis_shared.detection import DetectionEngine, DetectionSettings
    from tests.test_runtime import FakeProcessMonitor, _agent

    class ReplaySensor(NetworkSensor):
        def __init__(self) -> None:
            super().__init__(SensorSettings(capture_enabled=False, local_addresses=["10.0.0.5"]))

        def capture(self, *, count: int | None = None) -> object:
            return self.process_packets(
                [IP(src="10.0.0.5", dst="10.0.0.77") / TCP(sport=50000, dport=4444)]
            )

    detection = DetectionEngine.from_settings(
        DetectionSettings(suspicious_process_path_patterns=["*evil*"])
    )
    runtime = AegisRuntime(
        agent_settings=_agent(enable_process_monitor=True),
        sensor_settings=SensorSettings(capture_enabled=False, local_addresses=["10.0.0.5"]),
        detection_engine=detection,
        process_monitor=FakeProcessMonitor(
            ProcessChanges(started=(ProcessRecord(pid=1, executable_path="C:\\evil\\x.exe"),))
        ),
        network_sensor=ReplaySensor(),
    )
    runtime.start()
    result = runtime.poll_once()

    rule_ids = {finding.rule_id for finding in runtime._cycle_findings}
    assert "AEGIS-PROC-001" in rule_ids
    assert RULE_NETWORK_COMMUNICATION in rule_ids
    assert result.assessments >= 1

    # Risk engine received the new rule through the normal contributor path.
    contributor_rules = {
        contributor.rule_id
        for assessment in runtime._cycle_assessments
        for contributor in assessment.contributors
    }
    assert RULE_NETWORK_COMMUNICATION in contributor_rules

    # Incident correlator grouped the related findings on the same host.
    incidents = get_active_incidents()
    assert len(incidents) == 1
    assert any(
        finding_id.startswith(f"{RULE_NETWORK_COMMUNICATION}:")
        for finding_id in incidents[0].finding_ids
    )

    runtime.stop()


# --- 14. Desktop investigation exposes communication evidence ---------------


def test_desktop_investigation_exposes_communication() -> None:
    pytest.importorskip("PySide6", reason="desktop extra not installed")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from aegis_desktop.app import create_application
    from aegis_desktop.pages.detections import DetectionsPage
    from aegis_desktop.services.detections import (
        DetectionPosture,
        FindingRow,
        FindingSnapshotView,
        collect_investigation_view,
        evidence_summary,
    )

    app = create_application([])
    assert app is not None

    analyzer = _analyzer()
    finding = analyzer.analyze(
        [
            _obs(
                CommunicationSignalType.NEW_RELATIONSHIP,
                CommunicationSignalType.NEW_DESTINATION_PORT,
                CommunicationSignalType.NETWORK_ANOMALY,
            )
        ]
    )[0]

    view = collect_investigation_view(
        finding,
        event_details_lookup=lambda _eid: None,
    )
    assert view.communication is not None
    assert view.communication.relationship == "10.0.0.5 -> 10.0.0.77:4444"
    assert view.communication.signal_count == 3
    assert "new_relationship" in view.communication.signals

    snapshot = FindingSnapshotView(
        available=True,
        error=None,
        collected_at=_TS,
        posture=DetectionPosture(running=True, enabled=True, rule_count=6, findings=1),
        rows=(
            FindingRow(
                timestamp=_TS,
                finding_id=finding.finding_id,
                rule_id=finding.rule_id,
                severity=finding.severity.value,
                title=finding.title,
                event_id=finding.event_id,
                event_type=finding.event_type.value,
                category=finding.category.value,
                host_id=finding.host_id,
                description=finding.description,
                evidence_summary=evidence_summary(dict(finding.evidence)),
                tags=tuple(finding.tags),
            ),
        ),
        findings=(finding,),
    )
    page = DetectionsPage(provider=lambda: snapshot, investigation_provider=lambda _f: view)
    page.refresh()
    page.show_detail_for(page.row_at(0))

    keys = page.detail_keys()
    values = page.detail_values()
    assert "Communication" in keys
    assert "10.0.0.5 -> 10.0.0.77:4444" in values
    assert "new_relationship" in " ".join(values)


@pytest.fixture(autouse=True)
def _clean() -> object:
    clear_active_pipeline()
    clear_active_risk_engine()
    yield
    clear_active_pipeline()
    clear_active_risk_engine()
