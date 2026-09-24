"""Focused tests for host <-> network security correlation (Step 24).

Exercises the deterministic :class:`HostNetworkCorrelator` and the runtime /
desktop integration. Telemetry is either constructed directly or replayed through
the existing network sensor path; no real capture, privileges or fake data.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest

from aegis_shared.correlation import (
    CorrelationSettings,
    HostNetworkCorrelator,
    clear_active_host_network_correlations,
    get_active_host_network_correlations,
)
from aegis_shared.detection import DetectionFinding
from aegis_shared.enums import EventCategory, EventType, Severity
from aegis_shared.pipeline import clear_active_pipeline
from aegis_shared.risk import clear_active_risk_engine

_TS = datetime(2026, 6, 1, 10, 0, 0, tzinfo=UTC)


def _finding(
    event_id: str,
    category: EventCategory,
    *,
    host_id: str | None = "host-1",
    timestamp: datetime = _TS,
    rule_id: str = "AEGIS-TEST-001",
) -> DetectionFinding:
    event_type = (
        EventType.PROCESS_STARTED
        if category is EventCategory.HOST
        else EventType.FLOW_SUMMARY
    )
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


@pytest.fixture(autouse=True)
def _clean() -> Iterator[None]:
    clear_active_pipeline()
    clear_active_risk_engine()
    clear_active_host_network_correlations()
    yield
    clear_active_pipeline()
    clear_active_risk_engine()
    clear_active_host_network_correlations()


# --- 1. Same host inside the window correlates ------------------------------


def test_same_host_inside_window_correlates() -> None:
    correlator = HostNetworkCorrelator()
    findings = [
        _finding("h1", EventCategory.HOST),
        _finding("n1", EventCategory.NETWORK, timestamp=_TS + timedelta(seconds=120)),
    ]

    correlations = correlator.correlate(findings)

    assert len(correlations) == 1
    correlation = correlations[0]
    assert correlation.host_id == "host-1"
    assert correlation.host_finding_ids == ("AEGIS-TEST-001:h1",)
    assert correlation.network_finding_ids == ("AEGIS-TEST-001:n1",)
    assert correlation.window_seconds == 300
    assert "same host" in correlation.reason
    assert correlation.event_ids == ("h1", "n1")


# --- 2. Same host outside the window does not correlate ---------------------


def test_same_host_outside_window_no_correlation() -> None:
    correlator = HostNetworkCorrelator()
    findings = [
        _finding("h1", EventCategory.HOST),
        _finding("n1", EventCategory.NETWORK, timestamp=_TS + timedelta(seconds=1000)),
    ]

    assert correlator.correlate(findings) == ()


# --- 3. Different hosts do not correlate ------------------------------------


def test_different_hosts_no_correlation() -> None:
    correlator = HostNetworkCorrelator()
    findings = [
        _finding("h1", EventCategory.HOST, host_id="host-1"),
        _finding("n1", EventCategory.NETWORK, host_id="host-2"),
    ]

    assert correlator.correlate(findings) == ()


# --- 4. Missing/empty host ID does not correlate ----------------------------


def test_missing_host_id_no_correlation() -> None:
    correlator = HostNetworkCorrelator()
    findings = [
        _finding("h1", EventCategory.HOST, host_id=None),
        _finding("n1", EventCategory.NETWORK, host_id=None),
    ]

    assert correlator.correlate(findings) == ()


# --- 5. Host-only findings do not correlate ---------------------------------


def test_host_only_no_correlation() -> None:
    correlator = HostNetworkCorrelator()
    findings = [
        _finding("h1", EventCategory.HOST),
        _finding("h2", EventCategory.HOST),
    ]

    assert correlator.correlate(findings) == ()


# --- 6. Network-only findings do not correlate ------------------------------


def test_network_only_no_correlation() -> None:
    correlator = HostNetworkCorrelator()
    findings = [
        _finding("n1", EventCategory.NETWORK),
        _finding("n2", EventCategory.NETWORK),
    ]

    assert correlator.correlate(findings) == ()


# --- 7. Deterministic correlation id ----------------------------------------


def test_correlation_is_deterministic() -> None:
    correlator = HostNetworkCorrelator()
    findings = [
        _finding("h1", EventCategory.HOST),
        _finding("n1", EventCategory.NETWORK),
    ]

    first = correlator.correlate(findings)
    second = correlator.correlate(findings)

    assert [c.correlation_id for c in first] == [c.correlation_id for c in second]
    assert first[0].correlation_id.startswith("HNC-")


# --- 8. Runtime integration: finding -> correlation -> incident -------------


def test_runtime_correlates_host_and_network_findings() -> None:
    pytest.importorskip("scapy.layers.inet", reason="scapy not installed")
    from scapy.layers.inet import IP, TCP

    from aegis_agent.monitors.process.models import ProcessChanges, ProcessRecord
    from aegis_network_sensor.config import SensorSettings
    from aegis_network_sensor.sensor import NetworkSensor
    from aegis_runtime import AegisRuntime
    from aegis_shared.correlation import get_active_incidents
    from aegis_shared.detection import (
        DetectionEngine,
        DetectionSettings,
        NetworkBehaviorAnalyzer,
    )
    from tests.test_runtime import FakeProcessMonitor, _agent

    class FanoutSensor(NetworkSensor):
        def __init__(self) -> None:
            super().__init__(SensorSettings(capture_enabled=False))

        def capture(self, *, count: int | None = None) -> object:
            packets = [
                IP(src="10.0.0.1", dst=f"10.9.0.{i + 2}") / TCP(sport=40000 + i, dport=1000 + i)
                for i in range(6)
            ]
            return self.process_packets(packets)

    detection = DetectionEngine.from_settings(
        DetectionSettings(suspicious_process_path_patterns=["*evil*"])
    )
    process = FakeProcessMonitor(
        ProcessChanges(started=(ProcessRecord(pid=1, executable_path="C:\\evil\\x.exe"),))
    )
    analyzer = NetworkBehaviorAnalyzer(
        dest_fanout_threshold=3, dest_fanout_window_seconds=300
    )
    runtime = AegisRuntime(
        agent_settings=_agent(enable_process_monitor=True),
        sensor_settings=SensorSettings(capture_enabled=False),
        detection_engine=detection,
        process_monitor=process,
        network_sensor=FanoutSensor(),
        behavior_analyzer=analyzer,
    )
    runtime.start()
    result = runtime.poll_once()

    assert result.findings >= 2
    correlations = get_active_host_network_correlations()
    assert len(correlations) == 1
    assert correlations[0].host_finding_ids
    assert correlations[0].network_finding_ids

    # The existing IncidentCorrelator groups the same related findings.
    incidents = get_active_incidents()
    assert len(incidents) == 1
    assert len(incidents[0].finding_ids) >= 2

    runtime.stop()
    # Bounded/reset behaviour: stopping clears the published correlation state.
    assert get_active_host_network_correlations() == ()


def test_runtime_window_is_configurable() -> None:
    correlator = HostNetworkCorrelator(
        CorrelationSettings(host_network_correlation_window_seconds=30)
    )
    findings = [
        _finding("h1", EventCategory.HOST),
        _finding("n1", EventCategory.NETWORK, timestamp=_TS + timedelta(seconds=60)),
    ]

    assert correlator.correlate(findings) == ()


# --- 9. Desktop investigation exposes real correlation ----------------------


def test_desktop_investigation_exposes_correlation() -> None:
    from aegis_desktop.services.detections import collect_investigation_view

    host_finding = _finding("h1", EventCategory.HOST)
    network_finding = _finding("n1", EventCategory.NETWORK)
    correlation = HostNetworkCorrelator().correlate([host_finding, network_finding])[0]

    from aegis_shared.correlation import set_active_host_network_correlations

    set_active_host_network_correlations((correlation,))
    view = collect_investigation_view(
        host_finding,
        event_details_lookup=lambda _eid: None,
    )

    assert view.correlation is not None
    assert view.correlation.correlated is True
    assert view.correlation.host_id == "host-1"
    assert view.correlation.host_finding_count == 1
    assert view.correlation.network_finding_count == 1

    # Honest empty state when no correlation is published.
    clear_active_host_network_correlations()
    empty = collect_investigation_view(host_finding, event_details_lookup=lambda _eid: None)
    assert empty.correlation is None


# --- 10. Desktop incident view exposes real correlation ---------------------


def test_desktop_incident_view_exposes_correlation() -> None:
    pytest.importorskip("PySide6", reason="desktop extra not installed")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from aegis_desktop.app import create_application
    from aegis_desktop.pages.incidents import IncidentsPage
    from aegis_desktop.services.correlation import collect_correlations
    from aegis_desktop.services.incidents import collect_incident_view
    from aegis_shared.correlation import IncidentCorrelator

    app = create_application([])
    assert app is not None

    host_finding = _finding("h1", EventCategory.HOST)
    network_finding = _finding("n1", EventCategory.NETWORK)
    correlation = HostNetworkCorrelator().correlate([host_finding, network_finding])[0]
    incident = IncidentCorrelator().correlate((), [host_finding, network_finding])[0]

    view = collect_incident_view(
        incidents_provider=lambda: (incident,),
        findings_provider=lambda: {
            host_finding.finding_id: host_finding,
            network_finding.finding_id: network_finding,
        },
        events_provider=lambda: (),
        anomalies_provider=lambda: {},
        correlations_provider=lambda: collect_correlations(provider=lambda: (correlation,)),
    )
    assert view.correlations

    page = IncidentsPage(provider=lambda: view)
    page.refresh()
    page.show_detail_for(page.row_at(0))

    keys = page.detail_keys()
    values = page.detail_values()
    assert "Status" in keys
    assert "Correlated" in values
    assert any("same host" in value for value in values)
