"""Focused tests for real network behavioral detection (Step 23).

Exercises :class:`NetworkBehaviorAnalyzer` over locally constructed flow-summary
events and verifies the runtime integration into Finding -> Risk -> Incident.
No real packet capture, privileges or threads are used; telemetry is either
built directly or replayed through the existing sensor path.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest

from aegis_shared.detection import (
    RULE_NETWORK_DEST_FANOUT,
    RULE_NETWORK_FLOW_BURST,
    RULE_NETWORK_PORT_BREADTH,
    RULE_NETWORK_REPEATED_COMM,
    NetworkBehaviorAnalyzer,
)
from aegis_shared.enums import EventType, SourceKind, TransportProtocol
from aegis_shared.events import NetworkContext, SecurityEvent, SourceRef
from aegis_shared.pipeline import clear_active_pipeline
from aegis_shared.risk import clear_active_risk_engine

_TS = datetime(2026, 6, 1, 10, 0, 0, tzinfo=UTC)


def _flow_event(
    index: int,
    *,
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    port: int = 443,
    timestamp: datetime | None = None,
) -> SecurityEvent:
    return SecurityEvent.create(
        event_id=f"e{index}",
        event_type=EventType.FLOW_SUMMARY,
        source=SourceRef(kind=SourceKind.SENSOR, id="sensor"),
        timestamp=timestamp or _TS,
        network=NetworkContext(
            src_ip=src,
            dst_ip=dst,
            dst_port=port,
            flow_id=f"f{index}",
            protocol=TransportProtocol.TCP,
            packets_sent=10,
            bytes_sent=1000,
            duration_ms=1000,
        ),
    )


def _rule_ids(findings: object) -> list[str]:
    return [finding.rule_id for finding in findings]  # type: ignore[attr-defined]


@pytest.fixture(autouse=True)
def _clean() -> Iterator[None]:
    clear_active_pipeline()
    clear_active_risk_engine()
    yield
    clear_active_pipeline()
    clear_active_risk_engine()


# --- 1. Disabled by default -------------------------------------------------


def test_disabled_by_default_produces_no_findings() -> None:
    analyzer = NetworkBehaviorAnalyzer()
    events = [_flow_event(i, dst=f"10.0.0.{i + 2}") for i in range(20)]

    assert analyzer.configured is False
    assert analyzer.evaluate(events) == ()


# --- 2. Flow burst detection ------------------------------------------------


def test_flow_burst_detection() -> None:
    analyzer = NetworkBehaviorAnalyzer(flow_burst_threshold=5, flow_burst_window_seconds=60)
    events = [_flow_event(i, dst=f"10.0.0.{i + 2}") for i in range(6)]

    findings = analyzer.evaluate(events)

    assert _rule_ids(findings) == [RULE_NETWORK_FLOW_BURST]
    evidence = findings[0].evidence
    assert int(evidence["observed_count"]) == 6
    assert evidence["window_seconds"] == "60"
    assert evidence["threshold"] == "5"
    assert findings[0].severity.value == "medium"


# --- 3. Below threshold does not trigger ------------------------------------


def test_below_threshold_does_not_trigger() -> None:
    analyzer = NetworkBehaviorAnalyzer(flow_burst_threshold=10, flow_burst_window_seconds=60)
    events = [_flow_event(i, dst=f"10.0.0.{i + 2}") for i in range(4)]

    assert analyzer.evaluate(events) == ()


# --- 4. Repeated communication detection ------------------------------------


def test_repeated_communication_detection() -> None:
    analyzer = NetworkBehaviorAnalyzer(repeated_comm_threshold=4, repeated_comm_window_seconds=60)
    events = [_flow_event(i, src="10.0.0.1", dst="10.5.0.1", port=80) for i in range(5)]

    findings = analyzer.evaluate(events)

    assert _rule_ids(findings) == [RULE_NETWORK_REPEATED_COMM]
    evidence = findings[0].evidence
    assert evidence["src_ip"] == "10.0.0.1"
    assert evidence["dst_ip"] == "10.5.0.1"
    assert int(evidence["repeated_flows"]) == 5


# --- 5. Destination fan-out detection ---------------------------------------


def test_destination_fanout_detection() -> None:
    analyzer = NetworkBehaviorAnalyzer(
        dest_fanout_threshold=4, dest_fanout_window_seconds=60
    )
    events = [_flow_event(i, src="10.0.0.9", dst=f"10.7.0.{i + 1}") for i in range(5)]

    findings = analyzer.evaluate(events)

    assert _rule_ids(findings) == [RULE_NETWORK_DEST_FANOUT]
    evidence = findings[0].evidence
    assert evidence["src_ip"] == "10.0.0.9"
    assert int(evidence["distinct_destinations"]) == 5


# --- 6. Destination-port breadth detection ----------------------------------


def test_destination_port_breadth_detection() -> None:
    analyzer = NetworkBehaviorAnalyzer(
        port_breadth_threshold=4, port_breadth_window_seconds=60
    )
    events = [
        _flow_event(i, src="10.0.0.9", dst="10.8.0.1", port=1000 + i) for i in range(5)
    ]

    findings = analyzer.evaluate(events)

    assert _rule_ids(findings) == [RULE_NETWORK_PORT_BREADTH]
    evidence = findings[0].evidence
    assert int(evidence["distinct_destination_ports"]) == 5


# --- 7. Disabling a behavioral rule via disabled_rules ----------------------


def test_rule_can_be_disabled() -> None:
    analyzer = NetworkBehaviorAnalyzer(
        flow_burst_threshold=5,
        flow_burst_window_seconds=60,
        disabled_rules=(RULE_NETWORK_FLOW_BURST,),
    )
    events = [_flow_event(i, dst=f"10.0.0.{i + 2}") for i in range(6)]

    assert analyzer.evaluate(events) == ()


# --- 8. Deterministic and bounded window ------------------------------------


def test_deterministic_and_window_bounded() -> None:
    analyzer = NetworkBehaviorAnalyzer(flow_burst_threshold=5, flow_burst_window_seconds=60)
    recent = [_flow_event(i, dst=f"10.0.0.{i + 2}") for i in range(6)]
    old = [
        _flow_event(100 + i, dst=f"10.1.0.{i + 2}", timestamp=_TS - timedelta(hours=2))
        for i in range(6)
    ]
    events = [*old, *recent]

    first = analyzer.evaluate(events)
    second = analyzer.evaluate(events)

    # Deterministic: identical output for identical input.
    assert [f.finding_id for f in first] == [f.finding_id for f in second]
    # Window-bounded: the 2h-old flows are excluded, so only the 6 recent count.
    assert len(first) == 1
    assert first[0].evidence["observed_count"] == "6"


# --- 9. Runtime integration: finding -> risk -> incident --------------------


def test_runtime_finding_to_risk_to_incident() -> None:
    pytest.importorskip("scapy.layers.inet", reason="scapy not installed")
    from scapy.layers.inet import IP, TCP

    from aegis_agent.config import AgentSettings
    from aegis_network_sensor.config import SensorSettings
    from aegis_network_sensor.sensor import NetworkSensor
    from aegis_runtime import AegisRuntime
    from aegis_shared.correlation import get_active_incidents

    class FanoutSensor(NetworkSensor):
        def __init__(self) -> None:
            super().__init__(SensorSettings(capture_enabled=False))

        def capture(self, *, count: int | None = None) -> object:
            packets = [
                IP(src="10.0.0.1", dst=f"10.9.0.{i + 2}") / TCP(sport=40000 + i, dport=1000 + i)
                for i in range(6)
            ]
            return self.process_packets(packets)

    analyzer = NetworkBehaviorAnalyzer(
        flow_burst_threshold=5,
        flow_burst_window_seconds=300,
        dest_fanout_threshold=4,
        dest_fanout_window_seconds=300,
        port_breadth_threshold=4,
        port_breadth_window_seconds=300,
    )
    runtime = AegisRuntime(
        agent_settings=AgentSettings(
            enable_process_monitor=False,
            enable_port_monitor=False,
            enable_file_integrity=False,
            event_buffer_max_events=500,
        ),
        sensor_settings=SensorSettings(capture_enabled=False),
        network_sensor=FanoutSensor(),
        behavior_analyzer=analyzer,
    )
    runtime.start()
    result = runtime.poll_once()

    rule_ids = {finding.rule_id for finding in runtime._cycle_findings}
    expected = {RULE_NETWORK_FLOW_BURST, RULE_NETWORK_DEST_FANOUT, RULE_NETWORK_PORT_BREADTH}
    assert expected <= rule_ids
    assert result.findings >= 3
    assert result.assessments >= 1

    incidents = get_active_incidents()
    assert len(incidents) == 1
    assert len(incidents[0].finding_ids) >= 3

    runtime.stop()
    assert get_active_incidents() == ()


# --- 10. Desktop Detections service shows behavioral findings ---------------


def test_desktop_detections_service_shows_behavioral_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("scapy.layers.inet", reason="scapy not installed")
    from scapy.layers.inet import IP, TCP

    from aegis_agent.config import AgentSettings
    from aegis_desktop.services.detections import collect_finding_view
    from aegis_network_sensor.config import SensorSettings
    from aegis_network_sensor.sensor import NetworkSensor
    from aegis_runtime import AegisRuntime
    from aegis_shared.detection import get_detection_settings

    class FanoutSensor(NetworkSensor):
        def __init__(self) -> None:
            super().__init__(SensorSettings(capture_enabled=False))

        def capture(self, *, count: int | None = None) -> object:
            packets = [
                IP(src="10.0.0.1", dst=f"10.9.0.{i + 2}") / TCP(sport=40000 + i, dport=1000 + i)
                for i in range(6)
            ]
            return self.process_packets(packets)

    # Configure the behavioral rule through the existing detection settings.
    monkeypatch.setenv("AEGIS_DETECTION_NETWORK_DESTINATION_FANOUT_THRESHOLD", "4")
    monkeypatch.setenv("AEGIS_DETECTION_NETWORK_DESTINATION_FANOUT_WINDOW_SECONDS", "300")
    get_detection_settings.cache_clear()

    runtime = AegisRuntime(
        agent_settings=AgentSettings(
            enable_process_monitor=False,
            enable_port_monitor=False,
            enable_file_integrity=False,
            event_buffer_max_events=500,
        ),
        sensor_settings=SensorSettings(capture_enabled=False),
        network_sensor=FanoutSensor(),
    )
    runtime.start()
    runtime.poll_once()

    view = collect_finding_view(engine=runtime.detection_engine)

    assert view.available is True
    rule_ids = {row.rule_id for row in view.rows}
    assert RULE_NETWORK_DEST_FANOUT in rule_ids

    runtime.stop()
    get_detection_settings.cache_clear()
