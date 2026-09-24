"""Deterministic tests for the network volume behavioral rule (AEGIS-NET-002).

The rule evaluates a single ``NETWORK_FLOW_SUMMARY`` event against explicit,
configured packet/byte thresholds. No capture, no network, no ML and no
privileges are involved.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from aegis_shared.detection import (
    ALL_RULE_IDS,
    RULE_EXECUTABLE_CREATION,
    RULE_LISTEN_PORT,
    RULE_NETWORK_ENDPOINT,
    RULE_NETWORK_VOLUME,
    RULE_PROCESS_PATH,
    RULE_SENSITIVE_FILE,
    DetectionEngine,
    DetectionSettings,
    HighNetworkVolumeRule,
    build_default_rules,
)
from aegis_shared.enums import (
    AddressFamily,
    EventType,
    Severity,
    SourceKind,
    TransportProtocol,
)
from aegis_shared.events import NetworkContext, SecurityEvent, SourceRef

_TS = datetime(2026, 1, 1, tzinfo=UTC)

_EVIDENCE_KEYS = {
    "flow_id",
    "packets_sent",
    "bytes_sent",
    "protocol",
    "duration_ms",
    "packet_threshold",
    "byte_threshold",
}


def _source() -> SourceRef:
    return SourceRef(kind=SourceKind.SENSOR, id="sensor-test")


def _flow_event(
    event_id: str = "flow-1",
    *,
    packets: int = 10,
    byte_count: int = 1000,
    duration_ms: int = 100,
    flow_id: str = "ipv4|tcp|10.0.0.1:1234->10.0.0.2:80",
) -> SecurityEvent:
    return SecurityEvent.create(
        event_id=event_id,
        event_type=EventType.FLOW_SUMMARY,
        source=_source(),
        timestamp=_TS,
        network=NetworkContext(
            src_ip="10.0.0.1",
            src_port=1234,
            dst_ip="10.0.0.2",
            dst_port=80,
            protocol=TransportProtocol.TCP,
            ip_version=AddressFamily.IPV4,
            flow_id=flow_id,
            packets_sent=packets,
            bytes_sent=byte_count,
            duration_ms=duration_ms,
        ),
    )


# --- Threshold behavior ----------------------------------------------------


def test_flow_below_threshold_produces_no_finding() -> None:
    rule = HighNetworkVolumeRule(packet_threshold=100, byte_threshold=10_000)

    assert rule.matches(_flow_event(packets=10, byte_count=1_000)) is False


def test_packet_threshold_exceeded_produces_finding() -> None:
    rule = HighNetworkVolumeRule(packet_threshold=100)

    assert rule.matches(_flow_event(packets=500, byte_count=10)) is True


def test_byte_threshold_exceeded_produces_finding() -> None:
    rule = HighNetworkVolumeRule(byte_threshold=1_000)

    assert rule.matches(_flow_event(packets=1, byte_count=5_000)) is True


def test_threshold_boundary_is_inclusive() -> None:
    rule = HighNetworkVolumeRule(packet_threshold=100, byte_threshold=1_000)

    assert rule.matches(_flow_event(packets=99, byte_count=999)) is False
    assert rule.matches(_flow_event(packets=100, byte_count=1_000)) is True


def test_volume_rule_ignores_non_flow_events() -> None:
    rule = HighNetworkVolumeRule(packet_threshold=1)
    packet_event = SecurityEvent.create(
        event_id="packet-1",
        event_type=EventType.NETWORK_PACKET_OBSERVED,
        source=_source(),
        timestamp=_TS,
        network=NetworkContext(packet_length=9999),
    )

    assert rule.matches(packet_event) is False


# --- Multiple flows --------------------------------------------------------


def test_multiple_flows_are_evaluated_deterministically() -> None:
    engine = DetectionEngine.from_settings(DetectionSettings(network_volume_packet_threshold=100))
    events = [
        _flow_event("a", packets=10),
        _flow_event("b", packets=500),
        _flow_event("c", packets=50),
    ]

    findings = engine.evaluate_many(events)

    assert [finding.event_id for finding in findings] == ["b"]
    assert findings[0].rule_id == RULE_NETWORK_VOLUME


# --- Evidence & identity ---------------------------------------------------


def test_evidence_contains_measurable_telemetry() -> None:
    rule = HighNetworkVolumeRule(packet_threshold=100, byte_threshold=1_000)
    finding = rule.build_finding(
        _flow_event("f", packets=500, byte_count=2_000, duration_ms=250, flow_id="flow-xyz")
    )

    evidence = finding.evidence
    assert evidence["flow_id"] == "flow-xyz"
    assert evidence["packets_sent"] == "500"
    assert evidence["bytes_sent"] == "2000"
    assert evidence["duration_ms"] == "250"
    assert evidence["packet_threshold"] == "100"
    assert evidence["byte_threshold"] == "1000"


def test_finding_id_is_deterministic() -> None:
    rule = HighNetworkVolumeRule(packet_threshold=100)
    event = _flow_event("flow-42", packets=500)

    first = rule.build_finding(event)
    second = rule.build_finding(event)

    assert first.finding_id == second.finding_id
    assert first.finding_id == f"{RULE_NETWORK_VOLUME}:flow-42"


def test_no_payload_or_application_data_exposed() -> None:
    rule = HighNetworkVolumeRule(packet_threshold=100)
    finding = rule.build_finding(_flow_event(packets=500))

    assert set(finding.evidence) <= _EVIDENCE_KEYS
    assert "payload" not in finding.evidence
    assert "raw" not in finding.evidence
    assert "command_line" not in finding.evidence


def test_finding_wording_is_observational_not_accusatory() -> None:
    rule = HighNetworkVolumeRule(packet_threshold=100)
    finding = rule.build_finding(_flow_event(packets=500))

    assert finding.severity is Severity.MEDIUM
    text = f"{finding.title} {finding.description}".lower()
    for forbidden in ("malware", "ddos", "attack", "botnet", "malicious", "compromised"):
        assert forbidden not in text


# --- Configuration ---------------------------------------------------------


def test_configuration_controls_the_rule() -> None:
    settings = DetectionSettings(
        network_volume_packet_threshold=100, network_volume_byte_threshold=1_000
    )
    rules = {rule.rule_id: rule for rule in build_default_rules(settings)}
    rule = rules[RULE_NETWORK_VOLUME]

    assert isinstance(rule, HighNetworkVolumeRule)
    assert rule.matches(_flow_event(packets=500, byte_count=10)) is True


def test_thresholds_default_to_disabled() -> None:
    settings = DetectionSettings()

    assert settings.network_volume_packet_threshold == 0
    assert settings.network_volume_byte_threshold == 0


def test_unconfigured_rule_never_triggers() -> None:
    rule = HighNetworkVolumeRule()  # both thresholds 0 = unconfigured

    assert rule.configured is False
    assert rule.matches(_flow_event(packets=1_000_000, byte_count=1_000_000_000)) is False


def test_disabled_rule_does_not_trigger() -> None:
    settings = DetectionSettings(
        network_volume_packet_threshold=100, disabled_rules=[RULE_NETWORK_VOLUME]
    )
    rules = {rule.rule_id: rule for rule in build_default_rules(settings)}
    assert rules[RULE_NETWORK_VOLUME].enabled is False

    engine = DetectionEngine.from_settings(settings)
    assert engine.evaluate(_flow_event(packets=500)) == ()


def test_negative_threshold_is_rejected() -> None:
    with pytest.raises(ValueError):
        DetectionSettings(network_volume_packet_threshold=-1)


# --- Existing rules unchanged ---------------------------------------------


def test_existing_rule_ids_are_preserved() -> None:
    assert {
        RULE_LISTEN_PORT,
        RULE_SENSITIVE_FILE,
        RULE_EXECUTABLE_CREATION,
        RULE_PROCESS_PATH,
        RULE_NETWORK_ENDPOINT,
        RULE_NETWORK_VOLUME,
    } == set(ALL_RULE_IDS)
    assert len(ALL_RULE_IDS) == 6


def test_existing_rules_still_build() -> None:
    rules = {rule.rule_id for rule in build_default_rules(DetectionSettings())}

    assert RULE_LISTEN_PORT in rules
    assert RULE_SENSITIVE_FILE in rules
    assert RULE_EXECUTABLE_CREATION in rules
    assert RULE_PROCESS_PATH in rules
    assert RULE_NETWORK_ENDPOINT in rules
    assert RULE_NETWORK_VOLUME in rules
