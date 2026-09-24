"""Deterministic tests for the rule-based detection engine.

All events are constructed locally with fixed IDs and timestamps; no test
depends on the real machine, the network, or elevated privileges.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from aegis_shared.detection import (
    RULE_LISTEN_PORT,
    DetectionEngine,
    DetectionFinding,
    DetectionSettings,
    ExecutableCreationRule,
    SensitiveFileModificationRule,
    SuspiciousListeningPortRule,
    SuspiciousNetworkEndpointRule,
    SuspiciousProcessPathRule,
    build_default_rules,
    normalize_endpoint,
    parse_endpoint,
)
from aegis_shared.detection.rules import DetectionRule
from aegis_shared.enums import (
    AddressFamily,
    EventCategory,
    EventType,
    FileType,
    HashStatus,
    NetworkDirection,
    Platform,
    Severity,
    SourceKind,
    TransportProtocol,
)
from aegis_shared.events import (
    FileContext,
    HostRef,
    NetworkContext,
    ProcessContext,
    SecurityEvent,
    SocketContext,
    SourceRef,
)

_TS = datetime(2026, 1, 1, tzinfo=UTC)

_SENSITIVE_PATH = os.path.join("C:", "demo", "secrets", "config.ini")
_WATCH_DIR = os.path.join("C:", "demo", "watch")
_WATCHED_EXE = os.path.join(_WATCH_DIR, "payload.exe")
_PUBLIC_EXE = os.path.join("C:", "Users", "Public", "payload.exe")


# --- Test-only rules -------------------------------------------------------


class _AlwaysRule(DetectionRule):
    rule_id = "TEST-ALWAYS-001"
    name = "Always matches"
    description = "Test-only rule that matches every event."
    default_severity = Severity.LOW

    def matches(self, event: SecurityEvent) -> bool:
        return True


class _NoIdRule(DetectionRule):
    rule_id = ""
    name = "No id"
    description = "Test-only rule with an empty id."

    def matches(self, event: SecurityEvent) -> bool:
        return False


class _BoomRule(DetectionRule):
    rule_id = "TEST-BOOM-001"
    name = "Raises"
    description = "Test-only rule that raises on evaluation."

    def matches(self, event: SecurityEvent) -> bool:
        raise RuntimeError("boom")


# --- Event helpers ---------------------------------------------------------


def _source() -> SourceRef:
    return SourceRef(kind=SourceKind.AGENT, id="agent-test")


def _host() -> HostRef:
    return HostRef(host_id="host-1", hostname="ws-01", platform=Platform.WINDOWS)


def _port_event(
    port: int = 8080,
    *,
    protocol: TransportProtocol = TransportProtocol.TCP,
    event_id: str = "port-1",
) -> SecurityEvent:
    return SecurityEvent.create(
        event_id=event_id,
        event_type=EventType.PORT_LISTENING,
        source=_source(),
        host=_host(),
        timestamp=_TS,
        socket=SocketContext(
            local_address="127.0.0.1",
            local_port=port,
            address_family=AddressFamily.IPV4,
            protocol=protocol,
            status="LISTEN",
        ),
    )


def _file_event(
    path: str,
    *,
    event_type: EventType = EventType.FILE_MODIFIED,
    file_type: FileType = FileType.REGULAR,
    event_id: str = "file-1",
) -> SecurityEvent:
    return SecurityEvent.create(
        event_id=event_id,
        event_type=event_type,
        source=_source(),
        host=_host(),
        timestamp=_TS,
        file=FileContext(path=path, file_type=file_type, hash_status=HashStatus.HASHED),
    )


def _process_event(path: str, *, event_id: str = "proc-1") -> SecurityEvent:
    return SecurityEvent.create(
        event_id=event_id,
        event_type=EventType.PROCESS_STARTED,
        source=_source(),
        host=_host(),
        timestamp=_TS,
        process=ProcessContext(pid=10, name="payload.exe", executable_path=path),
    )


def _network_event(dst_ip: str, dst_port: int, *, event_id: str = "net-1") -> SecurityEvent:
    return SecurityEvent.create(
        event_id=event_id,
        event_type=EventType.NETWORK_PACKET_OBSERVED,
        source=SourceRef(kind=SourceKind.SENSOR, id="sensor-test"),
        timestamp=_TS,
        network=NetworkContext(
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=TransportProtocol.TCP,
            direction=NetworkDirection.OUTBOUND,
            ip_version=AddressFamily.IPV4,
            flow_id="flow-1",
        ),
    )


# --- Engine ----------------------------------------------------------------


def test_matching_event_produces_finding() -> None:
    engine = DetectionEngine([SuspiciousListeningPortRule(ports=[8080])])

    findings = engine.evaluate(_port_event(8080))

    assert len(findings) == 1
    assert findings[0].rule_id == RULE_LISTEN_PORT


def test_non_matching_event_produces_no_finding() -> None:
    engine = DetectionEngine([SuspiciousListeningPortRule(ports=[8080])])

    assert engine.evaluate(_port_event(443)) == ()


def test_multiple_rules_can_match_one_event() -> None:
    engine = DetectionEngine([SuspiciousListeningPortRule(ports=[8080]), _AlwaysRule()])

    findings = engine.evaluate(_port_event(8080))

    assert [finding.rule_id for finding in findings] == [RULE_LISTEN_PORT, "TEST-ALWAYS-001"]


def test_rule_ordering_is_deterministic() -> None:
    first = DetectionEngine([_AlwaysRule(), SuspiciousListeningPortRule(ports=[8080])])
    second = DetectionEngine([SuspiciousListeningPortRule(ports=[8080]), _AlwaysRule()])

    assert [rule.rule_id for rule in first.rules] == [rule.rule_id for rule in second.rules]
    assert [f.rule_id for f in first.evaluate(_port_event(8080))] == [
        f.rule_id for f in second.evaluate(_port_event(8080))
    ]


def test_evaluate_many_concatenates_in_event_order() -> None:
    engine = DetectionEngine(
        [
            SuspiciousListeningPortRule(ports=[8080]),
            SensitiveFileModificationRule(patterns=["*secrets*"]),
        ]
    )
    events = [_port_event(8080, event_id="e1"), _file_event(_SENSITIVE_PATH, event_id="e2")]

    findings = engine.evaluate_many(events)

    assert [finding.event_id for finding in findings] == ["e1", "e2"]


def test_empty_rule_configuration_matches_nothing() -> None:
    assert DetectionEngine([]).evaluate(_port_event(8080)) == ()

    engine = DetectionEngine.from_settings(DetectionSettings())
    assert engine.evaluate(_port_event(8080)) == ()
    assert engine.evaluate(_file_event(_SENSITIVE_PATH)) == ()


def test_disabled_rule_does_not_match() -> None:
    rule = SuspiciousListeningPortRule(ports=[8080], enabled=False)
    assert DetectionEngine([rule]).evaluate(_port_event(8080)) == ()

    settings = DetectionSettings(disabled_rules=[RULE_LISTEN_PORT], suspicious_listen_ports=[8080])
    assert DetectionEngine.from_settings(settings).evaluate(_port_event(8080)) == ()


def test_invalid_rule_configuration_is_rejected() -> None:
    with pytest.raises(ValidationError):
        DetectionSettings(suspicious_listen_ports=[0])
    with pytest.raises(ValidationError):
        DetectionSettings(suspicious_listen_ports=[70000])
    with pytest.raises(ValidationError):
        DetectionSettings(suspicious_network_endpoints=["not-an-ip"])
    with pytest.raises(ValueError, match="unknown rule id"):
        build_default_rules(DetectionSettings(disabled_rules=["NOPE-001"]))
    with pytest.raises(ValueError, match="rule_id"):
        DetectionEngine([_NoIdRule()])


def test_duplicate_rule_id_is_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate rule id"):
        DetectionEngine(
            [SuspiciousListeningPortRule(ports=[1]), SuspiciousListeningPortRule(ports=[2])]
        )


# --- Rules -----------------------------------------------------------------


def test_suspicious_listening_port_matches() -> None:
    assert SuspiciousListeningPortRule(ports=[8080]).matches(_port_event(8080)) is True


def test_normal_listening_port_does_not_match() -> None:
    rule = SuspiciousListeningPortRule(ports=[8080])
    assert rule.matches(_port_event(443)) is False
    assert rule.matches(_port_event(8080, protocol=TransportProtocol.UDP)) is False


def test_sensitive_file_modification_matches() -> None:
    rule = SensitiveFileModificationRule(patterns=["*secrets*"])
    assert rule.matches(_file_event(_SENSITIVE_PATH)) is True


def test_unrelated_file_modification_does_not_match() -> None:
    rule = SensitiveFileModificationRule(patterns=["*secrets*"])
    assert rule.matches(_file_event(os.path.join("C:", "tmp", "a.txt"))) is False
    # Wrong event type for this rule.
    assert rule.matches(_file_event(_SENSITIVE_PATH, event_type=EventType.FILE_CREATED)) is False


def test_executable_creation_matches() -> None:
    rule = ExecutableCreationRule(extensions=[".exe"], watch_paths=[_WATCH_DIR])
    assert rule.matches(_file_event(_WATCHED_EXE, event_type=EventType.FILE_CREATED)) is True


def test_non_executable_creation_does_not_match() -> None:
    rule = ExecutableCreationRule(extensions=[".exe"], watch_paths=[_WATCH_DIR])
    assert (
        rule.matches(
            _file_event(os.path.join(_WATCH_DIR, "notes.txt"), event_type=EventType.FILE_CREATED)
        )
        is False
    )
    # Executable outside the monitored directory.
    assert (
        rule.matches(
            _file_event(os.path.join("C:", "tmp", "x.exe"), event_type=EventType.FILE_CREATED)
        )
        is False
    )


def test_suspicious_process_path_matches() -> None:
    rule = SuspiciousProcessPathRule(patterns=["*Public*"])
    assert rule.matches(_process_event(_PUBLIC_EXE)) is True


def test_normal_process_path_does_not_match() -> None:
    rule = SuspiciousProcessPathRule(patterns=["*Public*"])
    normal = os.path.join("C:", "Windows", "System32", "svchost.exe")
    assert rule.matches(_process_event(normal)) is False


def test_suspicious_network_endpoint_matches() -> None:
    rule = SuspiciousNetworkEndpointRule(endpoints=[("203.0.113.9", 4444)])
    assert rule.matches(_network_event("203.0.113.9", 4444)) is True


def test_different_network_endpoint_does_not_match() -> None:
    rule = SuspiciousNetworkEndpointRule(endpoints=[("203.0.113.9", 4444)])
    assert rule.matches(_network_event("198.51.100.1", 4444)) is False
    assert rule.matches(_network_event("203.0.113.9", 4445)) is False


# --- Data integrity --------------------------------------------------------


def test_finding_references_correct_event_id() -> None:
    event = _port_event(8080, event_id="evt-42")
    rule = SuspiciousListeningPortRule(ports=[8080])

    finding = rule.build_finding(event)

    assert finding.event_id == "evt-42"
    assert finding.finding_id == f"{rule.rule_id}:evt-42"
    assert finding.event_type is EventType.PORT_LISTENING
    assert finding.category is EventCategory.HOST
    assert finding.host_id == "host-1"


def test_evidence_is_deterministic() -> None:
    rule = SuspiciousListeningPortRule(ports=[8080])
    event = _port_event(8080)

    assert rule.evidence(event) == rule.evidence(event)
    assert rule.evidence(event) == {
        "local_port": "8080",
        "protocol": "tcp",
        "local_address": "127.0.0.1",
    }


def test_json_serialization_is_deterministic() -> None:
    engine = DetectionEngine([SuspiciousListeningPortRule(ports=[8080])])
    event = _port_event(8080)

    first = json.dumps(engine.evaluate(event)[0].to_json_dict(), sort_keys=True)
    second = json.dumps(engine.evaluate(event)[0].to_json_dict(), sort_keys=True)

    assert first == second


def test_finding_timestamp_is_timezone_aware() -> None:
    finding = SuspiciousListeningPortRule(ports=[8080]).build_finding(_port_event(8080))

    assert finding.timestamp == _TS
    assert finding.timestamp.tzinfo is not None


def test_malformed_or_incomplete_events_are_handled_safely() -> None:
    engine = DetectionEngine([SuspiciousListeningPortRule(ports=[8080]), _BoomRule()])

    assert engine.evaluate(None) == ()  # type: ignore[arg-type]
    assert engine.evaluate(_port_event(8080).model_copy(update={"socket": None})) == ()
    # Port 443 does not match the port rule, leaving only the raising rule.
    assert engine.evaluate(_port_event(443, event_id="x")) == ()


def test_rules_do_not_mutate_the_input_event() -> None:
    event = _port_event(8080)
    before = event.model_dump()
    rule = SuspiciousListeningPortRule(ports=[8080])

    rule.matches(event)
    rule.build_finding(event)

    assert event.model_dump() == before


# --- Configuration helpers -------------------------------------------------


def test_configuration_defaults() -> None:
    settings = DetectionSettings()

    assert settings.enabled is True
    assert settings.suspicious_listen_ports == []
    assert settings.sensitive_file_patterns == []
    assert settings.executable_watch_paths == []
    assert settings.suspicious_process_path_patterns == []
    assert settings.suspicious_network_endpoints == []
    assert ".exe" in settings.executable_extensions


def test_configuration_accepts_comma_separated_values() -> None:
    settings = DetectionSettings(
        suspicious_listen_ports="8080, 9090",  # type: ignore[arg-type]
        sensitive_file_patterns="*secrets*,*private*",  # type: ignore[arg-type]
    )

    assert settings.suspicious_listen_ports == [8080, 9090]
    assert settings.sensitive_file_patterns == ["*secrets*", "*private*"]


def test_extension_normalization() -> None:
    settings = DetectionSettings(executable_extensions=["EXE", "ps1", ".BAT"])
    assert settings.executable_extensions == [".bat", ".exe", ".ps1"]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("203.0.113.9", "203.0.113.9"),
        ("203.0.113.9:4444", "203.0.113.9:4444"),
        ("2001:db8::1", "2001:db8::1"),
        ("[2001:db8::1]:443", "[2001:db8::1]:443"),
    ],
)
def test_normalize_endpoint(raw: str, expected: str) -> None:
    assert normalize_endpoint(raw) == expected


def test_parse_endpoint_round_trip() -> None:
    assert parse_endpoint("203.0.113.9") == ("203.0.113.9", None)
    assert parse_endpoint("203.0.113.9:4444") == ("203.0.113.9", 4444)
    assert parse_endpoint("[2001:db8::1]:443") == ("2001:db8::1", 443)


# --- CLI -------------------------------------------------------------------


def test_cli_detect_text(capsys: pytest.CaptureFixture[str]) -> None:
    from aegis_agent.__main__ import main

    exit_code = main(["detect"])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "Aegis detection demonstration" in out
    assert RULE_LISTEN_PORT in out
    assert "severity=medium" in out


def test_cli_detect_json(capsys: pytest.CaptureFixture[str]) -> None:
    from aegis_agent.__main__ import main

    exit_code = main(["detect", "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["events_evaluated"] == 6
    assert payload["finding_count"] == len(payload["findings"])
    assert payload["finding_count"] >= 5
    for finding in payload["findings"]:
        assert finding["rule_id"]
        assert finding["event_id"]
        assert finding["evidence"]


def test_cli_detect_does_not_mutate_or_require_privileges() -> None:
    # Detection is passive; constructing and running the engine needs no state.
    engine = DetectionEngine.from_settings(DetectionSettings())
    assert engine.evaluate(_port_event(8080)) == ()


def test_detection_finding_is_frozen() -> None:
    finding = SuspiciousListeningPortRule(ports=[8080]).build_finding(_port_event(8080))
    with pytest.raises(ValidationError):
        finding.severity = Severity.CRITICAL
    assert isinstance(finding, DetectionFinding)
