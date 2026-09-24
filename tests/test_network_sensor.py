"""Deterministic tests for the network sensor foundation.

Scapy packets are constructed in memory; no test opens a real interface, needs
the network, or requires privileges. Skipped when the sensor extra is absent.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

pytest.importorskip("scapy", reason="sensor extra not installed")

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
from scapy.packet import Raw

from aegis_network_sensor.__main__ import main
from aegis_network_sensor.config import SensorSettings
from aegis_network_sensor.events import build_network_event, describe_packet
from aegis_network_sensor.models import PacketRecord, format_ip_endpoint
from aegis_network_sensor.normalization import (
    compute_flow_id,
    detect_direction,
    normalize_packet,
)
from aegis_network_sensor.pipeline import NetworkEventPipeline
from aegis_network_sensor.sensor import NetworkSensor, SensorDisabledError
from aegis_shared.enums import (
    AddressFamily,
    EventCategory,
    EventType,
    NetworkDirection,
    Platform,
    SourceKind,
    TransportProtocol,
)
from aegis_shared.events import HostRef, SourceRef
from aegis_shared.pipeline import validate_event

_TS = datetime(2026, 1, 1, tzinfo=UTC)


def _ipv4_tcp(
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    sport: int = 1234,
    dport: int = 80,
    payload: bytes = b"",
) -> object:
    packet = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport)
    return packet / Raw(payload) if payload else packet


def _ipv4_udp(
    src: str = "10.0.0.1", dst: str = "10.0.0.2", sport: int = 5353, dport: int = 5353
) -> object:
    return IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)


def _ipv6_tcp(
    src: str = "2001:db8::1",
    dst: str = "2001:db8::2",
    sport: int = 443,
    dport: int = 51000,
) -> object:
    return IPv6(src=src, dst=dst) / TCP(sport=sport, dport=dport)


def _ipv6_udp(
    src: str = "2001:db8::1", dst: str = "2001:db8::2", sport: int = 5000, dport: int = 5001
) -> object:
    return IPv6(src=src, dst=dst) / UDP(sport=sport, dport=dport)


def _source() -> SourceRef:
    return SourceRef(kind=SourceKind.SENSOR, id="sensor-test")


def _host() -> HostRef:
    return HostRef(host_id="sensor-host", platform=Platform.LINUX)


# --- Protocol normalization ------------------------------------------------


def test_ipv4_tcp_normalization() -> None:
    record = normalize_packet(_ipv4_tcp(), interface="eth0", timestamp=_TS)

    assert record is not None
    assert record.protocol is TransportProtocol.TCP
    assert record.ip_version is AddressFamily.IPV4
    assert record.src_ip == "10.0.0.1"
    assert record.dst_ip == "10.0.0.2"
    assert record.ports_applicable is True
    assert record.src_port == 1234
    assert record.dst_port == 80
    assert record.interface == "eth0"
    assert record.direction is NetworkDirection.UNKNOWN


def test_ipv4_udp_normalization() -> None:
    record = normalize_packet(_ipv4_udp(), timestamp=_TS)

    assert record is not None
    assert record.protocol is TransportProtocol.UDP
    assert record.src_port == 5353
    assert record.dst_port == 5353


def test_ipv4_icmp_normalization() -> None:
    record = normalize_packet(IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(), timestamp=_TS)

    assert record is not None
    assert record.protocol is TransportProtocol.ICMP
    assert record.ports_applicable is False
    assert record.src_port is None
    assert record.dst_port is None


def test_ipv6_tcp_normalization() -> None:
    record = normalize_packet(_ipv6_tcp(), timestamp=_TS)

    assert record is not None
    assert record.ip_version is AddressFamily.IPV6
    assert record.protocol is TransportProtocol.TCP
    assert record.src_ip == "2001:db8::1"
    assert record.dst_port == 51000


def test_ipv6_udp_normalization() -> None:
    record = normalize_packet(_ipv6_udp(), timestamp=_TS)

    assert record is not None
    assert record.ip_version is AddressFamily.IPV6
    assert record.protocol is TransportProtocol.UDP


def test_ipv6_icmpv6_normalization() -> None:
    packet = IPv6(src="2001:db8::1", dst="2001:db8::2") / ICMPv6EchoRequest()
    record = normalize_packet(packet, timestamp=_TS)

    assert record is not None
    assert record.ip_version is AddressFamily.IPV6
    assert record.protocol is TransportProtocol.ICMP
    assert record.ports_applicable is False
    assert record.src_port is None


def test_unknown_packet_is_skipped() -> None:
    assert normalize_packet(Raw(b"not-ip"), timestamp=_TS) is None


def test_invalid_packet_handling() -> None:
    assert normalize_packet(None) is None
    assert normalize_packet("not-a-packet") is None
    assert normalize_packet(object()) is None


# --- Metadata --------------------------------------------------------------


def test_packet_length_is_observed() -> None:
    packet = _ipv4_tcp()
    record = normalize_packet(packet, timestamp=_TS)

    assert record is not None
    assert record.packet_length == len(packet)  # type: ignore[arg-type]


def test_timestamp_override_and_default() -> None:
    explicit = normalize_packet(_ipv4_tcp(), timestamp=_TS)
    assert explicit is not None and explicit.timestamp == _TS

    default = normalize_packet(_ipv4_tcp())
    assert default is not None
    assert default.timestamp.tzinfo is not None


def test_packet_record_rejects_naive_timestamp() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        PacketRecord(timestamp=datetime(2026, 1, 1))


def test_interface_metadata_is_preserved() -> None:
    record = normalize_packet(_ipv4_tcp(), interface="wlan0", timestamp=_TS)

    assert record is not None
    assert record.interface == "wlan0"


def test_packet_record_rejects_ports_when_not_applicable() -> None:
    with pytest.raises(ValueError, match="ports_applicable"):
        PacketRecord(ports_applicable=False, src_port=80)


# --- Direction -------------------------------------------------------------


def test_direction_unknown_without_local_addresses() -> None:
    record = normalize_packet(_ipv4_tcp(), timestamp=_TS)
    assert record is not None
    assert record.direction is NetworkDirection.UNKNOWN


def test_direction_classified_from_local_addresses() -> None:
    outbound = normalize_packet(
        _ipv4_tcp(src="10.0.0.5", dst="8.8.8.8"), local_addresses={"10.0.0.5"}, timestamp=_TS
    )
    inbound = normalize_packet(
        _ipv4_tcp(src="8.8.8.8", dst="10.0.0.5"), local_addresses={"10.0.0.5"}, timestamp=_TS
    )

    assert outbound is not None and outbound.direction is NetworkDirection.OUTBOUND
    assert inbound is not None and inbound.direction is NetworkDirection.INBOUND


def test_direction_unknown_when_both_endpoints_local() -> None:
    assert (
        detect_direction("10.0.0.5", "10.0.0.6", {"10.0.0.5", "10.0.0.6"})
        is NetworkDirection.UNKNOWN
    )


# --- Flow id ---------------------------------------------------------------


def test_flow_id_is_deterministic() -> None:
    first = normalize_packet(_ipv4_tcp(), timestamp=_TS)
    second = normalize_packet(_ipv4_tcp(), timestamp=_TS)
    other = normalize_packet(_ipv4_tcp(dport=81), timestamp=_TS)

    assert first is not None and second is not None and other is not None
    assert first.flow_id == second.flow_id
    assert first.flow_id != other.flow_id


def test_flow_id_brackets_ipv6_endpoints() -> None:
    flow_id = compute_flow_id(
        ip_version=AddressFamily.IPV6,
        protocol=TransportProtocol.TCP,
        src_ip="2001:db8::1",
        src_port=443,
        dst_ip="2001:db8::2",
        dst_port=51000,
    )

    assert "[2001:db8::1]:443" in flow_id
    assert "[2001:db8::2]:51000" in flow_id


@pytest.mark.parametrize(
    ("address", "port", "version", "expected"),
    [
        ("10.0.0.1", 80, AddressFamily.IPV4, "10.0.0.1:80"),
        ("2001:db8::1", 443, AddressFamily.IPV6, "[2001:db8::1]:443"),
        ("10.0.0.1", None, AddressFamily.IPV4, "10.0.0.1"),
        (None, None, AddressFamily.IPV4, "-"),
    ],
)
def test_format_ip_endpoint(
    address: str | None, port: int | None, version: AddressFamily, expected: str
) -> None:
    assert format_ip_endpoint(address, port, version) == expected


# --- Canonical event -------------------------------------------------------


def test_build_network_event_uses_canonical_schema() -> None:
    record = normalize_packet(_ipv4_tcp(), interface="eth0", timestamp=_TS)
    assert record is not None

    event = build_network_event(record, source=_source())

    assert event.event_type is EventType.NETWORK_PACKET_OBSERVED
    assert event.category is EventCategory.NETWORK
    assert event.source.kind is SourceKind.SENSOR
    assert event.network is not None
    assert event.network.src_ip == "10.0.0.1"
    assert event.network.dst_port == 80
    assert event.network.interface == "eth0"
    assert event.network.ip_version is AddressFamily.IPV4
    assert event.network.flow_id == record.flow_id
    assert validate_event(event).valid is True


def test_validation_rejects_missing_network_context() -> None:
    record = normalize_packet(_ipv4_tcp(), timestamp=_TS)
    assert record is not None
    event = build_network_event(record, source=_source())

    invalid = event.model_copy(update={"network": None})

    assert validate_event(invalid).valid is False


def test_describe_packet_brackets_ipv6() -> None:
    record = normalize_packet(_ipv6_tcp(), timestamp=_TS)
    assert record is not None

    assert "[2001:db8::1]:443" in describe_packet(record)


# --- Privacy ---------------------------------------------------------------


def test_no_payload_is_retained() -> None:
    record = normalize_packet(_ipv4_tcp(payload=b"SECRET-TOKEN-1234"), timestamp=_TS)
    assert record is not None

    payload = record.to_json_dict()

    assert "payload" not in PacketRecord.model_fields
    assert "raw" not in PacketRecord.model_fields
    assert "SECRET-TOKEN-1234" not in json.dumps(payload)


# --- Sensor / capture ------------------------------------------------------


def test_process_packets_submits_events() -> None:
    sensor = NetworkSensor(SensorSettings(interface="eth0", capture_enabled=False))

    summary = sensor.process_packets([_ipv4_tcp(), _ipv4_udp()])

    assert summary.observed == 2
    assert summary.normalized == 2
    assert summary.accepted == 2
    assert summary.skipped == 0
    events = sensor.drain()
    assert {envelope.event.event_type for envelope in events} == {EventType.NETWORK_PACKET_OBSERVED}


def test_capture_disabled_raises_without_capturing(monkeypatch: pytest.MonkeyPatch) -> None:
    sensor = NetworkSensor(SensorSettings(interface="eth0", capture_enabled=False))

    class _BoomCapture:
        def __init__(self, *args: object, **kwargs: object) -> None:
            raise AssertionError("capture must not be attempted when disabled")

    monkeypatch.setattr("aegis_network_sensor.sensor.PacketCapture", _BoomCapture)

    with pytest.raises(SensorDisabledError):
        sensor.capture()


def test_capture_is_bounded_by_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = SensorSettings(interface="eth0", capture_enabled=True, max_packets_per_run=3)
    sensor = NetworkSensor(settings)
    captured: dict[str, object] = {}

    class _FakeCapture:
        def __init__(self, **kwargs: object) -> None:
            captured["init"] = kwargs

        def capture(self, *, count: int, on_packet: object, timeout: object = None) -> int:
            captured["count"] = count
            on_packet(_ipv4_tcp())  # type: ignore[operator]
            return 1

    monkeypatch.setattr("aegis_network_sensor.sensor.PacketCapture", _FakeCapture)

    summary = sensor.capture(count=100)  # requested 100, capped to 3

    assert captured["count"] == 3
    assert summary.observed == 1
    assert summary.accepted == 1


def test_oversized_packet_is_skipped() -> None:
    sensor = NetworkSensor(
        SensorSettings(interface="eth0", capture_enabled=False, max_packet_bytes=64)
    )

    summary = sensor.process_packets([_ipv4_tcp(), _ipv4_tcp(payload=b"x" * 200)])

    assert summary.observed == 2
    assert summary.normalized == 1
    assert summary.skipped == 1


def test_network_pipeline_buffer_is_bounded() -> None:
    pipeline = NetworkEventPipeline(max_events=2)
    records = [normalize_packet(_ipv4_tcp(sport=1000 + index), timestamp=_TS) for index in range(5)]
    valid_records = [record for record in records if record is not None]

    pipeline.submit_packets(valid_records, source=_source())

    assert pipeline.stats.accepted == 5
    assert pipeline.stats.dropped == 3
    assert len(pipeline) == 2


def test_sensor_source_ref() -> None:
    assert NetworkSensor(SensorSettings(sensor_id="sensor-42")).source_ref().id == "sensor-42"
    assert NetworkSensor(SensorSettings(interface="eth0")).source_ref().id == "sensor-eth0"


# --- Configuration ---------------------------------------------------------


def test_configuration_defaults_and_validation() -> None:
    default = SensorSettings(capture_enabled=False, interface="")
    assert default.capture_enabled is False
    assert default.interface == ""

    with pytest.raises(ValueError, match="interface"):
        SensorSettings(capture_enabled=True, interface="")

    enabled = SensorSettings(capture_enabled=True, interface="eth0")
    assert enabled.interface == "eth0"

    with pytest.raises(ValueError):
        SensorSettings(max_packets_per_run=0)
    with pytest.raises(ValueError):
        SensorSettings(max_packet_bytes=1)


def test_default_bpf_filter_drops_noise() -> None:
    settings = SensorSettings(capture_enabled=False, interface="")
    assert "arp" in settings.capture_filter
    assert "5353" in settings.capture_filter  # mDNS
    assert "1900" in settings.capture_filter  # SSDP
    assert "(ip or ip6)" in settings.capture_filter


def test_bpf_filter_is_overridable() -> None:
    settings = SensorSettings(
        capture_enabled=False, interface="", capture_filter="tcp port 443"
    )
    assert settings.capture_filter == "tcp port 443"


def test_bpf_filter_reaches_capture(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = SensorSettings(
        interface="eth0",
        capture_enabled=True,
        capture_filter="tcp port 443",
    )
    sensor = NetworkSensor(settings)
    captured: dict[str, object] = {}

    class _FakeCapture:
        def __init__(self, **kwargs: object) -> None:
            captured["init"] = kwargs

        def capture(self, *, count: int, on_packet: object, timeout: object = None) -> int:
            return 0

    monkeypatch.setattr("aegis_network_sensor.sensor.PacketCapture", _FakeCapture)
    sensor.capture(count=1)

    init_kwargs = captured["init"]
    assert isinstance(init_kwargs, dict)
    assert init_kwargs.get("packet_filter") == "tcp port 443"


# --- CLI -------------------------------------------------------------------


def test_cli_interfaces_text(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("aegis_network_sensor.capture.list_interfaces", lambda: ("eth0", "lo"))

    exit_code = main(["interfaces"])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "eth0" in out
    assert "lo" in out


def test_cli_interfaces_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("aegis_network_sensor.capture.list_interfaces", lambda: ("eth0",))

    exit_code = main(["interfaces", "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["interfaces"] == ["eth0"]


def test_cli_capture_disabled_does_not_capture(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "aegis_network_sensor.__main__.get_sensor_settings",
        lambda: SensorSettings(interface="eth0", capture_enabled=False),
    )

    exit_code = main(["capture"])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "disabled" in out


def test_cli_status(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(
        "aegis_network_sensor.__main__.get_sensor_settings",
        lambda: SensorSettings(),
    )

    exit_code = main([])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "interfaces" in out
