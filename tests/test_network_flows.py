"""Deterministic tests for network flow telemetry (Step 11).

Flow aggregation is exercised with locally constructed :class:`PacketRecord`
objects (and in-memory Scapy packets for the sensor integration test). No real
capture, no network, no privileges.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

pytest.importorskip("scapy", reason="sensor extra not installed")

from scapy.layers.inet import IP, TCP

from aegis_network_sensor.config import SensorSettings
from aegis_network_sensor.flows import (
    DEFAULT_MAX_FLOWS,
    FlowAggregator,
    FlowRecord,
    build_flow_event,
)
from aegis_network_sensor.models import PacketRecord
from aegis_network_sensor.normalization import compute_flow_id
from aegis_network_sensor.sensor import NetworkSensor
from aegis_shared.enums import (
    AddressFamily,
    EventCategory,
    EventType,
    NetworkDirection,
    SourceKind,
    TransportProtocol,
)
from aegis_shared.events import SourceRef

_T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
_T1 = datetime(2026, 1, 1, 0, 0, 1, tzinfo=UTC)

_FLOW_FIELDS = {
    "flow_id",
    "ip_version",
    "protocol",
    "src_ip",
    "dst_ip",
    "ports_applicable",
    "src_port",
    "dst_port",
    "direction",
    "interface",
    "sni",
    "packet_count",
    "byte_count",
    "first_seen",
    "last_seen",
}


def _packet(**overrides: object) -> PacketRecord:
    values: dict[str, object] = {
        "timestamp": _T0,
        "ip_version": AddressFamily.IPV4,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "protocol": TransportProtocol.TCP,
        "ports_applicable": True,
        "src_port": 1234,
        "dst_port": 80,
        "packet_length": 100,
        "direction": NetworkDirection.OUTBOUND,
    }
    values.update(overrides)
    return PacketRecord(**values)  # type: ignore[arg-type]


# --- Aggregation -----------------------------------------------------------


def test_same_five_tuple_aggregates_into_one_flow() -> None:
    aggregator = FlowAggregator()

    aggregator.observe(_packet())
    aggregator.observe(_packet())
    flow = aggregator.observe(_packet())

    assert aggregator.flow_count == 1
    assert flow.packet_count == 3


def test_packet_and_byte_counters_are_correct() -> None:
    aggregator = FlowAggregator()

    aggregator.observe(_packet(packet_length=100))
    aggregator.observe(_packet(packet_length=250))
    flow = aggregator.observe(_packet(packet_length=50))

    assert flow.packet_count == 3
    assert flow.byte_count == 400


def test_unknown_packet_length_counts_as_zero_bytes() -> None:
    aggregator = FlowAggregator()

    aggregator.observe(_packet(packet_length=None))
    flow = aggregator.observe(_packet(packet_length=None))

    assert flow.packet_count == 2
    assert flow.byte_count == 0


def test_different_tuples_create_separate_flows() -> None:
    aggregator = FlowAggregator()

    aggregator.observe(_packet())
    aggregator.observe(_packet(dst_port=443))  # different destination port
    aggregator.observe(_packet(src_ip="10.0.0.9"))  # different source
    aggregator.observe(_packet(dst_ip="10.0.0.9"))  # different destination

    assert aggregator.flow_count == 4


def test_tcp_and_udp_are_separate_flows() -> None:
    aggregator = FlowAggregator()

    aggregator.observe(_packet(protocol=TransportProtocol.TCP, dst_port=53))
    aggregator.observe(_packet(protocol=TransportProtocol.UDP, dst_port=53))

    assert aggregator.flow_count == 2


def test_icmp_flow_has_no_ports() -> None:
    aggregator = FlowAggregator()

    flow = aggregator.observe(
        _packet(
            protocol=TransportProtocol.ICMP,
            ports_applicable=False,
            src_port=None,
            dst_port=None,
        )
    )

    assert flow.ports_applicable is False
    assert flow.src_port is None
    assert flow.dst_port is None


# --- Address family --------------------------------------------------------


def test_ipv4_flow_identity() -> None:
    aggregator = FlowAggregator()

    flow = aggregator.observe(_packet())

    assert flow.ip_version is AddressFamily.IPV4
    assert flow.flow_id.startswith("ipv4|tcp|")
    assert flow.flow_id.endswith("10.0.0.1:1234->10.0.0.2:80")


def test_ipv6_flow_identity_is_unambiguous() -> None:
    aggregator = FlowAggregator()

    flow = aggregator.observe(
        _packet(
            ip_version=AddressFamily.IPV6,
            src_ip="2001:db8::1",
            dst_ip="2001:db8::2",
            src_port=443,
            dst_port=51000,
        )
    )

    assert flow.ip_version is AddressFamily.IPV6
    assert flow.flow_id.startswith("ipv6|tcp|")
    assert "[2001:db8::1]:443" in flow.flow_id
    assert "[2001:db8::2]:51000" in flow.flow_id


def test_ipv4_and_ipv6_same_tuple_are_separate_flows() -> None:
    aggregator = FlowAggregator()

    aggregator.observe(_packet(ip_version=AddressFamily.IPV4))
    aggregator.observe(
        _packet(
            ip_version=AddressFamily.IPV6,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
        )
    )

    assert aggregator.flow_count == 2


# --- Direction -------------------------------------------------------------


def test_direction_is_preserved_when_determinable() -> None:
    aggregator = FlowAggregator()

    flow = aggregator.observe(_packet(direction=NetworkDirection.OUTBOUND))

    assert flow.direction is NetworkDirection.OUTBOUND


def test_direction_upgrades_from_unknown_to_determinable() -> None:
    aggregator = FlowAggregator()

    aggregator.observe(_packet(direction=NetworkDirection.UNKNOWN))
    flow = aggregator.observe(_packet(direction=NetworkDirection.INBOUND, timestamp=_T1))

    assert flow.direction is NetworkDirection.INBOUND


# --- Identity & timestamps -------------------------------------------------


def test_flow_identity_is_deterministic() -> None:
    first = FlowAggregator().observe(_packet())
    second = FlowAggregator().observe(_packet())

    assert first.flow_id == second.flow_id
    assert first.flow_id == compute_flow_id(
        ip_version=AddressFamily.IPV4,
        protocol=TransportProtocol.TCP,
        src_ip="10.0.0.1",
        src_port=1234,
        dst_ip="10.0.0.2",
        dst_port=80,
    )


def test_explicit_flow_id_is_honoured() -> None:
    flow = FlowAggregator().observe(_packet(flow_id="custom|flow|id"))

    assert flow.flow_id == "custom|flow|id"


def test_first_and_last_seen_track_extremes() -> None:
    aggregator = FlowAggregator()

    aggregator.observe(_packet(timestamp=_T1))
    flow = aggregator.observe(_packet(timestamp=_T0))

    assert flow.first_seen == _T0
    assert flow.last_seen == _T1
    assert flow.duration_ms == 1000


def test_snapshot_preserves_observation_order() -> None:
    aggregator = FlowAggregator()

    aggregator.observe(_packet(dst_port=1))
    aggregator.observe(_packet(dst_port=2))

    assert [flow.dst_port for flow in aggregator.snapshot()] == [1, 2]


# --- Boundedness -----------------------------------------------------------


def test_flow_state_is_bounded() -> None:
    aggregator = FlowAggregator(max_flows=2)

    aggregator.observe(_packet(dst_port=1))
    aggregator.observe(_packet(dst_port=2))
    aggregator.observe(_packet(dst_port=3))

    assert aggregator.flow_count == 2
    assert aggregator.evicted_count == 1
    # The oldest-observed flow (dst_port 1) was evicted.
    assert {flow.dst_port for flow in aggregator.snapshot()} == {2, 3}


def test_clear_drops_flows_but_keeps_eviction_counter() -> None:
    aggregator = FlowAggregator(max_flows=1)
    aggregator.observe(_packet(dst_port=1))
    aggregator.observe(_packet(dst_port=2))

    aggregator.clear()

    assert aggregator.flow_count == 0
    assert aggregator.evicted_count == 1


def test_invalid_max_flows_is_rejected() -> None:
    with pytest.raises(ValueError, match="max_flows"):
        FlowAggregator(max_flows=0)


def test_default_capacity_is_positive() -> None:
    assert DEFAULT_MAX_FLOWS >= 1


# --- Payload safety --------------------------------------------------------


def test_no_payload_is_stored() -> None:
    assert set(FlowRecord.model_fields) == _FLOW_FIELDS
    assert "payload" not in FlowRecord.model_fields
    assert "raw" not in FlowRecord.model_fields


def test_flow_serialisation_contains_only_metadata() -> None:
    flow = FlowAggregator().observe(_packet())

    dumped = flow.to_json_dict()

    assert set(dumped) == _FLOW_FIELDS
    assert dumped["packet_count"] == 1
    assert dumped["byte_count"] == 100


# --- Canonical event mapping ----------------------------------------------


def test_flow_maps_to_canonical_event() -> None:
    aggregator = FlowAggregator()
    aggregator.observe(_packet(packet_length=100))
    flow = aggregator.observe(_packet(packet_length=100, timestamp=_T1))

    event = build_flow_event(flow, source=SourceRef(kind=SourceKind.SENSOR, id="sensor-test"))

    assert event.event_type is EventType.FLOW_SUMMARY
    assert event.category is EventCategory.NETWORK
    assert event.network is not None
    assert event.network.flow_id == flow.flow_id
    assert event.network.packets_sent == 2
    assert event.network.bytes_sent == 200
    assert event.network.duration_ms == 1000


# --- Sensor integration ----------------------------------------------------


def test_sensor_aggregates_flows_from_processed_packets() -> None:
    sensor = NetworkSensor(SensorSettings(interface="eth0", capture_enabled=False))
    packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80)

    sensor.process_packets([packet, packet])

    flows = sensor.flows
    assert len(flows) == 1
    assert flows[0].packet_count == 2
    assert flows[0].protocol is TransportProtocol.TCP


def test_sensor_flow_aggregator_is_bounded_and_injectable() -> None:
    injected = FlowAggregator(max_flows=1)
    sensor = NetworkSensor(
        SensorSettings(interface="eth0", capture_enabled=False),
        flow_aggregator=injected,
    )

    sensor.process_packets(
        [
            IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=1),
            IP(src="10.0.0.3", dst="10.0.0.4") / TCP(sport=2, dport=2),
        ]
    )

    assert sensor.flow_aggregator is injected
    assert sensor.flow_aggregator.flow_count == 1
    assert sensor.flow_aggregator.evicted_count == 1


# --- drain_changed (batching) ----------------------------------------------


def test_drain_changed_returns_only_updated_flows() -> None:
    aggregator = FlowAggregator()

    aggregator.observe(_packet(dst_port=1))
    aggregator.observe(_packet(dst_port=2))

    changed = aggregator.drain_changed()
    assert len(changed) == 2
    assert {f.dst_port for f in changed} == {1, 2}

    # Second drain returns nothing — no new packets arrived.
    assert aggregator.drain_changed() == ()


def test_drain_changed_returns_only_newly_observed_flows() -> None:
    aggregator = FlowAggregator()

    aggregator.observe(_packet(dst_port=1))
    aggregator.drain_changed()  # drain first batch

    aggregator.observe(_packet(dst_port=1))  # same flow, new packet
    aggregator.observe(_packet(dst_port=3))  # brand-new flow

    changed = aggregator.drain_changed()
    assert len(changed) == 2
    ports = {f.dst_port for f in changed}
    assert 1 in ports
    assert 3 in ports


def test_drain_changed_clears_on_clear() -> None:
    aggregator = FlowAggregator()
    aggregator.observe(_packet())
    aggregator.clear()
    assert aggregator.drain_changed() == ()
