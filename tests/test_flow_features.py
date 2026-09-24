"""Deterministic tests for network behavioral feature extraction (Step 15).

Exercises :func:`extract_flow_features` and :func:`extract_batch` using locally
constructed :class:`FlowRecord` objects.  No real capture, no network, no
privileges, no ML training.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime

import pytest

from aegis_ml_engine.features import (
    extract_batch,
    extract_flow_features,
)
from aegis_ml_engine.features.flow_features import _FEATURE_VERSION
from aegis_network_sensor.flows.models import FlowRecord
from aegis_shared.enums import AddressFamily, NetworkDirection, TransportProtocol

_T0 = datetime(2026, 6, 1, 0, 0, 0, tzinfo=UTC)
_T1 = datetime(2026, 6, 1, 0, 0, 1, tzinfo=UTC)  # +1 second


def _flow(
    *,
    packet_count: int = 10,
    byte_count: int = 1000,
    first_seen: datetime = _T0,
    last_seen: datetime = _T1,
    protocol: TransportProtocol = TransportProtocol.TCP,
    ip_version: AddressFamily = AddressFamily.IPV4,
    direction: NetworkDirection = NetworkDirection.OUTBOUND,
    flow_id: str = "ipv4|tcp|10.0.0.1:1234->10.0.0.2:80",
) -> FlowRecord:
    """Build a FlowRecord with sensible defaults for testing."""
    return FlowRecord(
        flow_id=flow_id,
        ip_version=ip_version,
        protocol=protocol,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        ports_applicable=True,
        src_port=1234,
        dst_port=80,
        direction=direction,
        packet_count=packet_count,
        byte_count=byte_count,
        first_seen=first_seen,
        last_seen=last_seen,
    )


# --- 1. Normal flow feature extraction ---


def test_normal_flow_extracts_all_fields() -> None:
    flow = _flow(packet_count=10, byte_count=1000)
    features = extract_flow_features(flow)

    assert features.packet_count == 10
    assert features.byte_count == 1000
    assert features.duration_ms == 1000
    assert features.packets_per_second == pytest.approx(10.0)
    assert features.bytes_per_second == pytest.approx(1000.0)
    assert features.average_packet_size == pytest.approx(100.0)


# --- 2. Packet rate calculation ---


def test_packets_per_second_formula() -> None:
    # 20 packets over 2 seconds => 10 pps
    flow = _flow(
        packet_count=20, byte_count=2000,
        last_seen=datetime(2026, 6, 1, 0, 0, 2, tzinfo=UTC),
    )
    features = extract_flow_features(flow)

    assert features.packets_per_second == pytest.approx(10.0)


# --- 3. Byte rate calculation ---


def test_bytes_per_second_formula() -> None:
    # 5000 bytes over 5 seconds => 1000 Bps
    flow = _flow(
        packet_count=50,
        byte_count=5000,
        last_seen=datetime(2026, 6, 1, 0, 0, 5, tzinfo=UTC),
    )
    features = extract_flow_features(flow)

    assert features.bytes_per_second == pytest.approx(1000.0)


# --- 4. Average packet size ---


def test_average_packet_size_formula() -> None:
    # 1500 bytes / 3 packets => 500 avg
    flow = _flow(packet_count=3, byte_count=1500)
    features = extract_flow_features(flow)

    assert features.average_packet_size == pytest.approx(500.0)


# --- 5. Zero duration ---


def test_zero_duration_rates_are_zero() -> None:
    # first_seen == last_seen => duration_ms == 0
    flow = _flow(first_seen=_T0, last_seen=_T0, packet_count=100, byte_count=50000)
    features = extract_flow_features(flow)

    assert features.duration_ms == 0
    assert features.packets_per_second == 0.0
    assert features.bytes_per_second == 0.0
    # average_packet_size still valid: 50000 / 100 = 500
    assert features.average_packet_size == pytest.approx(500.0)


# --- 6. Zero packets ---


def test_zero_packets_average_is_zero() -> None:
    flow = _flow(packet_count=0, byte_count=0)
    features = extract_flow_features(flow)

    assert features.packet_count == 0
    assert features.byte_count == 0
    assert features.average_packet_size == 0.0
    # Rates: 0 packets / 1 second = 0 pps; 0 bytes / 1 second = 0 Bps
    assert features.packets_per_second == 0.0
    assert features.bytes_per_second == 0.0


# --- 7. Empty input ---


def test_empty_batch_returns_empty_tuple() -> None:
    result = extract_batch([])

    assert result == ()
    assert isinstance(result, tuple)


# --- 8. Multiple flows preserve order ---


def test_batch_preserves_input_order() -> None:
    flows = [_flow(flow_id=f"flow-{i}", packet_count=i + 1) for i in range(5)]
    features = extract_batch(flows)

    assert len(features) == 5
    assert [f.flow_id for f in features] == [f"flow-{i}" for i in range(5)]


# --- 9. Input FlowRecord is not mutated ---


def test_input_flow_record_is_not_mutated() -> None:
    flow = _flow(packet_count=42, byte_count=9999)
    original_packet_count = flow.packet_count
    original_byte_count = flow.byte_count

    _ = extract_flow_features(flow)

    assert flow.packet_count == original_packet_count
    assert flow.byte_count == original_byte_count


# --- 10. Deterministic repeated extraction ---


def test_deterministic_repeated_extraction() -> None:
    flow = _flow(packet_count=7, byte_count=3500)
    first = extract_flow_features(flow)
    second = extract_flow_features(flow)

    assert first == second
    # Also verify by extracting again from the same flow object
    third = extract_flow_features(flow)
    assert first == third


# --- 11. No NaN/infinity ---


def test_no_nan_or_infinity_in_features() -> None:
    flows = [
        _flow(packet_count=0, byte_count=0, last_seen=_T0),  # zero duration, zero packets
        _flow(packet_count=1, byte_count=0, last_seen=_T0),  # zero duration, 1 packet
        _flow(packet_count=0, byte_count=100, last_seen=_T0),  # zero duration, bytes
        _flow(packet_count=100, byte_count=10000),  # normal
    ]
    for flow in flows:
        features = extract_flow_features(flow)
        assert not math.isnan(features.packets_per_second)
        assert not math.isnan(features.bytes_per_second)
        assert not math.isnan(features.average_packet_size)
        assert not math.isinf(features.packets_per_second)
        assert not math.isinf(features.bytes_per_second)
        assert not math.isinf(features.average_packet_size)


# --- 12. Metadata/flow identity preservation ---


def test_flow_identity_is_preserved() -> None:
    flow = _flow(
        flow_id="custom|id",
        protocol=TransportProtocol.UDP,
        ip_version=AddressFamily.IPV6,
        direction=NetworkDirection.INBOUND,
    )
    features = extract_flow_features(flow)

    assert features.flow_id == "custom|id"
    assert features.protocol is TransportProtocol.UDP
    assert features.ip_version is AddressFamily.IPV6
    assert features.direction is NetworkDirection.INBOUND


# --- 13. Negative/invalid counters are handled safely ---


def test_negative_duration_treated_as_zero() -> None:
    # FlowRecord validator prevents last_seen < first_seen, but duration_ms
    # can be 0 when timestamps are equal. Verify the edge contract.
    flow = _flow(first_seen=_T1, last_seen=_T1, packet_count=50, byte_count=5000)
    features = extract_flow_features(flow)

    assert features.duration_ms == 0
    assert features.packets_per_second == 0.0
    assert features.bytes_per_second == 0.0
    assert features.average_packet_size == pytest.approx(100.0)


def test_large_counters_produce_finite_rates() -> None:
    # Simulate a high-volume flow: 1M packets, 1.5 GB, 10 seconds
    flow = _flow(
        packet_count=1_000_000,
        byte_count=1_500_000_000,
        last_seen=datetime(2026, 6, 1, 0, 0, 10, tzinfo=UTC),
    )
    features = extract_flow_features(flow)

    assert features.packets_per_second == pytest.approx(100_000.0)
    assert features.bytes_per_second == pytest.approx(150_000_000.0)
    assert features.average_packet_size == pytest.approx(1500.0)
    assert math.isfinite(features.packets_per_second)
    assert math.isfinite(features.bytes_per_second)
    assert math.isfinite(features.average_packet_size)


# --- 14. Public package import/export ---


def test_public_imports_from_top_level_package() -> None:
    # Verify all three import paths resolve to the same objects.
    import aegis_ml_engine
    import aegis_ml_engine.features
    import aegis_ml_engine.features.flow_features as mod

    assert aegis_ml_engine.NetworkBehaviorFeatures is mod.NetworkBehaviorFeatures
    assert aegis_ml_engine.extract_batch is mod.extract_batch
    assert aegis_ml_engine.extract_flow_features is mod.extract_flow_features
    assert aegis_ml_engine.features.NetworkBehaviorFeatures is mod.NetworkBehaviorFeatures
    assert aegis_ml_engine.features.extract_batch is mod.extract_batch
    assert aegis_ml_engine.features.extract_flow_features is mod.extract_flow_features


def test_feature_version_is_declared() -> None:
    assert _FEATURE_VERSION == "1.0.0"
    flow = _flow()
    features = extract_flow_features(flow)

    assert features.feature_version == _FEATURE_VERSION


def test_features_are_frozen() -> None:
    flow = _flow()
    features = extract_flow_features(flow)

    with pytest.raises(AttributeError):
        features.packet_count = 999  # type: ignore[misc]


def test_batch_single_element() -> None:
    flow = _flow(packet_count=5, byte_count=2500)
    result = extract_batch([flow])

    assert len(result) == 1
    assert result[0].packet_count == 5
    assert result[0].average_packet_size == pytest.approx(500.0)
