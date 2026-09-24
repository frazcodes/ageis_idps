"""Focused tests for the asset / network-identity baseline (Step 26).

Exercises the bounded :class:`AssetRegistry`, the :class:`NetworkBaseline`, the
runtime integration and the desktop Assets view. Telemetry is constructed
directly or replayed through the existing sensor path; only metadata is used.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest

from aegis_shared.assets import (
    AssetRegistry,
    AssetSettings,
    get_active_asset_snapshot,
)
from aegis_shared.baseline import NetworkBaseline, ObservationKind
from aegis_shared.enums import NetworkDirection, Platform, TransportProtocol
from aegis_shared.pipeline import clear_active_pipeline
from aegis_shared.risk import clear_active_risk_engine

_TS = datetime(2026, 6, 1, 10, 0, 0, tzinfo=UTC)


def _ts(seconds: int = 0) -> datetime:
    return _TS + timedelta(seconds=seconds)


def _registry(**overrides: object) -> AssetRegistry:
    return AssetRegistry(AssetSettings(**overrides))  # type: ignore[arg-type]


# --- 1. Asset identity creation ---------------------------------------------


def test_asset_identity_creation() -> None:
    registry = _registry()
    asset_id = registry.observe_host(
        host_id="host-1",
        hostname="ws-01",
        platform=Platform.WINDOWS,
        os="Windows 11",
        architecture="x86_64",
        ip_addresses=("10.0.0.5",),
        timestamp=_TS,
    )

    snapshot = registry.snapshot()
    asset = snapshot.asset_by_id(asset_id)

    assert asset is not None
    assert asset.host_id == "host-1"
    assert asset.hostname == "ws-01"
    assert asset.platform is Platform.WINDOWS
    assert asset.os == "Windows 11"
    assert asset.architecture == "x86_64"
    assert asset.ip_addresses == ("10.0.0.5",)
    assert asset.first_seen == _TS


# --- 2. Asset update preserves first_seen -----------------------------------


def test_asset_update_preserves_first_seen() -> None:
    registry = _registry()
    registry.observe_host(host_id="host-1", hostname="ws-01", timestamp=_ts(0))
    asset_id = registry.observe_host(
        host_id="host-1", hostname="ws-02", os="Linux", timestamp=_ts(60)
    )

    asset = registry.snapshot().asset_by_id(asset_id)

    assert asset is not None
    assert asset.hostname == "ws-02"  # updated
    assert asset.os == "Linux"
    assert asset.first_seen == _ts(0)  # preserved


# --- 3. last_seen update ----------------------------------------------------


def test_last_seen_updates() -> None:
    registry = _registry()
    asset_id = registry.observe_host(host_id="host-1", timestamp=_ts(0))
    registry.observe_host(host_id="host-1", timestamp=_ts(120))

    asset = registry.snapshot().asset_by_id(asset_id)

    assert asset is not None
    assert asset.last_seen == _ts(120)


# --- 4. IP merging ----------------------------------------------------------


def test_ip_addresses_merge() -> None:
    registry = _registry()
    asset_id = registry.observe_host(host_id="host-1", ip_addresses=("10.0.0.5",), timestamp=_ts(0))
    registry.observe_local_ip(asset_id, "10.0.0.6", _ts(10))

    asset = registry.snapshot().asset_by_id(asset_id)

    assert asset is not None
    assert asset.ip_addresses == ("10.0.0.5", "10.0.0.6")


# --- 5. Observed port merging -----------------------------------------------


def test_observed_service_merges() -> None:
    registry = _registry()
    asset_id = registry.observe_host(host_id="host-1", timestamp=_ts(0))
    registry.observe_service(
        asset_id, port=22, protocol=TransportProtocol.TCP, status="LISTEN", pid=1, timestamp=_ts(0)
    )
    registry.observe_service(
        asset_id, port=22, protocol=TransportProtocol.TCP, status="LISTEN", pid=1, timestamp=_ts(30)
    )

    asset = registry.snapshot().asset_by_id(asset_id)

    assert asset is not None
    assert len(asset.observed_services) == 1
    assert asset.observed_ports == (22,)
    assert asset.observed_protocols == ("tcp",)
    assert asset.observed_services[0].first_seen == _ts(0)
    assert asset.observed_services[0].last_seen == _ts(30)


# --- 6. Peer creation -------------------------------------------------------


def test_peer_creation() -> None:
    registry = _registry()
    asset_id = registry.observe_host(host_id="host-1", timestamp=_ts(0))
    registry.observe_peer(
        asset_id,
        host_id="host-1",
        remote_ip="10.0.0.9",
        remote_port=443,
        local_ip="10.0.0.5",
        protocol=TransportProtocol.TCP,
        direction=NetworkDirection.OUTBOUND,
        flow_id="f1",
        packets=10,
        byte_count=1000,
        timestamp=_ts(0),
    )

    snapshot = registry.snapshot()
    assert snapshot.peer_count == 1
    peer = snapshot.peers[0]
    assert peer.remote_ip == "10.0.0.9"
    assert peer.remote_port == 443
    assert peer.direction is NetworkDirection.OUTBOUND
    assert peer.flow_count == 1
    assert peer.packet_count == 10
    assert peer.byte_count == 1000


# --- 7. Peer aggregation (delta counters, no double counting) ---------------


def test_peer_aggregation_counts_deltas() -> None:
    registry = _registry()
    asset_id = registry.observe_host(host_id="host-1", timestamp=_ts(0))
    for packets, byte_count, ts in ((10, 1000, 0), (25, 2500, 30)):
        registry.observe_peer(
            asset_id,
            host_id="host-1",
            remote_ip="10.0.0.9",
            remote_port=443,
            local_ip="10.0.0.5",
            flow_id="f1",
            packets=packets,
            byte_count=byte_count,
            timestamp=_ts(ts),
        )

    peer = registry.snapshot().peers[0]
    assert peer.flow_count == 1
    assert peer.packet_count == 25
    assert peer.byte_count == 2500
    assert peer.first_seen == _ts(0)
    assert peer.last_seen == _ts(30)


# --- 8. Known vs new --------------------------------------------------------


def test_known_vs_new_observation() -> None:
    registry = _registry()
    asset_id = registry.observe_host(host_id="host-1", timestamp=_ts(0))
    registry.observe_service(asset_id, port=8443, protocol=TransportProtocol.TCP, timestamp=_ts(0))
    first = registry.snapshot().assets[0].observed_services[0]
    assert first.known is False  # first observation => new

    registry.observe_service(asset_id, port=8443, protocol=TransportProtocol.TCP, timestamp=_ts(30))
    second = registry.snapshot().assets[0].observed_services[0]
    assert second.known is True  # seen before => known


# --- 9. Bounded registry ----------------------------------------------------


def test_registry_is_bounded() -> None:
    registry = _registry(max_assets=2, max_peers=1)
    for i in range(3):
        registry.observe_host(host_id=f"host-{i}", timestamp=_ts(i))
    assert registry.asset_count == 2  # oldest evicted

    asset_id = registry.observe_host(host_id="host-x", timestamp=_ts(10))
    for i in range(2):
        registry.observe_peer(
            asset_id,
            host_id="host-x",
            remote_ip=f"10.0.0.{i}",
            remote_port=80,
            flow_id=f"f{i}",
            timestamp=_ts(10 + i),
        )
    assert registry.peer_count == 1  # bounded


# --- 10. Baseline known-memory ----------------------------------------------


def test_baseline_known_memory() -> None:
    baseline = NetworkBaseline(max_entries=2)

    assert baseline.observe(ObservationKind.IP, "10.0.0.5", _ts(0)) is False  # new
    assert baseline.observe(ObservationKind.IP, "10.0.0.5", _ts(5)) is True  # known
    assert baseline.is_known(ObservationKind.IP, "10.0.0.5") is True
    assert baseline.count(ObservationKind.IP, "10.0.0.5") == 2

    baseline.observe(ObservationKind.IP, "10.0.0.6", _ts(6))
    baseline.observe(ObservationKind.IP, "10.0.0.7", _ts(7))  # evicts oldest
    assert baseline.known_count(ObservationKind.IP) == 2
    assert baseline.is_known(ObservationKind.IP, "10.0.0.5") is False


# --- 11. Runtime start/reset and stop/clear ---------------------------------


def test_runtime_start_and_stop_reset_assets() -> None:
    from aegis_network_sensor.config import SensorSettings
    from aegis_runtime import AegisRuntime
    from tests.test_runtime import _agent

    registry = _registry()
    registry.observe_host(host_id="stale", timestamp=_ts(0))  # pre-existing state

    runtime = AegisRuntime(
        agent_settings=_agent(),
        sensor_settings=SensorSettings(capture_enabled=False),
        asset_registry=registry,
    )
    runtime.start()
    # start() resets any prior asset state.
    assert registry.asset_count == 0
    assert get_active_asset_snapshot() is None

    runtime.poll_once()
    snapshot = get_active_asset_snapshot()
    assert snapshot is not None
    assert snapshot.asset_count == 1  # the runtime's own host

    runtime.stop()
    assert get_active_asset_snapshot() is None
    assert registry.asset_count == 0


# --- 12. Real telemetry -> asset update -------------------------------------


def test_runtime_updates_assets_from_real_telemetry() -> None:
    pytest.importorskip("scapy.layers.inet", reason="scapy not installed")
    from scapy.layers.inet import IP, TCP

    from aegis_agent.monitors.port.models import PortChanges, PortRecord, PortSnapshot
    from aegis_network_sensor.config import SensorSettings
    from aegis_network_sensor.sensor import NetworkSensor
    from aegis_runtime import AegisRuntime
    from aegis_shared.enums import AddressFamily
    from tests.test_runtime import _agent

    class PortMonitor:
        def start(self) -> None:
            return None

        def poll(self) -> PortChanges:
            return PortChanges()

        def snapshot(self) -> PortSnapshot:
            return PortSnapshot(
                captured_at=_TS,
                ports=(
                    PortRecord(
                        protocol=TransportProtocol.TCP,
                        address_family=AddressFamily.IPV4,
                        local_address="0.0.0.0",
                        local_port=22,
                        status="LISTEN",
                        pid=1,
                        process_name="sshd",
                    ),
                ),
            )

        def stop(self) -> None:
            return None

    class ReplaySensor(NetworkSensor):
        def __init__(self) -> None:
            super().__init__(SensorSettings(capture_enabled=False, local_addresses=["10.0.0.5"]))

        def capture(self, *, count: int | None = None) -> object:
            return self.process_packets(
                [IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=50000, dport=443)]
            )

    runtime = AegisRuntime(
        agent_settings=_agent(enable_port_monitor=True),
        sensor_settings=SensorSettings(capture_enabled=False, local_addresses=["10.0.0.5"]),
        port_monitor=PortMonitor(),
        network_sensor=ReplaySensor(),
    )
    runtime.start()
    runtime.poll_once()

    snapshot = get_active_asset_snapshot()
    assert snapshot is not None
    asset = snapshot.assets[0]
    assert "10.0.0.5" in asset.ip_addresses
    assert 22 in asset.observed_ports
    assert snapshot.peer_count == 1
    assert snapshot.peers[0].remote_ip == "10.0.0.9"
    assert snapshot.peers[0].direction is NetworkDirection.OUTBOUND

    runtime.stop()


# --- 13. Desktop Assets view uses real runtime state ------------------------


def test_desktop_assets_view_uses_runtime_state() -> None:
    pytest.importorskip("PySide6", reason="desktop extra not installed")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from aegis_desktop.app import create_application
    from aegis_desktop.pages.assets import AssetsPage
    from aegis_desktop.services.assets import collect_asset_view

    app = create_application([])
    assert app is not None

    registry = _registry()
    asset_id = registry.observe_host(
        host_id="host-1", hostname="ws-01", ip_addresses=("10.0.0.5",), timestamp=_ts(0)
    )
    registry.observe_service(
        asset_id, port=22, protocol=TransportProtocol.TCP, status="LISTEN", timestamp=_ts(0)
    )
    registry.observe_peer(
        asset_id,
        host_id="host-1",
        remote_ip="10.0.0.9",
        remote_port=443,
        flow_id="f1",
        packets=5,
        byte_count=500,
        timestamp=_ts(0),
    )
    snapshot = registry.snapshot()

    view = collect_asset_view(snapshot_provider=lambda: snapshot)
    assert view.count == 1
    assert view.posture.peers == 1

    page = AssetsPage(provider=lambda: view)
    page.refresh()
    assert page.row_count() == 1
    assert page.asset_count_text() == "Assets: 1"

    page.show_detail_for(page.row_at(0))
    keys = page.detail_keys()
    values = page.detail_values()
    assert "Hostname" in keys
    assert "ws-01" in values
    assert "22/tcp" in keys  # observed service (port/protocol label)
    assert any("10.0.0.9" in key for key in keys)  # network relationship


# --- 14. Investigation asset context ----------------------------------------


def test_investigation_exposes_asset_context() -> None:
    from aegis_desktop.services.assets import AssetContext
    from aegis_desktop.services.detections import collect_investigation_view
    from aegis_shared.detection import DetectionFinding
    from aegis_shared.enums import EventCategory, EventType, Severity

    finding = DetectionFinding(
        finding_id="AEGIS-PROC-001:h1",
        rule_id="AEGIS-PROC-001",
        rule_name="Process launched from configured path",
        severity=Severity.HIGH,
        title="Process finding",
        description="A process finding.",
        event_id="h1",
        event_type=EventType.PROCESS_STARTED,
        category=EventCategory.HOST,
        timestamp=_TS,
        host_id="host-1",
    )
    context = AssetContext(
        host_id="host-1",
        hostname="ws-01",
        ip_addresses=("10.0.0.5",),
        observed_ports=("22/tcp",),
        known_peers=2,
        new_peers=1,
    )

    view = collect_investigation_view(
        finding,
        event_details_lookup=lambda _eid: None,
        asset_context_lookup=lambda host: context if host == "host-1" else None,
    )

    assert view.asset_context is not None
    assert view.asset_context.hostname == "ws-01"
    assert view.asset_context.observed_ports == ("22/tcp",)
    assert view.asset_context.new_peers == 1


@pytest.fixture(autouse=True)
def _clean() -> object:
    from aegis_shared.assets import clear_active_asset_snapshot

    clear_active_pipeline()
    clear_active_risk_engine()
    clear_active_asset_snapshot()
    yield
    clear_active_pipeline()
    clear_active_risk_engine()
    clear_active_asset_snapshot()
