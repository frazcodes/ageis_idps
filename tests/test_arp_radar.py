"""Unit and integration tests for ARP Radar, Subnet Discovery, and MITM Defense."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

import pytest

from aegis_desktop.app import create_application
from aegis_desktop.pages.network import ArpRadarTableModel, NetworkPage
from aegis_desktop.services.arp_radar import ArpDeviceRow, ArpRadarService
from aegis_network_sensor.arp_radar import (
    ArpTracker,
    lookup_mac_vendor,
    normalize_mac,
)
from aegis_shared.enums import Severity

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6", reason="desktop extra not installed")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication


@pytest.fixture(scope="module")
def app() -> QApplication:
    return create_application([])


# ===========================================================================
# 1. MAC Normalization & OUI Vendor Resolution
# ===========================================================================


def test_mac_normalization() -> None:
    """Test standardizing various MAC address formats."""
    assert normalize_mac("00-11-22-33-44-55") == "00:11:22:33:44:55"
    assert normalize_mac("001122334455") == "00:11:22:33:44:55"
    assert normalize_mac("00:11:22:33:44:55") == "00:11:22:33:44:55"
    assert normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
    assert normalize_mac("  aa-bb-cc-dd-ee-ff  ") == "aa:bb:cc:dd:ee:ff"


def test_oui_vendor_resolution() -> None:
    """Test resolving common hardware manufacturers from MAC addresses."""
    # Apple
    assert lookup_mac_vendor("00:1c:b3:11:22:33") == "Apple"
    assert lookup_mac_vendor("f0-18-98-aa-bb-cc") == "Apple"
    # Samsung
    assert lookup_mac_vendor("50:01:d9:12:34:56") == "Samsung"
    assert lookup_mac_vendor("d8:90:e8:00:11:22") == "Samsung"
    # Intel
    assert lookup_mac_vendor("00:02:b3:44:55:66") == "Intel"
    # Cisco
    assert lookup_mac_vendor("00:01:42:77:88:99") == "Cisco"
    # Raspberry Pi
    assert lookup_mac_vendor("b8:27:eb:11:22:33") == "Raspberry Pi"
    assert lookup_mac_vendor("dc:a6:32:44:55:66") == "Raspberry Pi"
    # Espressif IoT (Smart plugs, ESP32)
    assert lookup_mac_vendor("24:0a:c4:12:34:56") == "Espressif IoT"
    assert lookup_mac_vendor("18:fe:34:aa:bb:cc") == "Espressif IoT"
    # Docker
    assert lookup_mac_vendor("02:42:ac:11:00:02") == "Docker Container"
    # Broadcast & Multicast
    assert lookup_mac_vendor("ff:ff:ff:ff:ff:ff") == "Broadcast"
    assert lookup_mac_vendor("01:00:5e:00:00:01") == "Multicast"
    # Unknown
    assert lookup_mac_vendor("71:34:56:78:90:ab") == "Unknown Vendor"


# ===========================================================================
# 2. Normal ARP Observation & Device State Tracking
# ===========================================================================


def test_arp_normal_device_tracking() -> None:
    """Observing legitimate ARP frames records active subnet hosts."""
    tracker = ArpTracker(known_gateway_ip="192.168.1.1", local_host_ip="192.168.1.10")

    # Host 1: Normal laptop
    t1 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)
    alerts = tracker.observe_arp(
        src_ip="192.168.1.50",
        src_mac="00:1c:b3:aa:bb:cc",
        timestamp=t1,
    )
    assert len(alerts) == 0

    devices = tracker.get_devices()
    assert len(devices) == 1
    d = devices[0]
    assert d.ip == "192.168.1.50"
    assert d.mac == "00:1c:b3:aa:bb:cc"
    assert d.vendor == "Apple"
    assert d.is_gateway is False
    assert d.is_suspicious is False
    assert d.packet_count == 1

    # Repeat observation updates packet count and timestamp
    t2 = datetime(2026, 1, 1, 10, 0, 5, tzinfo=UTC)
    tracker.observe_arp(
        src_ip="192.168.1.50",
        src_mac="00:1c:b3:aa:bb:cc",
        timestamp=t2,
    )
    devices = tracker.get_devices()
    assert len(devices) == 1
    assert devices[0].packet_count == 2
    assert devices[0].last_seen == t2


def test_arp_device_sorting_by_ip() -> None:
    """Discovered devices are sorted numerically by IPv4 octets."""
    tracker = ArpTracker()
    tracker.observe_arp(src_ip="192.168.1.100", src_mac="00:11:22:33:44:01")
    tracker.observe_arp(src_ip="192.168.1.2", src_mac="00:11:22:33:44:02")
    tracker.observe_arp(src_ip="192.168.1.20", src_mac="00:11:22:33:44:03")
    tracker.observe_arp(src_ip="192.168.1.1", src_mac="00:11:22:33:44:04")

    ips = [d.ip for d in tracker.get_devices()]
    assert ips == ["192.168.1.1", "192.168.1.2", "192.168.1.20", "192.168.1.100"]


# ===========================================================================
# 3. Gateway Spoofing / MITM Attack Detection
# ===========================================================================


def test_gateway_spoofing_detection() -> None:
    """A rogue MAC claiming the default gateway triggers a critical MITM alert."""
    tracker = ArpTracker(
        known_gateway_ip="192.168.1.1",
        known_gateway_mac="00:01:42:11:22:33",  # Cisco Router
    )

    # Normal gateway response
    alerts1 = tracker.observe_arp(
        src_ip="192.168.1.1",
        src_mac="00:01:42:11:22:33",
    )
    assert len(alerts1) == 0

    # Attacker MAC claims gateway IP (ARP Spoofing / MITM)
    alerts2 = tracker.observe_arp(
        src_ip="192.168.1.1",
        src_mac="de:ad:be:ef:00:01",
    )
    assert len(alerts2) == 1
    alert = alerts2[0]
    assert alert.alert_type == "GATEWAY_SPOOFING"
    assert alert.severity == Severity.CRITICAL
    assert alert.ip == "192.168.1.1"
    assert alert.claimed_mac == "de:ad:be:ef:00:01"
    assert alert.original_mac == "00:01:42:11:22:33"
    assert "MITM DETECTED" in alert.message

    # The device entry must now be flagged as suspicious
    devices = tracker.get_devices()
    gw_dev = next(d for d in devices if d.ip == "192.168.1.1")
    assert gw_dev.is_suspicious is True


# ===========================================================================
# 4. Host Cache Poisoning / IP Conflict Detection
# ===========================================================================


def test_arp_cache_poisoning_host_conflict() -> None:
    """Conflicting MACs for the same internal host trigger cache poisoning alert."""
    tracker = ArpTracker()

    # Host A legitimate binding
    tracker.observe_arp(src_ip="192.168.1.75", src_mac="00:02:b3:11:22:33")
    assert len(tracker.get_alerts()) == 0

    # Attacker machine B claims Host A's IP
    alerts = tracker.observe_arp(src_ip="192.168.1.75", src_mac="de:ad:be:ef:99:99")
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.alert_type == "ARP_CACHE_POISONING"
    assert alert.severity == Severity.HIGH
    assert alert.claimed_mac == "de:ad:be:ef:99:99"
    assert alert.original_mac == "00:02:b3:11:22:33"


# ===========================================================================
# 5. Gratuitous ARP Flooding Detection
# ===========================================================================


def test_gratuitous_arp_flood_detection() -> None:
    """Rapid bursts of unsolicited gratuitous ARP announcements are flagged."""
    tracker = ArpTracker(gratuitous_window_seconds=2.0, gratuitous_burst_limit=3)

    # Attacker sends gratuitous ARP announcements (src_ip == dst_ip)
    alerts = []
    for _ in range(5):
        a = tracker.observe_arp(
            src_ip="192.168.1.120",
            src_mac="ee:ee:ee:ee:ee:ee",
            dst_ip="192.168.1.120",
            op=2,
        )
        alerts.extend(a)

    # Beyond limit of 3, an alert must be generated
    assert any(a.alert_type == "GRATUITOUS_FLOOD" for a in alerts)


# ===========================================================================
# 6. Desktop Service Layer Integration
# ===========================================================================


def test_arp_radar_service_rows_and_summary() -> None:
    """ArpRadarService correctly formats presentation rows and roles."""
    tracker = ArpTracker(known_gateway_ip="192.168.1.1", local_host_ip="192.168.1.100")
    tracker.observe_arp(src_ip="192.168.1.1", src_mac="00:01:42:11:22:33")
    tracker.observe_arp(src_ip="192.168.1.100", src_mac="00:02:b3:44:55:66")
    tracker.observe_arp(src_ip="192.168.1.50", src_mac="00:1c:b3:aa:bb:cc")

    service = ArpRadarService(tracker=tracker)
    service._local_ip = "192.168.1.100"
    service._gateway_ip = "192.168.1.1"

    rows = service.get_rows()
    assert len(rows) == 3

    # Check roles
    gw_row = next(r for r in rows if r.ip == "192.168.1.1")
    assert "DEFAULT GATEWAY" in gw_row.role

    host_row = next(r for r in rows if r.ip == "192.168.1.100")
    assert "THIS COMPUTER" in host_row.role

    endpoint_row = next(r for r in rows if r.ip == "192.168.1.50")
    assert "ENDPOINT NODE" in endpoint_row.role

    summary = service.get_summary()
    assert summary["total_devices"] == 3
    assert summary["suspicious_count"] == 0
    assert summary["is_mitm_detected"] is False


# ===========================================================================
# 7. Desktop Qt UI & Table Model (Offscreen)
# ===========================================================================


def test_arp_radar_table_model(app: Any) -> None:
    """ArpRadarTableModel renders columns, threat colors, and tooltips."""
    model = ArpRadarTableModel()

    normal_row = ArpDeviceRow(
        ip="192.168.1.50",
        mac="00:1c:b3:aa:bb:cc",
        vendor="Apple",
        role="📱 ENDPOINT NODE",
        status="ACTIVE",
        is_suspicious=False,
        first_seen="10:00:00",
        last_seen="10:05:00",
        packets=10,
    )
    spoofed_row = ArpDeviceRow(
        ip="192.168.1.1",
        mac="de:ad:be:ef:00:01",
        vendor="Unknown Vendor",
        role="🚨 SUSPICIOUS / SPOOFER",
        status="ATTACK DETECTED",
        is_suspicious=True,
        first_seen="10:04:00",
        last_seen="10:05:00",
        packets=5,
    )

    model.set_rows((normal_row, spoofed_row))
    assert model.rowCount() == 2
    assert model.columnCount() == 8

    # DisplayRole checks
    assert model.data(model.index(0, 0), Qt.ItemDataRole.DisplayRole) == "192.168.1.50"
    assert model.data(model.index(0, 2), Qt.ItemDataRole.DisplayRole) == "Apple"

    # Suspicious row styling
    bg_suspicious = model.data(model.index(1, 0), Qt.ItemDataRole.BackgroundRole)
    assert bg_suspicious is not None

    tooltip_suspicious = model.data(model.index(1, 0), Qt.ItemDataRole.ToolTipRole)
    assert "SUSPICIOUS ARP ACTIVITY" in str(tooltip_suspicious)

    # Normal row styling
    bg_normal = model.data(model.index(0, 0), Qt.ItemDataRole.BackgroundRole)
    assert bg_normal is None


def test_network_page_arp_radar_tab_integration(app: Any) -> None:
    """NetworkPage integrates the ARP Radar tab and responds to refresh/scan."""
    tracker = ArpTracker(known_gateway_ip="192.168.1.1", local_host_ip="192.168.1.10")
    tracker.observe_arp(src_ip="192.168.1.1", src_mac="00:01:42:11:22:33")
    tracker.observe_arp(src_ip="192.168.1.25", src_mac="b8:27:eb:aa:bb:cc")

    service = ArpRadarService(tracker=tracker)
    page = NetworkPage(arp_service=service)

    # Initial state
    assert page.arp_device_count() == 0

    # Refresh ARP
    page.refresh_arp()
    assert page.arp_device_count() == 2
    row0 = page.arp_row_at(0)
    assert row0.ip == "192.168.1.1"

    # Verify MITM Alert banner triggers on spoof
    tracker.observe_arp(src_ip="192.168.1.1", src_mac="66:66:66:66:66:66")
    page.refresh_arp()
    assert "CRITICAL ALERT: ARP SPOOFING" in page.arp_alert_text()


def test_arp_device_removal_and_pruning() -> None:
    """Test dynamic removal and stale device pruning when endpoints disconnect."""
    tracker = ArpTracker(known_gateway_ip="192.168.1.1", local_host_ip="192.168.1.10")
    tracker.observe_arp(src_ip="192.168.1.1", src_mac="00:01:42:11:22:33")
    tracker.observe_arp(src_ip="192.168.1.50", src_mac="00:1c:b3:aa:bb:cc")
    tracker.observe_arp(src_ip="192.168.1.60", src_mac="50:01:d9:11:22:33")

    assert len(tracker.get_devices()) == 3

    # Remove single disconnected device
    assert tracker.remove_device("192.168.1.50") is True
    assert len(tracker.get_devices()) == 2
    assert "192.168.1.50" not in [d.ip for d in tracker.get_devices()]

    # Sync active IPs (gateway is always preserved even if omitted from active_ips)
    tracker.sync_active_ips({"192.168.1.10"})
    devices = tracker.get_devices()
    # 192.168.1.60 pruned; gateway 192.168.1.1 preserved
    assert len(devices) == 1
    assert devices[0].ip == "192.168.1.1"


def test_arp_service_sync_live_endpoints_disconnect() -> None:
    """ArpRadarService prunes disconnected endpoints during sync_live_endpoints."""
    tracker = ArpTracker(known_gateway_ip="192.168.1.1", local_host_ip="192.168.1.10")
    tracker.observe_arp(src_ip="192.168.1.1", src_mac="00:01:42:11:22:33")
    # Add a mock disconnected device on a non-routable dummy IP
    tracker.observe_arp(src_ip="192.0.2.254", src_mac="00:1c:b3:99:99:99")

    service = ArpRadarService(tracker=tracker, auto_seed=False)
    service._gateway_ip = "192.168.1.1"
    service._local_ip = "192.168.1.10"

    assert len(service.tracker.get_devices()) == 2

    # Run liveness sync: unreachable 192.0.2.254 must be pruned
    dead = service.sync_live_endpoints()
    assert "192.0.2.254" in dead
    remaining = [d.ip for d in service.tracker.get_devices()]
    assert "192.0.2.254" not in remaining
    assert "192.168.1.1" in remaining
