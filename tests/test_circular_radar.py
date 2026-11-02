"""Unit tests for TacticalCircularRadarWidget."""

from __future__ import annotations

import os
import pytest

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from aegis_desktop.app import create_application
from aegis_desktop.services.arp_radar import ArpDeviceRow
from aegis_desktop.widgets.circular_radar import TacticalCircularRadarWidget

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="module")
def app() -> QApplication:
    return create_application([])


def test_circular_radar_widget_initialization(app: QApplication) -> None:
    """Widget initializes properly and handles device updates."""
    widget = TacticalCircularRadarWidget()
    assert widget.minimumWidth() >= 350
    assert widget.minimumHeight() >= 350

    sample_devices = [
        ArpDeviceRow(
            ip="192.168.8.1",
            mac="88:40:3b:d0:0f:24",
            vendor="Huawei",
            role="🌐 DEFAULT GATEWAY",
            status="ACTIVE",
            is_suspicious=False,
            first_seen="12:00:00",
            last_seen="12:05:00",
            packets=15,
        ),
        ArpDeviceRow(
            ip="192.168.8.102",
            mac="80:9d:65:42:8f:f5",
            vendor="Realtek",
            role="💻 THIS COMPUTER",
            status="ONLINE",
            is_suspicious=False,
            first_seen="12:00:00",
            last_seen="12:05:00",
            packets=42,
        ),
        ArpDeviceRow(
            ip="192.168.8.100",
            mac="90:cb:a3:03:66:21",
            vendor="Vivo Mobile",
            role="📱 ENDPOINT NODE",
            status="ACTIVE",
            is_suspicious=False,
            first_seen="12:00:00",
            last_seen="12:05:00",
            packets=8,
        ),
        ArpDeviceRow(
            ip="192.168.8.200",
            mac="66:66:66:66:66:66",
            vendor="Unknown Vendor",
            role="🚨 SUSPICIOUS / SPOOFER",
            status="ATTACK DETECTED",
            is_suspicious=True,
            first_seen="12:00:00",
            last_seen="12:05:00",
            packets=99,
        ),
    ]

    widget.set_devices(sample_devices)
    assert len(widget._devices) == 4

    # Test coordinate calculation for local host (must be center)
    cx, cy, _ = widget._calculate_blip_pos(sample_devices[1], 200, 200, 150)
    assert cx == 200
    assert cy == 200

    # Test tick advancement
    prev_angle = widget._sweep_angle
    widget._on_tick()
    assert widget._sweep_angle != prev_angle
