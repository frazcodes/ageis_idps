"""Unit tests for the Live Cyber Threat Globe & World Attack Map."""

from __future__ import annotations

import os
from typing import Any

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6", reason="desktop extra not installed")

from PySide6.QtCore import QPointF
from PySide6.QtWidgets import QApplication

from aegis_desktop.app import create_application
from aegis_desktop.widgets.world_attack_map import (
    GlobalThreatMapContainer,
    WorldAttackMapWidget,
    resolve_ip_location,
)


@pytest.fixture(scope="module")
def app() -> QApplication:
    return create_application([])


def test_geoip_resolution_known_cloud_providers() -> None:
    """Known IP prefixes map to the expected cloud provider and country."""
    # Google DNS
    loc1 = resolve_ip_location("8.8.8.8")
    assert loc1.country == "United States"
    assert loc1.country_code == "US"
    assert "Google" in loc1.isp

    # Cloudflare
    loc2 = resolve_ip_location("1.1.1.1")
    assert loc2.country == "United States"
    assert loc2.country_code == "US"
    assert "Cloudflare" in loc2.isp

    # Tor Relay
    loc3 = resolve_ip_location("185.220.101.5")
    assert loc3.country == "Germany"
    assert loc3.country_code == "DE"
    assert loc3.is_threat is True

    # Local Subnet / RFC1918
    loc4 = resolve_ip_location("192.168.8.1")
    assert loc4.country_code == "LAN"


def test_world_attack_map_widget_lifecycle(app: Any) -> None:
    """WorldAttackMapWidget initializes, calculates projections, and updates flows."""
    widget = WorldAttackMapWidget()
    assert widget is not None
    assert len(widget._arcs) > 0

    # Test coordinate projection mapping
    pt_home = widget._geo_to_screen(74.3587, 31.5204, 800.0, 500.0)
    assert isinstance(pt_home, QPointF)
    assert 0.0 <= pt_home.x() <= 800.0
    assert 0.0 <= pt_home.y() <= 500.0

    # Ingest mock flows
    class MockFlow:
        remote_address = "142.250.180.174"
        protocol = "TCP"
        remote_port = 443
        bytes = 8192
        packets = 16
        direction = "OUTBOUND"

    class MockEvent:
        src_ip = "185.220.101.5"
        title = "RECONNAISSANCE SCAN"

    widget.update_flows([MockFlow()], [MockEvent()])
    assert len(widget._arcs) >= 2
    assert widget._threat_count >= 1


def test_global_threat_map_container(app: Any) -> None:
    """GlobalThreatMapContainer embeds the map and delegates flow updates."""
    container = GlobalThreatMapContainer()
    assert container.map_widget is not None

    class MockFlow:
        remote_address = "13.107.42.14"
        protocol = "TCP"
        remote_port = 443
        bytes = 5000
        packets = 10
        direction = "OUTBOUND"

    container.update_flows([MockFlow()])
    assert len(container.map_widget._arcs) >= 1

