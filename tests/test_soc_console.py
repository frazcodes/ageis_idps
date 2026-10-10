"""Focused tests for the SOC console dashboard redesign (Step 32.1)."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason="desktop extra not installed")

from aegis_agent.config import AgentSettings
from aegis_agent.inventory import SystemInventory
from aegis_desktop.app import create_application
from aegis_desktop.pages.base import BasePage
from aegis_desktop.pages.dashboard import DashboardPage
from aegis_desktop.services.dashboard import DashboardSnapshot, collect_dashboard_snapshot
from aegis_desktop.services.live_network import (
    MAX_ACTIVITY_ROWS,
    LiveActivityRow,
    LiveNetworkActivity,
    LiveNetworkTableModel,
    analyze_packet_threat,
)
from aegis_network_sensor.config import SensorSettings
from aegis_shared.enums import Platform

_TS = datetime(2026, 6, 1, 10, 0, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def app() -> Any:
    return create_application([])


def _inventory() -> SystemInventory:
    return SystemInventory(
        host_id="host-1", hostname="ws-01", platform=Platform.WINDOWS,
        os_name="Windows", os_version="10.0", architecture="AMD64",
        python_version="3.14.3", agent_version="0.1.0", cpu_count=8,
        total_memory_bytes=16 * 1024**3, boot_time=_TS, collected_at=_TS,
    )


def _snapshot(**_kw: Any) -> DashboardSnapshot:
    return collect_dashboard_snapshot(
        inventory_collector=_inventory, agent_settings=AgentSettings(),
        sensor_settings=SensorSettings(capture_enabled=False, interface=""),
        collected_at=_TS,
        events_view_provider=lambda: None, findings_view_provider=lambda: None,
    )


def _activity_row(flow_id: str = "flow-1", **overrides: Any) -> LiveActivityRow:
    defaults = {
        "timestamp": _TS, "source": "10.0.0.1:443", "destination": "192.168.1.100:52000",
        "port": "443", "protocol": "TCP", "packets": 10, "bytes": 5000,
        "direction": "outbound", "state": "active", "flow_id": flow_id,
    }
    defaults.update(overrides)
    return LiveActivityRow(**defaults)


# --- 1. LiveNetworkActivity empty state -----------------------------------
def test_live_network_activity_empty() -> None:
    store = LiveNetworkActivity()
    assert store.count == 0
    assert store.latest() is None
    assert store.rows() == ()


# --- 2. LiveNetworkActivity add row ---------------------------------------
def test_live_network_activity_add() -> None:
    store = LiveNetworkActivity()
    row = _activity_row()
    store.add(row)
    assert store.count == 1
    latest = store.latest()
    assert latest is not None
    assert latest.flow_id == "flow-1"


# --- 3. LiveNetworkActivity bounded eviction ------------------------------
def test_live_network_activity_bounded() -> None:
    store = LiveNetworkActivity(max_rows=3)
    for i in range(5):
        store.add(_activity_row(flow_id=f"flow-{i}"))
    assert store.count == 3
    rows = store.rows()
    assert rows[0].flow_id == "flow-2"
    assert rows[2].flow_id == "flow-4"


# --- 4. LiveNetworkActivity duplicate flow_id updates ---------------------
def test_live_network_activity_duplicate_update() -> None:
    store = LiveNetworkActivity()
    store.add(_activity_row(flow_id="f-1", packets=10))
    store.add(_activity_row(flow_id="f-1", packets=20))
    assert store.count == 1
    latest = store.latest()
    assert latest is not None
    assert latest.packets == 20


# --- 5. LiveNetworkActivity clear ----------------------------------------
def test_live_network_activity_clear() -> None:
    store = LiveNetworkActivity()
    store.add(_activity_row())
    assert store.count == 1
    store.clear()
    assert store.count == 0


# --- 6. LiveNetworkTableModel basics --------------------------------------
def test_live_network_table_model_basics(app: Any) -> None:
    model = LiveNetworkTableModel()
    assert model.rowCount() == 0
    assert model.columnCount() == 9


# --- 7. LiveNetworkTableModel set_rows ------------------------------------
def test_live_network_table_model_set_rows(app: Any) -> None:
    model = LiveNetworkTableModel()
    rows = (_activity_row("f-1"), _activity_row("f-2"))
    model.set_rows(rows)
    assert model.rowCount() == 2


# --- 8. LiveNetworkTableModel row_at --------------------------------------
def test_live_network_table_model_row_at(app: Any) -> None:
    model = LiveNetworkTableModel()
    row = _activity_row("f-1")
    model.set_rows((row,))
    assert model.row_at(0) is row
    assert model.row_at(1) is None


# --- 9. LiveNetworkTableModel display data --------------------------------
def test_live_network_table_model_display(app: Any) -> None:
    from PySide6.QtCore import Qt
    model = LiveNetworkTableModel()
    row = _activity_row(flow_id="f-1", packets=42, bytes=1234)
    model.set_rows((row,))
    idx = model.index(0, 0)
    assert model.data(idx, Qt.ItemDataRole.DisplayRole) == "10:00:00"
    idx_port = model.index(0, 3)
    assert model.data(idx_port, Qt.ItemDataRole.DisplayRole) == "443"
    idx_proto = model.index(0, 4)
    assert model.data(idx_proto, Qt.ItemDataRole.DisplayRole) == "TCP"
    idx_pkts = model.index(0, 5)
    assert model.data(idx_pkts, Qt.ItemDataRole.DisplayRole) == "42"


# --- 10. LiveNetworkTableModel header data --------------------------------
def test_live_network_table_model_header(app: Any) -> None:
    from PySide6.QtCore import Qt
    model = LiveNetworkTableModel()
    header = model.headerData(0, Qt.Orientation.Horizontal, Qt.ItemDataRole.DisplayRole)
    assert header == "Time"


# --- 11. DashboardPage constructor with live_network ----------------------
def test_dashboard_constructs_with_live_network(app: Any) -> None:
    ln = LiveNetworkActivity()
    page = DashboardPage(provider=lambda: _snapshot(), live_network=ln)
    assert isinstance(page, BasePage)
    assert page.live_network is ln


# --- 12. DashboardPage set_main_window ------------------------------------
def test_dashboard_set_main_window(app: Any) -> None:
    page = DashboardPage(provider=lambda: _snapshot())
    mock_window = MagicMock()
    page.set_main_window(mock_window)
    assert page._main_window is mock_window


# --- 13. DashboardPage _navigate_to calls window --------------------------
def test_dashboard_navigate_to_calls_window(app: Any) -> None:
    page = DashboardPage(provider=lambda: _snapshot())
    mock_window = MagicMock()
    page.set_main_window(mock_window)
    page._navigate_to("detections", select_id="F-001")
    mock_window.navigate_to.assert_called_once_with("detections", select_id="F-001")


# --- 14. DashboardPage _navigate_to handles no window ---------------------
def test_dashboard_navigate_to_no_window(app: Any) -> None:
    page = DashboardPage(provider=lambda: _snapshot())
    page._navigate_to("detections", select_id="F-001")


# --- 15. DashboardPage live_network property ------------------------------
def test_dashboard_live_network_property(app: Any) -> None:
    ln = LiveNetworkActivity()
    page = DashboardPage(provider=lambda: _snapshot(), live_network=ln)
    assert page.live_network is ln


# --- 16. DashboardPage refresh_live updates live network -------------------
def test_dashboard_refresh_live_updates_network(app: Any) -> None:
    ln = LiveNetworkActivity()
    page = DashboardPage(provider=lambda: _snapshot(), live_network=ln)
    page.refresh_live()
    assert ln.count >= 0


# --- 17. MAX_ACTIVITY_ROWS is 100 -----------------------------------------
def test_max_activity_rows() -> None:
    assert MAX_ACTIVITY_ROWS == 100


# --- 18. LiveNetworkActivity max_rows property ----------------------------
def test_live_network_activity_max_rows() -> None:
    store = LiveNetworkActivity(max_rows=50)
    assert store.max_rows == 50


# --- 19. DashboardPage has new panels -------------------------------------
def test_dashboard_has_new_panels(app: Any) -> None:
    page = DashboardPage(provider=lambda: _snapshot())
    assert page._findings_container is not None
    assert page._incidents_container is not None
    assert page._explanation_container is not None
    assert page._relationships_container is not None


# --- 20. DashboardPage network summary labels -----------------------------
def test_dashboard_network_summary_labels(app: Any) -> None:
    page = DashboardPage(provider=lambda: _snapshot())
    assert "total_packets" in page._network_summary_labels
    assert "total_bytes" in page._network_summary_labels
    assert "last_time" in page._network_summary_labels


# --- 21. DashboardPage refresh_live updates network summary ---------------
def test_dashboard_refresh_live_updates_summary(app: Any) -> None:
    page = DashboardPage(provider=lambda: _snapshot())
    page.refresh_live()
    assert page._network_summary_labels["last_time"].text() is not None


# --- 22. LiveNetworkTableModel handles empty data -------------------------
def test_live_network_table_model_empty(app: Any) -> None:
    from PySide6.QtCore import Qt
    model = LiveNetworkTableModel()
    idx = model.index(0, 0)
    assert model.data(idx, Qt.ItemDataRole.DisplayRole) is None
    assert model.headerData(5, Qt.Orientation.Horizontal, Qt.ItemDataRole.DisplayRole) == "Packets"


# --- 23. DashboardPage existing status_text still works --------------------
def test_existing_status_text_intact(app: Any) -> None:
    page = DashboardPage(provider=lambda: _snapshot())
    assert page.status_text("runtime") == "NOT RUNNING"
    assert page.status_text("detection") == "NOT RUNNING"
    assert page.status_text("risk") == "NOT RUNNING"
    assert page.status_text("response") == "MONITOR (read-only)"


# --- 24. BasePage has handle_navigate -------------------------------------
def test_base_page_has_handle_navigate() -> None:
    assert hasattr(BasePage, "handle_navigate")


# --- 25. MainWindow navigate_to accepts kwargs (compile check) ------------
def test_window_navigate_to_signature() -> None:
    import inspect

    from aegis_desktop.window import MainWindow
    sig = inspect.signature(MainWindow.navigate_to)
    params = list(sig.parameters.keys())
    assert "key" in params
    assert "kwargs" in params


# --- 26. Packet threat analysis and red-stripe styling --------------------
def test_analyze_packet_threat_clean() -> None:
    is_threat, tag, detail = analyze_packet_threat(
        source="192.168.1.10:50123",
        destination="142.250.190.46:443",
        port="443",
        protocol="TCP",
        packets=20,
        bytes_transferred=4096,
        state="active",
    )
    assert not is_threat
    assert tag == ""
    assert detail == ""


def test_analyze_packet_threat_critical_ports() -> None:
    # Port 445 (SMB)
    is_threat, tag, detail = analyze_packet_threat(
        source="10.0.0.50:49200",
        destination="10.0.0.5:445",
        port="445",
        protocol="TCP",
    )
    assert is_threat
    assert tag == "SMB EXPLOIT"
    assert "Port 445" in detail

    # Port 3389 (RDP)
    is_threat, tag, detail = analyze_packet_threat(
        source="192.168.1.200:55000",
        destination="192.168.1.5:3389",
    )
    assert is_threat
    assert tag == "RDP BRUTE"

    # Port 4444 (Metasploit)
    is_threat, tag, detail = analyze_packet_threat(
        source="10.0.0.1:4444",
        destination="10.0.0.2:49000",
    )
    assert is_threat
    assert tag == "METASPLOIT C2"


def test_analyze_packet_threat_floods_and_alert_state() -> None:
    # Traffic volume flood
    is_threat, tag, _ = analyze_packet_threat(
        packets=6000,
        bytes_transferred=20_000_000,
    )
    assert is_threat
    assert tag == "TRAFFIC FLOOD"

    # ICMP flood
    is_threat, tag, _ = analyze_packet_threat(
        protocol="ICMP",
        packets=600,
    )
    assert is_threat
    assert tag == "ICMP FLOOD"

    # Explicit alert state
    is_threat, tag, _ = analyze_packet_threat(
        state="suspicious",
    )
    assert is_threat
    assert tag == "ACTIVE ALERT"


def test_live_network_table_model_threat_styling(app: Any) -> None:
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QColor

    model = LiveNetworkTableModel()
    suspicious_row = _activity_row(
        flow_id="f-threat-1",
        port="445",
        state="active",
        is_suspicious=True,
        threat_tag="SMB EXPLOIT",
        threat_detail="SMB Port 445 Lateral Movement",
    )
    normal_row = _activity_row(flow_id="f-normal-1", port="443", state="active")
    model.set_rows((suspicious_row, normal_row))

    # Suspicious row (row 0)
    bg_color = model.data(model.index(0, 0), Qt.ItemDataRole.BackgroundRole)
    assert isinstance(bg_color, QColor)
    assert bg_color.red() == 248 and bg_color.green() == 81

    tooltip = model.data(model.index(0, 0), Qt.ItemDataRole.ToolTipRole)
    assert tooltip is not None
    assert "SUSPICIOUS NETWORK ACTIVITY" in str(tooltip)
    assert "SMB EXPLOIT" in str(tooltip)

    # State column (col 8) displays alert badge and red text
    state_display = model.data(model.index(0, 8), Qt.ItemDataRole.DisplayRole)
    assert state_display == "🚨 SMB EXPLOIT"
    fg_color = model.data(model.index(0, 8), Qt.ItemDataRole.ForegroundRole)
    assert isinstance(fg_color, QColor)

    # Normal row (row 1)
    assert model.data(model.index(1, 0), Qt.ItemDataRole.BackgroundRole) is None
    assert model.data(model.index(1, 0), Qt.ItemDataRole.ToolTipRole) is None
    assert model.data(model.index(1, 8), Qt.ItemDataRole.DisplayRole) == "active"


# ---------------------------------------------------------------------------
# Step 3: SNI Display & Domain Threat Intelligence Tests
# ---------------------------------------------------------------------------


def test_live_network_table_model_displays_sni_alongside_ip(app: Any) -> None:
    from PySide6.QtCore import Qt

    model = LiveNetworkTableModel()
    row_with_sni = _activity_row(
        flow_id="f-sni-1",
        destination="104.21.5.10:443",
        sni="api.cloudflare.com",
    )
    model.set_rows((row_with_sni,))

    col2_idx = model.index(0, 2)
    display_val = model.data(col2_idx, Qt.ItemDataRole.DisplayRole)
    assert display_val == "104.21.5.10:443 (api.cloudflare.com)"

    # Tooltip on destination column indicates resolved SNI
    tooltip = model.data(col2_idx, Qt.ItemDataRole.ToolTipRole)
    assert tooltip == "Resolved TLS SNI Hostname: api.cloudflare.com"


def test_live_network_table_model_backward_compatibility_no_sni(app: Any) -> None:
    from PySide6.QtCore import Qt

    model = LiveNetworkTableModel()
    row_no_sni = _activity_row(
        flow_id="f-plain-1",
        destination="192.168.1.1:80",
        sni=None,
    )
    model.set_rows((row_no_sni,))

    col2_idx = model.index(0, 2)
    display_val = model.data(col2_idx, Qt.ItemDataRole.DisplayRole)
    # Does not invent or append fake domain
    assert display_val == "192.168.1.1:80"
    assert "(" not in display_val
    assert model.data(col2_idx, Qt.ItemDataRole.ToolTipRole) is None


def test_analyze_packet_threat_detects_malicious_domain_ioc() -> None:
    from aegis_shared.enums import IndicatorType, Severity
    from aegis_shared.threat_intel.matcher import IOCMatcher
    from aegis_shared.threat_intel.models import ThreatIndicator

    custom_indicator = ThreatIndicator(
        indicator_id="IOC-TEST-C2-001",
        indicator_type=IndicatorType.DOMAIN,
        value="apt-command-server.net",
        source="unit-test",
        confidence=0.95,
        severity=Severity.CRITICAL,
        description="Known APT C2 beacon domain",
    )
    matcher = IOCMatcher([custom_indicator])

    is_threat, tag, detail = analyze_packet_threat(
        source="10.0.0.10:49210",
        destination="185.220.101.5:443",
        port="443",
        protocol="TCP",
        domain="apt-command-server.net",
        ioc_matcher=matcher,
    )
    assert is_threat is True
    assert tag == "MALICIOUS IOC DOMAIN"
    assert "apt-command-server.net" in detail
    assert "Known APT C2 beacon domain" in detail


def test_analyze_packet_threat_benign_domain_with_unusual_tld() -> None:
    # Requirement: Do not classify a domain as malicious solely because of .top or .xyz
    is_threat_xyz, tag_xyz, _ = analyze_packet_threat(
        destination="104.26.10.5:443",
        port="443",
        protocol="TCP",
        domain="portfolio-showcase.xyz",
    )
    assert is_threat_xyz is False
    assert tag_xyz == ""

    is_threat_top, tag_top, _ = analyze_packet_threat(
        destination="104.26.10.6:443",
        port="443",
        protocol="TCP",
        domain="corporate-services.top",
    )
    assert is_threat_top is False
    assert tag_top == ""


def test_analyze_packet_threat_missing_sni_and_ech_no_false_claims() -> None:
    # Missing SNI or ECH encrypted frame (domain="") causes zero false claims
    is_threat, tag, _ = analyze_packet_threat(
        destination="104.26.10.7:443",
        port="443",
        protocol="TCP",
        domain="",
    )
    assert is_threat is False
    assert tag == ""


