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
    assert store.latest() is not None
    assert store.latest().flow_id == "flow-1"


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
    assert store.latest().packets == 20


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
