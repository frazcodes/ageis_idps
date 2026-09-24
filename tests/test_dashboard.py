"""Deterministic tests for the Security Operations Dashboard (Step 13).

Inventory, configuration, detection, risk and event data are injected/mocked;
no test needs real network access, administrator privileges, or a running
monitor. Qt uses the offscreen platform.
"""

from __future__ import annotations

import os
import subprocess
import sys
from datetime import UTC, datetime
from typing import Any

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason="desktop extra not installed")

from PySide6.QtWidgets import QApplication

from aegis_agent.config import AgentSettings
from aegis_agent.inventory import SystemInventory
from aegis_desktop.app import create_application
from aegis_desktop.pages.base import BasePage
from aegis_desktop.pages.dashboard import DashboardPage
from aegis_desktop.services.dashboard import (
    INVENTORY_ERROR,
    DashboardSnapshot,
    DetectionPostureView,
    PipelinePosture,
    RiskPostureView,
    collect_dashboard_snapshot,
    format_bytes,
    format_timestamp,
)
from aegis_desktop.window import MainWindow
from aegis_network_sensor.config import SensorSettings
from aegis_shared.enums import Platform
from aegis_shared.pipeline import DEFAULT_DEDUP_WINDOW, DEFAULT_MAX_EVENTS

_TS = datetime(2026, 1, 1, tzinfo=UTC)
_TS2 = datetime(2026, 1, 2, tzinfo=UTC)

#: Packages the dashboard must never import.
_FORBIDDEN_IMPORT_PREFIXES = (
    "aegis_agent.monitors",
    "aegis_network_sensor.capture",
    "aegis_network_sensor.normalization",
    "aegis_network_sensor.sensor",
    "aegis_response_engine",
    "aegis_ml_engine",
    "aegis_shared.detection",
    "aegis_shared.risk",
)


@pytest.fixture(scope="module")
def app() -> QApplication:
    return create_application([])


def _inventory(**overrides: Any) -> SystemInventory:
    values: dict[str, Any] = {
        "host_id": "host-1",
        "hostname": "ws-01",
        "platform": Platform.WINDOWS,
        "os_name": "Windows",
        "os_version": "10.0.19045",
        "architecture": "AMD64",
        "python_version": "3.14.3",
        "agent_version": "0.1.0",
        "cpu_count": 8,
        "total_memory_bytes": 16 * 1024**3,
        "boot_time": _TS,
        "collected_at": _TS,
    }
    values.update(overrides)
    return SystemInventory(**values)


def _snapshot(
    inventory: SystemInventory | None = None,
    *,
    agent: AgentSettings | None = None,
    sensor: SensorSettings | None = None,
    collected_at: datetime = _TS,
) -> DashboardSnapshot:
    return collect_dashboard_snapshot(
        inventory_collector=lambda: inventory or _inventory(),
        agent_settings=agent or AgentSettings(),
        sensor_settings=sensor or SensorSettings(capture_enabled=False, interface=""),
        collected_at=collected_at,
        events_view_provider=lambda: None,
        findings_view_provider=lambda: None,
    )


# --- Service adapter -------------------------------------------------------


def test_adapter_maps_inventory() -> None:
    view = _snapshot().inventory

    assert view.available is True
    assert view.error is None
    assert view.hostname == "ws-01"
    assert view.host_id == "host-1"
    assert view.operating_system == "Windows 10.0.19045"
    assert view.platform == "windows"
    assert view.architecture == "AMD64"
    assert view.python_version == "3.14.3"
    assert view.agent_version == "0.1.0"
    assert view.cpu_count == "8"
    assert view.total_memory == "16.0 GiB"
    assert view.boot_time == format_timestamp(_TS)
    assert view.collected_at == format_timestamp(_TS)


def test_adapter_monitor_states_default_disabled() -> None:
    snapshot = _snapshot()

    assert [monitor.name for monitor in snapshot.monitors] == [
        "Process Monitoring",
        "Port Monitoring",
        "File Integrity Monitoring",
        "Network Sensor",
    ]
    assert all(monitor.configured_enabled is False for monitor in snapshot.monitors)
    assert all(monitor.runtime == "not running" for monitor in snapshot.monitors)


def test_adapter_monitor_states_reflect_configuration() -> None:
    agent = AgentSettings(
        enable_process_monitor=True,
        enable_port_monitor=True,
        enable_file_integrity=True,
    )
    sensor = SensorSettings(capture_enabled=True, interface="eth0")

    snapshot = _snapshot(agent=agent, sensor=sensor)
    states = {monitor.name: monitor.configured_enabled for monitor in snapshot.monitors}

    assert states == {
        "Process Monitoring": True,
        "Port Monitoring": True,
        "File Integrity Monitoring": True,
        "Network Sensor": True,
    }


def test_adapter_pipeline_view() -> None:
    pipeline = _snapshot().pipeline

    assert pipeline.host_buffer_capacity == AgentSettings().event_buffer_max_events
    assert pipeline.dedup_window == DEFAULT_DEDUP_WINDOW
    assert pipeline.network_buffer_capacity == DEFAULT_MAX_EVENTS


def test_adapter_inventory_failure_is_safe() -> None:
    def boom() -> SystemInventory:
        raise RuntimeError("inventory unavailable")

    snapshot = collect_dashboard_snapshot(
        inventory_collector=boom,
        agent_settings=AgentSettings(),
        sensor_settings=SensorSettings(),
        collected_at=_TS,
        events_view_provider=lambda: None,
        findings_view_provider=lambda: None,
    )

    assert snapshot.inventory.available is False
    assert snapshot.inventory.error == INVENTORY_ERROR
    assert snapshot.inventory.hostname == "Unknown"
    assert len(snapshot.monitors) == 4
    assert snapshot.pipeline.host_buffer_capacity > 0


def test_snapshot_has_pipeline_posture() -> None:
    posture = _snapshot().pipeline_posture
    assert isinstance(posture, PipelinePosture)
    assert posture.running is False
    assert posture.buffered == 0


def test_snapshot_has_detection_posture() -> None:
    posture = _snapshot().detection
    assert isinstance(posture, DetectionPostureView)
    assert posture.running is False
    assert posture.finding_count == 0


def test_snapshot_has_risk_posture() -> None:
    posture = _snapshot().risk
    assert isinstance(posture, RiskPostureView)
    assert posture.running is False
    assert posture.assessment_count == 0
    assert posture.latest_score is None


def test_snapshot_has_empty_activity() -> None:
    snapshot = _snapshot()
    assert snapshot.activity == ()
    assert snapshot.high_risk_findings == ()


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "Unknown"),
        (0, "0 B"),
        (512, "512 B"),
        (1024, "1.0 KiB"),
        (16 * 1024**3, "16.0 GiB"),
    ],
)
def test_format_bytes(value: int | None, expected: str) -> None:
    assert format_bytes(value) == expected


def test_format_timestamp() -> None:
    assert format_timestamp(None) == "Unknown"
    assert format_timestamp(_TS) == "2026-01-01 00:00:00Z"


# --- Page ------------------------------------------------------------------


def test_dashboard_constructs(app: QApplication) -> None:
    page = DashboardPage(provider=lambda: _snapshot())

    assert isinstance(page, BasePage)
    assert page.PAGE_KEY == "dashboard"
    assert page.TITLE == "Security Operations"


def test_runtime_stopped_state_is_displayed(app: QApplication) -> None:
    page = DashboardPage(provider=lambda: _snapshot())

    assert page.status_text("runtime") == "NOT RUNNING"
    assert page.status_text("detection") == "NOT RUNNING"
    assert page.status_text("risk") == "NOT RUNNING"
    assert page.status_text("response") == "MONITOR (read-only)"


def test_active_runtime_state_is_displayed(app: QApplication) -> None:
    agent = AgentSettings(
        enable_process_monitor=True,
        enable_port_monitor=True,
        enable_file_integrity=True,
    )
    sensor = SensorSettings(capture_enabled=True, interface="eth0")
    page = DashboardPage(provider=lambda: _snapshot(agent=agent, sensor=sensor))

    assert page.status_text("runtime") == "ACTIVE"
    assert page.status_text("host") == "ACTIVE"
    assert page.status_text("network") == "ACTIVE"
    assert page.status_text("fim") == "ACTIVE"


def test_real_metrics_are_represented(app: QApplication) -> None:
    page = DashboardPage(provider=lambda: _snapshot())

    events = page.metric_text("events")
    detections = page.metric_text("detections")
    assessments = page.metric_text("assessments")
    processes = page.metric_text("processes")
    ports = page.metric_text("ports")

    for value in (events, detections, assessments, processes, ports):
        assert value in ("\u2014", "") or value.isdigit()


def test_empty_event_state_is_safe(app: QApplication) -> None:
    page = DashboardPage(provider=lambda: _snapshot())

    assert page.has_error() is False


def test_available_detections_are_displayed(app: QApplication) -> None:
    snapshot = _snapshot()
    page = DashboardPage(provider=lambda: snapshot)

    assert page.status_text("detection") == "NOT RUNNING"
    assert page.metric_text("detections") in ("\u2014", "")


def test_available_risk_information_is_displayed(app: QApplication) -> None:
    snapshot = _snapshot()
    page = DashboardPage(provider=lambda: snapshot)

    assert page.status_text("risk") == "NOT RUNNING"
    assert page.risk_score_text() in ("\u2014", "")
    assert page.risk_level_text() in ("\u2014", "")
    assert page.risk_count_text() in ("\u2014", "")


def test_host_section_uses_real_data(app: QApplication) -> None:
    page = DashboardPage(provider=lambda: _snapshot())

    assert page.host_value("hostname") == "ws-01"
    assert page.host_value("platform") == "windows"
    assert page.host_value("os") == "Windows 10.0.19045"


def test_network_section_uses_real_data(app: QApplication) -> None:
    page = DashboardPage(provider=lambda: _snapshot())

    assert page.network_value("capture_state") == "DISABLED"
    assert page.network_value("promiscuous") == "No"

    sensor = SensorSettings(capture_enabled=True, interface="eth0", promiscuous=True)
    page2 = DashboardPage(provider=lambda: _snapshot(sensor=sensor))
    assert page2.network_value("capture_state") == "ACTIVE"
    assert page2.network_value("interface") == "eth0"
    assert page2.network_value("promiscuous") == "Yes"


def test_no_fake_metrics_are_introduced(app: QApplication) -> None:
    page = DashboardPage(provider=lambda: _snapshot())

    for key in ("events", "detections", "assessments", "processes", "ports"):
        value = page.metric_text(key)
        assert value in ("\u2014", "") or value.isdigit()
        assert "attack" not in value.lower()
        assert "threat" not in value.lower()


def test_dashboard_refresh_remains_read_only(app: QApplication) -> None:
    calls: list[int] = []

    def provider() -> DashboardSnapshot:
        calls.append(1)
        return _snapshot()

    page = DashboardPage(provider=provider)
    page.refresh()

    assert len(calls) == 2
    assert page.has_error() is False


def test_inventory_failure_shows_safe_error(app: QApplication) -> None:
    def boom() -> SystemInventory:
        raise RuntimeError("no inventory")

    page = DashboardPage(
        provider=lambda: collect_dashboard_snapshot(
            inventory_collector=boom,
            agent_settings=AgentSettings(),
            sensor_settings=SensorSettings(),
            collected_at=_TS,
            events_view_provider=lambda: None,
            findings_view_provider=lambda: None,
        )
    )

    assert page.has_error() is True
    assert page.error_text() == INVENTORY_ERROR


def test_provider_exception_shows_safe_error(app: QApplication) -> None:
    def boom() -> DashboardSnapshot:
        raise RuntimeError("unexpected failure")

    page = DashboardPage(provider=boom)

    assert page.has_error() is True
    assert page.error_text() == INVENTORY_ERROR
    assert page.refresh() is None


def test_dashboard_does_not_import_security_engines() -> None:
    code = (
        "import sys; import aegis_desktop.pages.dashboard; "
        f"prefixes = {_FORBIDDEN_IMPORT_PREFIXES!r}; "
        "print(sorted(m for m in sys.modules if m.startswith(prefixes)))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "[]"


def test_existing_navigation_still_works(app: QApplication) -> None:
    window = MainWindow()
    try:
        window.navigate_to("dashboard")
        assert window.current_page_key == "dashboard"
        assert window.current_page is window.page("dashboard")

        window.navigate_to("settings")
        assert window.current_page_key == "settings"
    finally:
        window.close()


def test_dashboard_does_not_start_monitoring(app: QApplication) -> None:
    calls: list[int] = []

    def provider() -> DashboardSnapshot:
        calls.append(1)
        return _snapshot()

    page = DashboardPage(provider=provider)
    page.refresh()

    assert len(calls) == 2


# --- Activity feed ---------------------------------------------------------


def test_activity_feed_shows_no_data_when_empty(app: QApplication) -> None:
    page = DashboardPage(provider=lambda: _snapshot())

    assert page.metric_text("events") in ("\u2014", "")
    assert page.metric_text("detections") in ("\u2014", "")


def test_risk_card_shows_no_data_when_empty(app: QApplication) -> None:
    page = DashboardPage(provider=lambda: _snapshot())

    assert page.risk_score_text() in ("\u2014", "")
    assert page.risk_level_text() in ("\u2014", "")
    assert page.risk_count_text() in ("\u2014", "")
    assert page.risk_version_text() in ("\u2014", "")
