"""Deterministic tests for the read-only Settings page integration (GUI-9).

Configuration is injected/mocked; no test reads real machine state, starts a
runtime, or requires privileges. Qt runs with the offscreen platform.
"""

from __future__ import annotations

import os
import subprocess
import sys
from datetime import UTC, datetime

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason="desktop extra not installed")

from PySide6.QtWidgets import QApplication, QCheckBox, QComboBox, QLineEdit, QSpinBox

from aegis_agent.config import AgentSettings, SymlinkPolicy
from aegis_desktop.app import create_application
from aegis_desktop.pages.base import BasePage
from aegis_desktop.pages.settings import SettingsPage
from aegis_desktop.services.settings import (
    MISSING,
    NOT_RUNNING,
    SETTINGS_ERROR,
    SettingsView,
    collect_settings_view,
)
from aegis_desktop.window import MainWindow
from aegis_ml_engine.config import MLEngineSettings
from aegis_network_sensor.config import SensorSettings
from aegis_response_engine.config import ResponseEngineSettings
from aegis_shared.detection import DetectionSettings
from aegis_shared.risk import RiskSettings

_TS = datetime(2026, 1, 1, tzinfo=UTC)

#: Packages the application must not load just by opening it.
_FORBIDDEN_IMPORT_PREFIXES = (
    "aegis_agent.monitors",
    "aegis_network_sensor.capture",
    "aegis_network_sensor.normalization",
    "aegis_network_sensor.sensor",
    "aegis_response_engine.actions",
    "aegis_response_engine.executors",
    "aegis_ml_engine.features",
    "aegis_ml_engine.scoring",
)


@pytest.fixture(scope="module")
def app() -> QApplication:
    return create_application([])


def _agent(**overrides: object) -> AgentSettings:
    values: dict[str, object] = {
        "agent_id": "agent-1",
        "backend_url": "http://127.0.0.1:8000",
        "heartbeat_interval": 30,
        "event_buffer_max_events": 1000,
        "enable_process_monitor": False,
        "enable_port_monitor": False,
        "enable_connection_monitor": False,
        "enable_file_integrity": False,
        "enable_yara": False,
        "file_integrity_paths": [],
        "file_integrity_interval": 300,
        "file_integrity_max_hash_bytes": 10 * 1024 * 1024,
        "file_integrity_symlink_policy": SymlinkPolicy.SKIP,
    }
    values.update(overrides)
    return AgentSettings(**values)  # type: ignore[arg-type]


def _sensor(**overrides: object) -> SensorSettings:
    values: dict[str, object] = {
        "interface": "",
        "capture_enabled": False,
        "promiscuous": False,
        "capture_filter": "",
        "max_packets_per_run": 1000,
        "max_packet_bytes": 65535,
        "local_addresses": [],
        "flow_window_seconds": 10,
    }
    values.update(overrides)
    return SensorSettings(**values)  # type: ignore[arg-type]


def _view(
    *,
    agent: AgentSettings | None = None,
    sensor: SensorSettings | None = None,
    detection: DetectionSettings | None = None,
    risk: RiskSettings | None = None,
    response: ResponseEngineSettings | None = None,
    ml: MLEngineSettings | None = None,
) -> SettingsView:
    return collect_settings_view(
        agent_settings=agent or _agent(),
        sensor_settings=sensor or _sensor(),
        detection_settings=detection or DetectionSettings(),
        risk_settings=risk or RiskSettings(),
        response_settings=response or ResponseEngineSettings(),
        ml_settings=ml or MLEngineSettings(),
        collected_at=_TS,
    )


def _empty_view() -> SettingsView:
    return SettingsView(available=True, error=None, collected_at=None)


# --- Adapter ---------------------------------------------------------------


def test_adapter_reads_agent_settings() -> None:
    view = _view(agent=_agent(agent_id="host-42"))

    assert view.available is True
    assert view.value_for("Agent", "Agent ID") == "host-42"
    assert view.value_for("Agent", "Event Buffer Capacity") == "1000"


def test_adapter_process_monitor_configuration() -> None:
    view = _view(agent=_agent(enable_process_monitor=True))

    assert view.value_for("Monitors (configuration)", "Process Monitoring") == "Enabled"


def test_adapter_port_monitor_configuration() -> None:
    view = _view(agent=_agent(enable_port_monitor=True))

    assert view.value_for("Monitors (configuration)", "Port Monitoring") == "Enabled"


def test_adapter_fim_configuration() -> None:
    view = _view(
        agent=_agent(
            enable_file_integrity=True,
            file_integrity_paths=["C:\\a", "C:\\b"],
            file_integrity_symlink_policy=SymlinkPolicy.REPORT,
        )
    )

    assert view.value_for("File Integrity", "Enabled") == "Enabled"
    assert view.value_for("File Integrity", "Configured Paths") == "2"
    assert view.value_for("File Integrity", "Symlink Policy") == "report"
    assert "C:\\a" in (view.value_for("File Integrity", "Paths") or "")


def test_adapter_network_configuration() -> None:
    view = _view(sensor=_sensor(interface="eth0", local_addresses=["10.0.0.5"]))

    assert view.value_for("Network Sensor", "Interface") == "eth0"
    assert view.value_for("Network Sensor", "Local Addresses") == "10.0.0.5"
    assert view.value_for("Network Sensor", "Capture Enabled") == "Disabled"


def test_adapter_pipeline_configuration() -> None:
    view = _view(agent=_agent(event_buffer_max_events=500))

    assert view.value_for("Agent", "Event Buffer Capacity") == "500"


def test_adapter_detection_configuration() -> None:
    view = _view(detection=DetectionSettings(suspicious_listen_ports=[8080, 9090]))

    assert view.value_for("Detection", "Enabled") == "Enabled"
    assert view.value_for("Detection", "Suspicious Listen Ports") == "8080, 9090"


def test_adapter_detection_rule_count_needs_runtime() -> None:
    view = _view()

    assert view.value_for("Detection", "Rule Count") == "Not connected"


def test_adapter_risk_configuration() -> None:
    view = _view(risk=RiskSettings(scoring_version="3"))

    assert view.value_for("Risk", "Scoring Version") == "3"
    assert view.value_for("Risk", "Thresholds (low/med/high/crit)") == "10/25/40/60"


def test_adapter_response_configuration() -> None:
    view = _view(response=ResponseEngineSettings())

    assert view.value_for("Response Safety", "Mode") == "monitor"
    assert view.value_for("Response Safety", "Dry Run") == "Enabled"
    assert view.value_for("Response Safety", "Approval Required") == "Yes"
    assert view.value_for("Response Safety", "Enforcement Enabled") == "No"


def test_adapter_runtime_status_defaults_to_not_running() -> None:
    view = _view()

    assert view.value_for("Runtime Status", "Event Pipeline") == NOT_RUNNING
    assert view.value_for("Runtime Status", "Detection Engine") == NOT_RUNNING
    assert view.value_for("Runtime Status", "Risk Engine") == NOT_RUNNING


def test_adapter_missing_optional_configuration() -> None:
    view = _view(sensor=_sensor(interface=""), agent=_agent(agent_id="", file_integrity_paths=[]))

    assert view.value_for("Network Sensor", "Interface") == MISSING
    assert view.value_for("Agent", "Agent ID") == MISSING
    assert view.value_for("File Integrity", "Paths") == MISSING


def test_adapter_malformed_configuration_is_safe() -> None:
    class _Boom:
        @property
        def enabled_monitors(self) -> object:
            raise RuntimeError("boom")

    view = collect_settings_view(
        agent_settings=_Boom(),
        sensor_settings=_sensor(),
        detection_settings=DetectionSettings(),
        risk_settings=RiskSettings(),
        response_settings=ResponseEngineSettings(),
        ml_settings=MLEngineSettings(),
    )

    assert view.available is False
    assert view.error == SETTINGS_ERROR
    assert view.posture == ()


def test_adapter_redacts_secrets() -> None:
    # Response settings expose no secret; assert no secret-looking value leaks
    # from any displayed field, and that secrets are simply not selected.
    view = _view()

    values = [field.value for field in view.posture]
    for section in view.sections:
        values.extend(field.value for field in section.fields)
    joined = " ".join(values).lower()
    for forbidden in ("password", "api_key", "token", "secret", "bearer"):
        assert forbidden not in joined


def test_adapter_does_not_mutate_settings() -> None:
    agent = _agent()
    sensor = _sensor()
    before_agent = agent.model_dump()
    before_sensor = sensor.model_dump()

    collect_settings_view(
        agent_settings=agent,
        sensor_settings=sensor,
        detection_settings=DetectionSettings(),
        risk_settings=RiskSettings(),
        response_settings=ResponseEngineSettings(),
        ml_settings=MLEngineSettings(),
    )

    assert agent.model_dump() == before_agent
    assert sensor.model_dump() == before_sensor


def test_adapter_output_is_deterministic() -> None:
    first = _view()
    second = _view()

    assert [f.label for f in first.posture] == [f.label for f in second.posture]
    assert [s.title for s in first.sections] == [s.title for s in second.sections]
    assert first.sections == second.sections


def test_adapter_sections_present() -> None:
    view = _view()

    titles = [section.title for section in view.sections]
    for expected in (
        "Agent",
        "Monitors (configuration)",
        "File Integrity",
        "Network Sensor",
        "Detection",
        "Risk",
        "Response Safety",
        "Runtime Status",
    ):
        assert expected in titles


# --- Page ------------------------------------------------------------------


def test_page_constructs(app: QApplication) -> None:
    page = SettingsPage(provider=_empty_view)

    assert isinstance(page, BasePage)
    assert page.PAGE_KEY == "settings"
    assert page.TITLE == "Settings"


def test_initial_page_does_not_read(app: QApplication) -> None:
    calls: list[int] = []

    def provider() -> SettingsView:
        calls.append(1)
        return _empty_view()

    page = SettingsPage(provider=provider)

    assert calls == []
    assert page.section_titles() == ()
    assert page.last_updated_text() == "Last updated: —"


def test_configuration_displayed(app: QApplication) -> None:
    page = SettingsPage(provider=lambda: _view(agent=_agent(agent_id="agent-xyz")))
    page.refresh()

    assert page.value_for("Agent", "Agent ID") == "agent-xyz"
    assert "Agent" in page.section_titles()
    assert "Risk" in page.section_titles()


def test_runtime_status_displayed(app: QApplication) -> None:
    page = SettingsPage(provider=lambda: _view())
    page.refresh()

    assert page.value_for("Runtime Status", "Event Pipeline") == NOT_RUNNING


def test_posture_displayed(app: QApplication) -> None:
    page = SettingsPage(provider=lambda: _view())
    page.refresh()

    assert page.posture_value("Network Capture") == "Disabled"
    assert page.posture_value("Response Mode") == "monitor"
    assert page.posture_value("Approval Required") == "Yes"


def test_posture_distinguishes_configured_from_running(app: QApplication) -> None:
    page = SettingsPage(provider=lambda: _view(agent=_agent(enable_process_monitor=True)))
    page.refresh()

    assert page.value_for("Monitors (configuration)", "Process Monitoring") == "Enabled"
    assert page.value_for("Runtime Status", "Detection Engine") == NOT_RUNNING


def test_refresh_behavior(app: QApplication) -> None:
    calls: list[int] = []

    def provider() -> SettingsView:
        calls.append(1)
        return _view()

    page = SettingsPage(provider=provider)

    page.refresh()
    assert len(calls) == 1
    page.refresh()
    assert len(calls) == 2


def test_refresh_rereads_state(app: QApplication) -> None:
    queue = [_view(agent=_agent(agent_id="first")), _view(agent=_agent(agent_id="second"))]
    page = SettingsPage(provider=lambda: queue.pop(0))

    page.refresh()
    assert page.value_for("Agent", "Agent ID") == "first"
    page.refresh()
    assert page.value_for("Agent", "Agent ID") == "second"


def test_refresh_does_not_start_producers(app: QApplication) -> None:
    from aegis_shared.pipeline import get_active_pipeline

    page = SettingsPage(provider=lambda: _view())
    page.refresh()

    assert get_active_pipeline() is None  # nothing was started


def test_read_only_widgets_only(app: QApplication) -> None:
    page = SettingsPage(provider=lambda: _view())
    page.refresh()

    # No editable security controls anywhere on the page.
    assert page.findChildren(QLineEdit) == []
    assert page.findChildren(QComboBox) == []
    assert page.findChildren(QSpinBox) == []
    assert page.findChildren(QCheckBox) == []


def test_no_editable_or_response_controls(app: QApplication) -> None:
    from PySide6.QtWidgets import QPushButton

    page = SettingsPage(provider=lambda: _view())
    page.refresh()

    labels = {button.text().lower() for button in page.findChildren(QPushButton)}
    assert labels <= {"refresh"}
    forbidden_words = (
        "enable",
        "disable",
        "approve",
        "block",
        "kill",
        "quarantine",
        "save",
        "apply",
    )
    for forbidden in forbidden_words:
        assert not any(forbidden in label for label in labels)


def test_safe_missing_configuration_state(app: QApplication) -> None:
    page = SettingsPage(provider=_empty_view)
    page.refresh()

    assert page.has_error() is False
    assert page.value_for("Agent", "Agent ID") is None


def test_safe_provider_failure(app: QApplication) -> None:
    def boom() -> SettingsView:
        raise RuntimeError("unexpected failure")

    page = SettingsPage(provider=boom)

    assert page.refresh() is None
    assert page.has_error() is True
    assert page.error_text() == SETTINGS_ERROR


def test_unavailable_view_shows_error(app: QApplication) -> None:
    page = SettingsPage(
        provider=lambda: SettingsView(available=False, error=SETTINGS_ERROR, collected_at=None)
    )
    page.refresh()

    assert page.has_error() is True
    assert page.section_titles() == ()


def test_navigation_regression(app: QApplication) -> None:
    window = MainWindow()
    try:
        window.navigate_to("settings")
        assert window.current_page_key == "settings"
        assert window.current_page is window.page("settings")

        window.navigate_to("dashboard")
        assert window.current_page_key == "dashboard"
    finally:
        window.close()


# --- Safety ----------------------------------------------------------------


def test_application_does_not_load_security_runtime() -> None:
    code = (
        "import sys; import aegis_desktop.app, aegis_desktop.window; "
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


def test_importing_settings_page_does_not_start_runtime() -> None:
    code = (
        "import sys; "
        "from aegis_desktop.pages.settings import SettingsPage; "
        "from aegis_shared.pipeline import get_active_pipeline; "
        "from aegis_shared.detection import get_active_engine; "
        "from aegis_shared.risk import get_active_risk_engine; "
        "assert get_active_pipeline() is None; "
        "assert get_active_engine() is None; "
        "assert get_active_risk_engine() is None; "
        "print('ok')"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"
