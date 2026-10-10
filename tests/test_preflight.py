"""Deterministic tests for the Step 38 preflight diagnostic checklist.

The checklist is presentation + read-only probing: tests never open a capture,
never start a real runtime and never wait on the production 400 ms/1 s pacing
(the dialog accepts shorter intervals, and one test drives the synchronous
``run_checks()`` path instead of an event loop).
"""

from __future__ import annotations

import os
import time
from typing import ClassVar

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason="desktop extra not installed")

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QApplication, QDialog

from aegis_desktop import window as window_module
from aegis_desktop.app import create_application
from aegis_desktop.preflight import (
    ADMIN_LABEL,
    CHECK_INTERVAL_MS,
    CHECKS,
    COMPLETE_FOOTER,
    DRIVER_LABEL,
    ML_LABEL,
    OK_TEXT,
    PREFLIGHT_ENV_VAR,
    RUNNING_FOOTER,
    SETTLE_DELAY_MS,
    STATE_ERROR,
    STATE_OK,
    STATE_PENDING,
    STATE_WARNING,
    TITLE,
    DiagnosticResult,
    PreflightDialog,
    check_admin_privileges,
    check_ml_engine,
    check_network_driver,
    preflight_enabled_from_env,
)
from aegis_desktop.services.monitoring import (
    CAPTURE_INACTIVE,
    MonitoringStatus,
    NetworkCounters,
)
from aegis_desktop.window import MainWindow

_ADMIN_WARNING = "\U0001f7e1 WARNING: Running in Restricted Mode (Dry-Run Only)"
_TERMINAL_STATES = {STATE_OK, STATE_WARNING, STATE_ERROR}


@pytest.fixture(scope="module")
def app() -> QApplication:
    return create_application([])


# --- Probe contract ---------------------------------------------------------


def test_check_catalog_matches_the_documented_checklist() -> None:
    labels = tuple(label for _key, label, _runner in CHECKS)

    assert labels == (DRIVER_LABEL, ADMIN_LABEL, ML_LABEL)
    assert all(callable(runner) for _key, _label, runner in CHECKS)
    assert CHECK_INTERVAL_MS == 400
    assert SETTLE_DELAY_MS == 1000


def test_driver_check_is_a_read_only_probe() -> None:
    result = check_network_driver()

    assert isinstance(result, DiagnosticResult)
    assert result.key == "driver"
    assert result.label == DRIVER_LABEL
    assert result.state in _TERMINAL_STATES
    assert result.status
    assert result.detail


def test_admin_check_reports_the_documented_warning_when_restricted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("aegis_desktop.preflight._is_admin", lambda: False)

    result = check_admin_privileges()

    assert result.key == "admin"
    assert result.state == STATE_WARNING
    assert result.status == _ADMIN_WARNING
    assert "Restricted Mode" in result.status


def test_admin_check_reports_ok_when_elevated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aegis_desktop.preflight._is_admin", lambda: True)

    result = check_admin_privileges()

    assert result.state == STATE_OK
    assert result.status == OK_TEXT


def test_ml_check_reports_engine_readiness() -> None:
    result = check_ml_engine()

    assert result.key == "ml"
    assert result.label == ML_LABEL
    assert result.state in _TERMINAL_STATES
    assert result.detail


def test_preflight_env_kill_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(PREFLIGHT_ENV_VAR, raising=False)
    assert preflight_enabled_from_env() is True

    for value in ("0", "false", "OFF", "no"):
        monkeypatch.setenv(PREFLIGHT_ENV_VAR, value)
        assert preflight_enabled_from_env() is False

    monkeypatch.setenv(PREFLIGHT_ENV_VAR, "1")
    assert preflight_enabled_from_env() is True


# --- Dialog -----------------------------------------------------------------


def test_dialog_is_frameless_and_lists_every_check(app: QApplication) -> None:
    dialog = PreflightDialog()

    assert dialog.objectName() == "PreflightDialog"
    assert dialog.windowTitle() == TITLE
    assert bool(dialog.windowFlags() & Qt.WindowType.FramelessWindowHint)
    assert dialog.checks() == (
        ("driver", DRIVER_LABEL),
        ("admin", ADMIN_LABEL),
        ("ml", ML_LABEL),
    )
    assert dialog.status_texts() == ("\u2014", "\u2014", "\u2014")
    assert dialog.status_states() == (STATE_PENDING, STATE_PENDING, STATE_PENDING)
    assert dialog.footer_text() == RUNNING_FOOTER
    assert dialog.is_completed() is False
    assert dialog.interval_ms == CHECK_INTERVAL_MS
    assert dialog.settle_ms == SETTLE_DELAY_MS


def test_run_checks_applies_results_without_an_event_loop(app: QApplication) -> None:
    dialog = PreflightDialog()

    results = dialog.run_checks()

    assert len(results) == len(CHECKS)
    assert dialog.results() == results
    assert dialog.status_states() == tuple(result.state for result in results)
    assert all(state in _TERMINAL_STATES for state in dialog.status_states())
    assert all(text not in {"...", "\u2014"} for text in dialog.status_texts())
    assert all(hint for hint in dialog.detail_texts())
    # The engine only starts after the settle delay, which never runs here.
    assert dialog.is_completed() is False

    admin = results[1]
    if admin.state == STATE_OK:
        assert admin.status == OK_TEXT
    else:
        assert admin.status == _ADMIN_WARNING


def test_timed_sequence_finishes_and_reports_ready(app: QApplication) -> None:
    dialog = PreflightDialog(interval_ms=1, settle_ms=1)
    dialog.start()

    deadline = time.monotonic() + 15.0
    while not dialog.is_completed() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.002)

    assert dialog.is_completed() is True
    assert dialog.footer_text() == COMPLETE_FOOTER
    assert all(state in _TERMINAL_STATES for state in dialog.status_states())

    dialog._finish()  # idempotent: never closes twice
    assert dialog.is_completed() is True


def test_cancel_leaves_the_dialog_incomplete(app: QApplication) -> None:
    dialog = PreflightDialog(interval_ms=50, settle_ms=50)
    dialog.start()

    dialog.reject()

    assert dialog.is_completed() is False


def test_exec_starts_the_probes_so_the_dialog_closes_itself(app: QApplication) -> None:
    """Regression: the window only calls ``exec()``, which must start the probes.

    Without this the sequence never advances, every check stays pending and
    ``exec()`` blocks forever - so monitoring never starts.
    """
    dialog = PreflightDialog(interval_ms=1, settle_ms=1)
    QTimer.singleShot(5000, dialog.reject)  # safety net: never hang the suite

    code = dialog.exec()

    assert code == QDialog.DialogCode.Accepted
    assert dialog.is_completed() is True
    assert dialog.footer_text() == COMPLETE_FOOTER
    assert all(state in _TERMINAL_STATES for state in dialog.status_states())


# --- Window interception ----------------------------------------------------


class FakeController:
    """Minimal MonitoringController double recording start/stop calls."""

    def __init__(self, running: bool = False, events: list[str] | None = None) -> None:
        self.is_running = running
        self.poll_interval_ms = 2000
        self.started = 0
        self.stopped = 0
        self.events = events if events is not None else []

    def start(self) -> bool:
        self.started += 1
        self.is_running = True
        self.events.append("start")
        return True

    def stop(self) -> None:
        self.stopped += 1
        self.is_running = False
        self.events.append("stop")

    def poll(self) -> None:
        return None

    def status(self) -> MonitoringStatus:
        return MonitoringStatus(
            running=self.is_running,
            capture_state=CAPTURE_INACTIVE,
            capture_error=None,
            interface=None,
            counters=NetworkCounters(packets=None, bytes=None, flows=None, active_flows=None),
        )


class FakePreflightDialog:
    """Dialog double that never opens an event loop."""

    completed = True
    constructed: ClassVar[list[FakePreflightDialog]] = []
    events: ClassVar[list[str]] = []

    def __init__(self, parent: object = None, **_kwargs: object) -> None:
        self.completed = type(self).completed
        type(self).constructed.append(self)
        type(self).events.append("preflight")

    def exec(self) -> int:
        return 0

    def is_completed(self) -> bool:
        return self.completed


@pytest.fixture
def fake_preflight(monkeypatch: pytest.MonkeyPatch) -> type[FakePreflightDialog]:
    FakePreflightDialog.constructed = []
    FakePreflightDialog.events = []
    FakePreflightDialog.completed = True
    monkeypatch.setattr(window_module, "PreflightDialog", FakePreflightDialog)
    return FakePreflightDialog


def test_start_click_runs_preflight_before_the_engine(
    app: QApplication, fake_preflight: type[FakePreflightDialog]
) -> None:
    events: list[str] = []
    controller = FakeController(events=events)
    fake_preflight.events = events  # shared order log: dialog then engine
    window = MainWindow(controller=controller)
    try:
        window.preflight_enabled = True

        window.toggle_monitoring()

        assert len(fake_preflight.constructed) == 1
        assert fake_preflight.constructed[0].is_completed() is True
        assert controller.started == 1
        assert events == ["preflight", "start"]
    finally:
        window.close()


def test_cancelled_preflight_does_not_start_the_engine(
    app: QApplication, fake_preflight: type[FakePreflightDialog]
) -> None:
    controller = FakeController()
    window = MainWindow(controller=controller)
    try:
        window.preflight_enabled = True
        fake_preflight.completed = False

        window.toggle_monitoring()

        assert controller.started == 0
        assert "Preflight cancelled" in window.statusBar().currentMessage()
    finally:
        window.close()


def test_preflight_can_be_bypassed_for_automated_ui_tests(
    app: QApplication, fake_preflight: type[FakePreflightDialog]
) -> None:
    controller = FakeController()
    window = MainWindow(controller=controller)
    try:
        window.preflight_enabled = False

        window.toggle_monitoring()

        assert fake_preflight.constructed == []
        assert controller.started == 1
    finally:
        window.close()


def test_stop_path_never_opens_the_preflight_dialog(
    app: QApplication, fake_preflight: type[FakePreflightDialog]
) -> None:
    controller = FakeController(running=True)
    window = MainWindow(controller=controller)
    try:
        window.toggle_monitoring()

        assert fake_preflight.constructed == []
        assert controller.stopped == 1
        assert controller.started == 0
    finally:
        window.close()


def test_direct_start_monitoring_call_skips_the_dialog(
    app: QApplication, fake_preflight: type[FakePreflightDialog]
) -> None:
    controller = FakeController()
    window = MainWindow(controller=controller)
    try:
        window.preflight_enabled = True

        assert window.start_monitoring() is True

        assert fake_preflight.constructed == []
        assert controller.started == 1
    finally:
        window.close()


def test_window_reads_the_env_kill_switch(
    app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(PREFLIGHT_ENV_VAR, "0")
    assert preflight_enabled_from_env() is False

    controller = FakeController()
    window = MainWindow(controller=controller)
    try:
        assert window.preflight_enabled is False
    finally:
        window.close()
