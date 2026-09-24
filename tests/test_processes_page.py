"""Deterministic tests for the Processes page integration (GUI-3).

Process data is mocked via injected snapshots/views; no test depends on the real
machine's process list. Qt runs with the offscreen platform and no privileges.
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

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QPushButton

from aegis_agent.monitors.process import ProcessRecord, ProcessSnapshot
from aegis_desktop.app import create_application
from aegis_desktop.pages.base import BasePage
from aegis_desktop.pages.processes import ProcessesPage
from aegis_desktop.services.processes import (
    MISSING,
    PROCESS_ERROR,
    ProcessRow,
    ProcessSnapshotView,
    collect_process_view,
)
from aegis_desktop.window import MainWindow

_TS = datetime(2026, 1, 1, tzinfo=UTC)
_TS2 = datetime(2026, 1, 2, tzinfo=UTC)

#: Packages the application must not load just by opening it.
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


def _record(**overrides: Any) -> ProcessRecord:
    values: dict[str, Any] = {
        "pid": 100,
        "ppid": 1,
        "name": "proc",
        "parent_name": "init",
        "executable_path": "C:\\bin\\proc.exe",
        "username": "alice",
        "command_line": "proc --flag",
        "create_time": _TS,
    }
    values.update(overrides)
    return ProcessRecord(**values)


def _snapshot(records: list[ProcessRecord]) -> ProcessSnapshot:
    return ProcessSnapshot(processes=tuple(records), captured_at=_TS)


def _row(**overrides: Any) -> ProcessRow:
    values: dict[str, Any] = {
        "pid": 100,
        "name": "proc",
        "executable": "C:\\bin\\proc.exe",
        "username": "alice",
        "ppid": 1,
        "parent_name": "init",
        "create_time": _TS,
        "identity": "100:2026-01-01T00:00:00+00:00",
        "command_line_available": True,
    }
    values.update(overrides)
    return ProcessRow(**values)


def _view(
    rows: tuple[ProcessRow, ...] = (),
    *,
    available: bool = True,
    error: str | None = None,
    collected_at: datetime | None = _TS,
) -> ProcessSnapshotView:
    return ProcessSnapshotView(
        available=available, error=error, collected_at=collected_at, rows=rows
    )


def _display_values(page: ProcessesPage) -> list[str]:
    model = page.source_model
    return [
        str(model.data(model.index(row, column), Qt.ItemDataRole.DisplayRole))
        for row in range(model.rowCount())
        for column in range(model.columnCount())
    ]


# --- Adapter ---------------------------------------------------------------


def test_adapter_converts_snapshot() -> None:
    view = collect_process_view(collector=lambda: _snapshot([_record(), _record(pid=200)]))

    assert view.available is True
    assert view.error is None
    assert view.count == 2
    assert view.collected_at == _TS


def test_adapter_preserves_pid() -> None:
    view = collect_process_view(collector=lambda: _snapshot([_record(pid=4321)]))

    assert view.rows[0].pid == 4321


def test_adapter_preserves_name() -> None:
    view = collect_process_view(collector=lambda: _snapshot([_record(name="explorer.exe")]))

    assert view.rows[0].name == "explorer.exe"


def test_adapter_preserves_executable() -> None:
    view = collect_process_view(
        collector=lambda: _snapshot([_record(executable_path="C:\\Windows\\notepad.exe")])
    )

    assert view.rows[0].executable == "C:\\Windows\\notepad.exe"


def test_adapter_preserves_identity() -> None:
    record = _record(pid=99)
    view = collect_process_view(collector=lambda: _snapshot([record]))

    assert view.rows[0].identity == record.identity.key


def test_adapter_handles_missing_optional_values() -> None:
    record = _record(
        ppid=None,
        name=None,
        parent_name=None,
        executable_path=None,
        username=None,
        command_line=None,
        create_time=None,
    )
    view = collect_process_view(collector=lambda: _snapshot([record]))
    row = view.rows[0]

    assert row.ppid is None
    assert row.name is None
    assert row.parent_name is None
    assert row.executable is None
    assert row.username is None
    assert row.create_time is None
    assert row.command_line_available is False


def test_adapter_supports_empty_snapshot() -> None:
    view = collect_process_view(collector=lambda: _snapshot([]))

    assert view.available is True
    assert view.count == 0
    assert view.rows == ()


def test_adapter_collection_failure_is_safe() -> None:
    def boom() -> ProcessSnapshot:
        raise OSError("access denied")

    view = collect_process_view(collector=boom)

    assert view.available is False
    assert view.error == PROCESS_ERROR
    assert view.rows == ()


# --- Page ------------------------------------------------------------------


def test_page_constructs(app: QApplication) -> None:
    page = ProcessesPage(provider=lambda: _view())

    assert isinstance(page, BasePage)
    assert page.PAGE_KEY == "processes"
    assert page.TITLE == "Processes"
    assert page.column_headers()[0] == "PID"


def test_snapshot_populates_table(app: QApplication) -> None:
    page = ProcessesPage(provider=lambda: _view((_row(pid=1), _row(pid=2))))

    page.refresh()

    assert page.row_count() == 2
    assert page.source_model.rowCount() == 2
    assert page.source_model.columnCount() == len(page.column_headers())


def test_process_count_is_correct(app: QApplication) -> None:
    page = ProcessesPage(provider=lambda: _view((_row(), _row(pid=2), _row(pid=3))))

    page.refresh()

    assert page.process_count_text() == "Processes: 3"


def test_refresh_updates_table(app: QApplication) -> None:
    queue: list[ProcessSnapshotView] = [
        _view((_row(pid=1),)),
        _view((_row(pid=1), _row(pid=2))),
    ]
    page = ProcessesPage(provider=lambda: queue.pop(0))

    assert page.row_count() == 0  # nothing collected automatically
    page.refresh()
    assert page.row_count() == 1
    page.refresh()
    assert page.row_count() == 2


def test_last_updated_changes_on_refresh(app: QApplication) -> None:
    queue: list[ProcessSnapshotView] = [
        _view((_row(),), collected_at=_TS),
        _view((_row(),), collected_at=_TS2),
    ]
    page = ProcessesPage(provider=lambda: queue.pop(0))

    page.refresh()
    assert "2026-01-01" in page.last_updated_text()

    page.refresh()
    assert "2026-01-02" in page.last_updated_text()


def test_collection_failure_produces_safe_error(app: QApplication) -> None:
    page = ProcessesPage(provider=lambda: _view(available=False, error=PROCESS_ERROR))

    page.refresh()

    assert page.has_error() is True
    assert page.error_text() == PROCESS_ERROR
    assert page.row_count() == 0
    assert page.process_count_text() == "Processes: —"


def test_provider_exception_produces_safe_error(app: QApplication) -> None:
    def boom() -> ProcessSnapshotView:
        raise RuntimeError("unexpected failure")

    page = ProcessesPage(provider=boom)

    assert page.refresh() is None
    assert page.has_error() is True
    assert page.error_text() == PROCESS_ERROR


def test_no_destructive_process_action_exists(app: QApplication) -> None:
    page = ProcessesPage(provider=lambda: _view((_row(),)))

    labels = {button.text().lower() for button in page.findChildren(QPushButton)}

    assert labels <= {"refresh"}
    for destructive in ("kill", "terminate", "suspend", "resume", "restart", "quarantine"):
        assert not any(destructive in label for label in labels)


def test_command_line_is_not_displayed_raw(app: QApplication) -> None:
    record = _record(command_line="TOPSECRET --password=hunter2")
    page = ProcessesPage(
        provider=lambda: _view(
            (
                ProcessRow(
                    pid=record.pid,
                    name=record.name,
                    executable=record.executable_path,
                    username=record.username,
                    ppid=record.ppid,
                    parent_name=record.parent_name,
                    create_time=record.create_time,
                    identity=record.identity.key,
                    command_line_available=record.command_line is not None,
                ),
            )
        )
    )

    page.refresh()

    values = _display_values(page)
    assert "Available" in values
    assert not any("TOPSECRET" in value for value in values)
    assert not any("hunter2" in value for value in values)


def test_missing_values_display_placeholder(app: QApplication) -> None:
    page = ProcessesPage(
        provider=lambda: _view(
            (_row(pid=None, name=None, executable=None, username=None, ppid=None),)
        )
    )

    page.refresh()

    assert page.row_at(0).pid is None
    assert MISSING in _display_values(page)


def test_sorting_is_numeric_for_pid(app: QApplication) -> None:
    page = ProcessesPage(provider=lambda: _view((_row(pid=300), _row(pid=100), _row(pid=200))))
    page.refresh()

    page.proxy_model.sort(0, Qt.SortOrder.AscendingOrder)
    pids = [page.proxy_model.index(row, 0).data() for row in range(page.proxy_model.rowCount())]

    assert pids == ["100", "200", "300"]


def test_executable_tooltip_shows_full_path(app: QApplication) -> None:
    long_path = "C:\\" + "very-long-directory\\" * 5 + "app.exe"
    page = ProcessesPage(provider=lambda: _view((_row(executable=long_path),)))
    page.refresh()

    tooltip = page.source_model.data(page.source_model.index(0, 2), Qt.ItemDataRole.ToolTipRole)

    assert tooltip == long_path


def test_existing_navigation_still_works(app: QApplication) -> None:
    window = MainWindow()
    try:
        window.navigate_to("processes")
        assert window.current_page_key == "processes"
        assert window.current_page is window.page("processes")

        window.navigate_to("dashboard")
        assert window.current_page_key == "dashboard"
    finally:
        window.close()


# --- Safety / import -------------------------------------------------------


def test_opening_the_page_does_not_collect_automatically(app: QApplication) -> None:
    calls: list[int] = []

    def provider() -> ProcessSnapshotView:
        calls.append(1)
        return _view()

    page = ProcessesPage(provider=provider)

    assert calls == []
    assert page.row_count() == 0
    assert page.process_count_text() == "Processes: —"


def test_refresh_is_one_shot(app: QApplication) -> None:
    calls: list[int] = []

    def provider() -> ProcessSnapshotView:
        calls.append(1)
        return _view((_row(),))

    page = ProcessesPage(provider=provider)

    page.refresh()
    assert len(calls) == 1
    page.refresh()
    assert len(calls) == 2


def test_application_does_not_load_security_engines() -> None:
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
