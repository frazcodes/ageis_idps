"""Deterministic tests for the Network page integration (GUI-4).

Local listening-endpoint data is mocked via injected snapshots/views; no test
depends on the machine's real ports and no packet capture occurs. Qt runs with
the offscreen platform and no privileges.
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

from aegis_agent.monitors.port import PortRecord, PortSnapshot
from aegis_desktop.app import create_application
from aegis_desktop.pages.base import BasePage
from aegis_desktop.pages.network import NetworkPage
from aegis_desktop.services.network import (
    MISSING,
    PORT_ERROR,
    PortRow,
    PortSnapshotView,
    collect_port_view,
)
from aegis_desktop.window import MainWindow
from aegis_shared.enums import AddressFamily, TransportProtocol

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


def _record(**overrides: Any) -> PortRecord:
    values: dict[str, Any] = {
        "protocol": TransportProtocol.TCP,
        "address_family": AddressFamily.IPV4,
        "local_address": "0.0.0.0",
        "local_port": 8000,
        "status": "LISTEN",
        "pid": 100,
        "process_name": "svc",
        "process_create_time": _TS,
    }
    values.update(overrides)
    return PortRecord(**values)


def _snapshot(records: list[PortRecord]) -> PortSnapshot:
    return PortSnapshot(ports=tuple(records), captured_at=_TS)


def _row(**overrides: Any) -> PortRow:
    values: dict[str, Any] = {
        "protocol": "tcp",
        "address_family": "ipv4",
        "local_address": "0.0.0.0",
        "local_port": 8000,
        "pid": 100,
        "process_name": "svc",
        "status": "LISTEN",
        "endpoint": "0.0.0.0:8000",
        "identity": "tcp|ipv4|0.0.0.0|8000|100:2026-01-01T00:00:00+00:00",
    }
    values.update(overrides)
    return PortRow(**values)


def _view(
    rows: tuple[PortRow, ...] = (),
    *,
    available: bool = True,
    error: str | None = None,
    collected_at: datetime | None = _TS,
) -> PortSnapshotView:
    return PortSnapshotView(available=available, error=error, collected_at=collected_at, rows=rows)


def _display_values(page: NetworkPage) -> list[str]:
    model = page.source_model
    return [
        str(model.data(model.index(row, column), Qt.ItemDataRole.DisplayRole))
        for row in range(model.rowCount())
        for column in range(model.columnCount())
    ]


# --- Adapter ---------------------------------------------------------------


def test_adapter_converts_snapshot() -> None:
    view = collect_port_view(collector=lambda: _snapshot([_record(), _record(local_port=9000)]))

    assert view.available is True
    assert view.error is None
    assert view.count == 2
    assert view.collected_at == _TS


def test_adapter_preserves_protocol() -> None:
    view = collect_port_view(
        collector=lambda: _snapshot([_record(protocol=TransportProtocol.UDP, status=None)])
    )

    assert view.rows[0].protocol == "udp"


def test_adapter_preserves_local_address() -> None:
    view = collect_port_view(collector=lambda: _snapshot([_record(local_address="127.0.0.1")]))

    assert view.rows[0].local_address == "127.0.0.1"


def test_adapter_preserves_local_port() -> None:
    view = collect_port_view(collector=lambda: _snapshot([_record(local_port=4444)]))

    assert view.rows[0].local_port == 4444


def test_adapter_formats_ipv4_endpoint() -> None:
    view = collect_port_view(collector=lambda: _snapshot([_record()]))

    assert view.rows[0].endpoint == "0.0.0.0:8000"


def test_adapter_formats_ipv6_endpoint() -> None:
    view = collect_port_view(
        collector=lambda: _snapshot(
            [
                _record(
                    address_family=AddressFamily.IPV6,
                    local_address="::1",
                    local_port=8000,
                )
            ]
        )
    )

    assert view.rows[0].endpoint == "[::1]:8000"


def test_adapter_preserves_address_family() -> None:
    view = collect_port_view(
        collector=lambda: _snapshot(
            [_record(address_family=AddressFamily.IPV6, local_address="::")]
        )
    )

    assert view.rows[0].address_family == "ipv6"


def test_adapter_preserves_pid() -> None:
    view = collect_port_view(collector=lambda: _snapshot([_record(pid=4321)]))

    assert view.rows[0].pid == 4321


def test_adapter_preserves_process_name() -> None:
    view = collect_port_view(collector=lambda: _snapshot([_record(process_name="nginx.exe")]))

    assert view.rows[0].process_name == "nginx.exe"


def test_adapter_handles_missing_ownership() -> None:
    view = collect_port_view(
        collector=lambda: _snapshot(
            [_record(pid=None, process_name=None, process_create_time=None)]
        )
    )
    row = view.rows[0]

    assert row.pid is None
    assert row.process_name is None
    # Endpoint identity degrades to an "unowned" owner component.
    assert "unowned" in row.identity


def test_adapter_supports_empty_snapshot() -> None:
    view = collect_port_view(collector=lambda: _snapshot([]))

    assert view.available is True
    assert view.count == 0
    assert view.rows == ()


def test_adapter_collection_failure_is_safe() -> None:
    def boom() -> PortSnapshot:
        raise OSError("access denied")

    view = collect_port_view(collector=boom)

    assert view.available is False
    assert view.error == PORT_ERROR
    assert view.rows == ()


# --- Page ------------------------------------------------------------------


def test_page_constructs(app: QApplication) -> None:
    page = NetworkPage(provider=lambda: _view())

    assert isinstance(page, BasePage)
    assert page.PAGE_KEY == "network"
    assert page.TITLE == "Network"
    assert page.column_headers()[0] == "Protocol"


def test_snapshot_populates_table(app: QApplication) -> None:
    page = NetworkPage(provider=lambda: _view((_row(local_port=80), _row(local_port=443))))

    page.refresh()

    assert page.row_count() == 2
    assert page.source_model.rowCount() == 2
    assert page.source_model.columnCount() == len(page.column_headers())


def test_endpoint_count_is_correct(app: QApplication) -> None:
    page = NetworkPage(
        provider=lambda: _view((_row(local_port=1), _row(local_port=2), _row(local_port=3)))
    )

    page.refresh()

    assert page.endpoint_count_text() == "Endpoints: 3"


def test_refresh_updates_table(app: QApplication) -> None:
    queue: list[PortSnapshotView] = [
        _view((_row(local_port=80),)),
        _view((_row(local_port=80), _row(local_port=443))),
    ]
    page = NetworkPage(provider=lambda: queue.pop(0))

    assert page.row_count() == 0
    page.refresh()
    assert page.row_count() == 1
    page.refresh()
    assert page.row_count() == 2


def test_last_updated_changes_on_refresh(app: QApplication) -> None:
    queue: list[PortSnapshotView] = [
        _view((_row(),), collected_at=_TS),
        _view((_row(),), collected_at=_TS2),
    ]
    page = NetworkPage(provider=lambda: queue.pop(0))

    page.refresh()
    assert "2026-01-01" in page.last_updated_text()

    page.refresh()
    assert "2026-01-02" in page.last_updated_text()


def test_collection_failure_produces_safe_error(app: QApplication) -> None:
    page = NetworkPage(provider=lambda: _view(available=False, error=PORT_ERROR))

    page.refresh()

    assert page.has_error() is True
    assert page.error_text() == PORT_ERROR
    assert page.row_count() == 0
    assert page.endpoint_count_text() == "Endpoints: No data"


def test_provider_exception_produces_safe_error(app: QApplication) -> None:
    def boom() -> PortSnapshotView:
        raise RuntimeError("unexpected failure")

    page = NetworkPage(provider=boom)

    assert page.refresh() is None
    assert page.has_error() is True
    assert page.error_text() == PORT_ERROR


def test_sorting_is_numeric_for_port(app: QApplication) -> None:
    page = NetworkPage(
        provider=lambda: _view((_row(local_port=8080), _row(local_port=80), _row(local_port=443)))
    )
    page.refresh()

    page.proxy_model.sort(3, Qt.SortOrder.AscendingOrder)
    ports = [page.proxy_model.index(row, 3).data() for row in range(page.proxy_model.rowCount())]

    assert ports == ["80", "443", "8080"]


def test_sorting_is_numeric_for_pid(app: QApplication) -> None:
    page = NetworkPage(provider=lambda: _view((_row(pid=300), _row(pid=100), _row(pid=200))))
    page.refresh()

    page.proxy_model.sort(4, Qt.SortOrder.AscendingOrder)
    pids = [page.proxy_model.index(row, 4).data() for row in range(page.proxy_model.rowCount())]

    assert pids == ["100", "200", "300"]


def test_ipv6_endpoint_is_readable(app: QApplication) -> None:
    page = NetworkPage(
        provider=lambda: _view(
            (
                _row(
                    address_family="ipv6",
                    local_address="::1",
                    local_port=8000,
                    endpoint="[::1]:8000",
                ),
            )
        )
    )
    page.refresh()

    values = _display_values(page)
    assert "::1" in values
    assert "[::1]:8000" in values


def test_no_executable_or_user_columns_are_fabricated(app: QApplication) -> None:
    # Step 4 exposes PID + process name only; no user or executable path exists.
    headers = NetworkPage(provider=lambda: _view()).column_headers()

    assert "Executable" not in headers
    assert "User" not in headers
    assert "Process Name" in headers


def test_missing_ownership_displays_placeholder(app: QApplication) -> None:
    page = NetworkPage(provider=lambda: _view((_row(pid=None, process_name=None),)))
    page.refresh()

    values = _display_values(page)
    assert MISSING in values


def test_no_destructive_network_control_exists(app: QApplication) -> None:
    page = NetworkPage(provider=lambda: _view((_row(),)))

    labels = {button.text().lower() for button in page.findChildren(QPushButton)}

    assert labels <= {"refresh"}
    for destructive in (
        "close",
        "kill",
        "block",
        "firewall",
        "isolate",
        "terminate",
        "unblock",
    ):
        assert not any(destructive in label for label in labels)


def test_existing_navigation_still_works(app: QApplication) -> None:
    window = MainWindow()
    try:
        window.navigate_to("network")
        assert window.current_page_key == "network"
        assert window.current_page is window.page("network")

        window.navigate_to("dashboard")
        assert window.current_page_key == "dashboard"
    finally:
        window.close()


# --- Safety / import -------------------------------------------------------


def test_opening_the_page_does_not_collect_automatically(app: QApplication) -> None:
    calls: list[int] = []

    def provider() -> PortSnapshotView:
        calls.append(1)
        return _view()

    page = NetworkPage(provider=provider)

    assert calls == []
    assert page.row_count() == 0
    assert page.endpoint_count_text() == "Endpoints: No data"
    assert page.last_updated_text() == "Last updated: —"


def test_refresh_is_one_shot(app: QApplication) -> None:
    calls: list[int] = []

    def provider() -> PortSnapshotView:
        calls.append(1)
        return _view((_row(),))

    page = NetworkPage(provider=provider)

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
