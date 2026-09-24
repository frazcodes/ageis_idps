"""Deterministic tests for the Aegis desktop console (GUI-1).

Qt runs with the offscreen platform so no display is required and no privileged
access is used. The tests assert that the console is UI infrastructure only: it
loads no security engine, starts no capture and triggers no response.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Iterator

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason="desktop extra not installed")

from PySide6.QtWidgets import QApplication

from aegis_desktop.app import create_application
from aegis_desktop.navigation import NAV_ITEMS
from aegis_desktop.pages import PAGE_FACTORIES, BasePage, create_page
from aegis_desktop.window import STATUS_MESSAGE, MainWindow

_EXPECTED_KEYS = (
    "dashboard",
    "assets",
    "processes",
    "network",
    "files",
    "events",
    "detections",
    "incidents",
    "response",
    "risk",
    "settings",
)

#: Packages the console must never import (monitoring/capture/detection logic).
#: Read-only configuration and inventory imports (e.g. ``aegis_agent.config``,
#: ``aegis_agent.inventory``, ``aegis_network_sensor.config``) are allowed.
_FORBIDDEN_IMPORT_PREFIXES = (
    "aegis_agent.monitors",
    "aegis_network_sensor.capture",
    "aegis_network_sensor.normalization",
    "aegis_network_sensor.sensor",
    "aegis_response_engine",
    "aegis_ml_engine",
    "aegis_shared.correlation",
    "aegis_shared.detection",
    "aegis_shared.risk",
    "aegis_shared.threat_intel",
    "aegis_shared.assets",
)


@pytest.fixture(scope="module")
def app() -> QApplication:
    return create_application([])


@pytest.fixture()
def window(app: QApplication) -> Iterator[MainWindow]:
    main_window = MainWindow()
    yield main_window
    main_window.close()


def test_desktop_package_imports() -> None:
    import aegis_desktop

    assert "MainWindow" in aegis_desktop.__all__


def test_main_window_can_be_constructed(window: MainWindow) -> None:
    assert window.windowTitle() == "Aegis IDPS"


def test_navigation_entries_exist() -> None:
    keys = tuple(item.key for item in NAV_ITEMS)
    titles = {item.key: item.title for item in NAV_ITEMS}

    assert keys == _EXPECTED_KEYS
    assert titles["dashboard"] == "Dashboard"
    assert titles["files"] == "File Integrity"


def test_all_expected_pages_can_be_created(window: MainWindow) -> None:
    assert tuple(PAGE_FACTORIES) == _EXPECTED_KEYS
    assert window.page_keys() == _EXPECTED_KEYS

    for key in _EXPECTED_KEYS:
        page = window.page(key)
        assert isinstance(page, BasePage)
        assert key == page.PAGE_KEY


def test_switching_between_pages_works(window: MainWindow) -> None:
    for key in _EXPECTED_KEYS:
        window.navigate_to(key)
        assert window.current_page_key == key
        assert window.current_page is window.page(key)


def test_unknown_navigation_key_is_rejected(window: MainWindow) -> None:
    with pytest.raises(KeyError):
        window.navigate_to("does-not-exist")
    with pytest.raises(KeyError):
        create_page("does-not-exist")


def test_status_bar_reports_safe_defaults(window: MainWindow) -> None:
    assert "Monitoring disabled" in STATUS_MESSAGE
    assert "no response actions" in STATUS_MESSAGE
    assert "Monitoring disabled" in window.statusBar().currentMessage()


def test_gui_does_not_require_monitors_enabled(window: MainWindow) -> None:
    from aegis_agent.config import AgentSettings

    # Safety defaults from Steps 1-9 are unchanged: nothing is enabled.
    assert AgentSettings().enabled_monitors == ()
    # The window still constructs and navigates with every monitor disabled.
    window.navigate_to("processes")
    assert window.current_page_key == "processes"


def test_create_application_is_idempotent(app: QApplication) -> None:
    assert create_application([]) is app
    assert app.applicationName() == "Aegis IDPS"


def test_module_entry_point_exists() -> None:
    from aegis_desktop.__main__ import main

    assert callable(main)


def test_desktop_does_not_load_security_engines() -> None:
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
