"""Deterministic tests for the File Integrity page integration (GUI-5).

FIM models/configuration are mocked via injected snapshots/views; no test scans
the user's filesystem or hashes real files. Qt runs with the offscreen platform
and no privileges.
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

from aegis_agent.config import AgentSettings, SymlinkPolicy
from aegis_agent.monitors.file_integrity import FileRecord, FileSnapshot
from aegis_desktop.app import create_application
from aegis_desktop.pages.base import BasePage
from aegis_desktop.pages.files import FilesPage
from aegis_desktop.services.files import (
    FILE_ERROR,
    FIM_DISABLED_NOTICE,
    MISSING,
    FileIntegrityConfig,
    FileRow,
    FileSnapshotView,
    collect_file_view,
    file_integrity_config,
)
from aegis_desktop.window import MainWindow
from aegis_shared.enums import FileType, HashStatus

_TS = datetime(2026, 1, 1, tzinfo=UTC)
_TS2 = datetime(2026, 1, 2, tzinfo=UTC)
_HASH = "a" * 64

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


def _record(**overrides: Any) -> FileRecord:
    values: dict[str, Any] = {
        "path": "C:\\demo\\a.txt",
        "file_type": FileType.REGULAR,
        "size_bytes": 12,
        "modified_at": _TS,
        "sha256": _HASH,
        "hash_status": HashStatus.HASHED,
    }
    values.update(overrides)
    return FileRecord(**values)


def _snapshot(files: list[FileRecord]) -> FileSnapshot:
    return FileSnapshot(files=tuple(files), captured_at=_TS)


def _settings(**overrides: Any) -> AgentSettings:
    values: dict[str, Any] = {
        "enable_file_integrity": True,
        "file_integrity_paths": ["C:\\demo"],
        "file_integrity_max_hash_bytes": 10 * 1024 * 1024,
        "file_integrity_symlink_policy": SymlinkPolicy.SKIP,
    }
    values.update(overrides)
    return AgentSettings(**values)


def _config(**overrides: Any) -> FileIntegrityConfig:
    values: dict[str, Any] = {
        "enabled": True,
        "configured_paths": 1,
        "symlink_policy": "skip",
        "max_hash_bytes": 10 * 1024 * 1024,
    }
    values.update(overrides)
    return FileIntegrityConfig(**values)


def _row(**overrides: Any) -> FileRow:
    values: dict[str, Any] = {
        "path": "C:\\demo\\a.txt",
        "file_type": "regular",
        "size_bytes": 12,
        "modified_at": _TS,
        "sha256": _HASH,
        "hash_status": "hashed",
        "identity": "c:\\demo\\a.txt",
    }
    values.update(overrides)
    return FileRow(**values)


def _view(
    rows: tuple[FileRow, ...] = (),
    *,
    available: bool = True,
    error: str | None = None,
    notice: str | None = None,
    collected_at: datetime | None = _TS,
    config: FileIntegrityConfig | None = None,
) -> FileSnapshotView:
    return FileSnapshotView(
        available=available,
        error=error,
        notice=notice,
        collected_at=collected_at,
        config=config or _config(),
        rows=rows,
    )


def _display_values(page: FilesPage) -> list[str]:
    model = page.source_model
    return [
        str(model.data(model.index(row, column), Qt.ItemDataRole.DisplayRole))
        for row in range(model.rowCount())
        for column in range(model.columnCount())
    ]


# --- Adapter ---------------------------------------------------------------


def test_adapter_converts_snapshot() -> None:
    view = collect_file_view(settings=_settings(), collector=lambda: _snapshot([_record()]))

    assert view.available is True
    assert view.error is None
    assert view.count == 1
    assert view.collected_at == _TS


def test_adapter_preserves_path() -> None:
    view = collect_file_view(
        settings=_settings(), collector=lambda: _snapshot([_record(path="C:\\demo\\sub\\b.bin")])
    )

    assert view.rows[0].path == "C:\\demo\\sub\\b.bin"


def test_adapter_preserves_file_type() -> None:
    view = collect_file_view(
        settings=_settings(),
        collector=lambda: _snapshot([_record(file_type=FileType.DIRECTORY, sha256=None)]),
    )

    assert view.rows[0].file_type == "directory"


def test_adapter_preserves_size() -> None:
    view = collect_file_view(
        settings=_settings(), collector=lambda: _snapshot([_record(size_bytes=4096)])
    )

    assert view.rows[0].size_bytes == 4096


def test_adapter_preserves_modified_time() -> None:
    view = collect_file_view(settings=_settings(), collector=lambda: _snapshot([_record()]))

    assert view.rows[0].modified_at == _TS


def test_adapter_preserves_hash() -> None:
    view = collect_file_view(settings=_settings(), collector=lambda: _snapshot([_record()]))

    assert view.rows[0].sha256 == _HASH
    assert len(view.rows[0].sha256 or "") == 64


def test_adapter_preserves_hash_status() -> None:
    view = collect_file_view(
        settings=_settings(),
        collector=lambda: _snapshot([_record(sha256=None, hash_status=HashStatus.SKIPPED_SIZE)]),
    )

    assert view.rows[0].hash_status == "skipped_size"


def test_adapter_preserves_identity() -> None:
    record = _record()
    view = collect_file_view(settings=_settings(), collector=lambda: _snapshot([record]))

    assert view.rows[0].identity == record.identity.key


def test_adapter_handles_missing_optional_fields() -> None:
    view = collect_file_view(
        settings=_settings(),
        collector=lambda: _snapshot(
            [_record(size_bytes=None, modified_at=None, sha256=None, hash_status=HashStatus.ERROR)]
        ),
    )
    row = view.rows[0]

    assert row.size_bytes is None
    assert row.modified_at is None
    assert row.sha256 is None
    assert row.hash_status == "error"


def test_adapter_supports_empty_snapshot() -> None:
    view = collect_file_view(settings=_settings(), collector=lambda: _snapshot([]))

    assert view.available is True
    assert view.count == 0
    assert view.rows == ()


def test_adapter_collection_failure_is_safe() -> None:
    def boom() -> FileSnapshot:
        raise OSError("permission denied")

    view = collect_file_view(settings=_settings(), collector=boom)

    assert view.available is False
    assert view.error == FILE_ERROR
    assert view.rows == ()


def test_adapter_extracts_configuration() -> None:
    config = file_integrity_config(settings=_settings(file_integrity_paths=["C:\\a", "C:\\b"]))

    assert config.enabled is True
    assert config.configured_paths == 2
    assert config.symlink_policy == "skip"
    assert config.max_hash_bytes == 10 * 1024 * 1024

    disabled = file_integrity_config(settings=AgentSettings(enable_file_integrity=False))
    assert disabled.enabled is False
    assert disabled.configured_paths == 0


def test_adapter_disabled_does_not_collect() -> None:
    calls: list[int] = []

    def boom() -> FileSnapshot:
        calls.append(1)
        raise AssertionError("collector must not run when FIM is disabled")

    disabled = collect_file_view(
        settings=AgentSettings(enable_file_integrity=False), collector=boom
    )
    unconfigured = collect_file_view(
        settings=AgentSettings(enable_file_integrity=True, file_integrity_paths=[]),
        collector=boom,
    )

    assert calls == []
    assert disabled.notice == FIM_DISABLED_NOTICE
    assert unconfigured.notice == FIM_DISABLED_NOTICE


# --- Page ------------------------------------------------------------------


def test_page_constructs(app: QApplication) -> None:
    page = FilesPage(provider=lambda: _view(), config_provider=lambda: _config())

    assert isinstance(page, BasePage)
    assert page.PAGE_KEY == "files"
    assert page.TITLE == "File Integrity"
    assert page.column_headers()[0] == "Path"


def test_initial_page_performs_no_collection(app: QApplication) -> None:
    calls: list[int] = []

    def provider() -> FileSnapshotView:
        calls.append(1)
        return _view()

    page = FilesPage(provider=provider, config_provider=lambda: _config())

    assert calls == []
    assert page.row_count() == 0
    assert page.file_count_text() == "Files: No data"
    assert page.last_updated_text() == "Last updated: —"


def test_disabled_fim_state_is_displayed(app: QApplication) -> None:
    page = FilesPage(
        provider=lambda: _view(),
        config_provider=lambda: _config(enabled=False, configured_paths=0),
    )

    assert page.fim_status_text() == "FIM: Disabled"
    assert page.configured_paths_text() == "Configured paths: 0"


def test_configured_path_count_is_displayed(app: QApplication) -> None:
    page = FilesPage(
        provider=lambda: _view(),
        config_provider=lambda: _config(configured_paths=3),
    )

    assert page.fim_status_text() == "FIM: Enabled"
    assert page.configured_paths_text() == "Configured paths: 3"
    assert page.symlink_policy_text() == "Symlink policy: skip"
    assert page.hash_limit_text() == "Hash limit: 10.0 MiB"


def test_snapshot_populates_table(app: QApplication) -> None:
    page = FilesPage(
        provider=lambda: _view((_row(path="C:\\a"), _row(path="C:\\b"))),
        config_provider=lambda: _config(),
    )

    page.refresh()

    assert page.row_count() == 2
    assert page.source_model.rowCount() == 2
    assert page.source_model.columnCount() == len(page.column_headers())


def test_file_count_is_correct(app: QApplication) -> None:
    page = FilesPage(
        provider=lambda: _view((_row(), _row(path="C:\\b"), _row(path="C:\\c"))),
        config_provider=lambda: _config(),
    )

    page.refresh()

    assert page.file_count_text() == "Files: 3"


def test_refresh_is_exactly_one_collection(app: QApplication) -> None:
    calls: list[int] = []

    def provider() -> FileSnapshotView:
        calls.append(1)
        return _view((_row(),))

    page = FilesPage(provider=provider, config_provider=lambda: _config())

    page.refresh()
    assert len(calls) == 1
    page.refresh()
    assert len(calls) == 2


def test_refresh_updates_table(app: QApplication) -> None:
    queue: list[FileSnapshotView] = [
        _view((_row(),)),
        _view((_row(), _row(path="C:\\b"))),
    ]
    page = FilesPage(provider=lambda: queue.pop(0), config_provider=lambda: _config())

    assert page.row_count() == 0
    page.refresh()
    assert page.row_count() == 1
    page.refresh()
    assert page.row_count() == 2


def test_last_updated_changes_on_refresh(app: QApplication) -> None:
    queue: list[FileSnapshotView] = [
        _view((_row(),), collected_at=_TS),
        _view((_row(),), collected_at=_TS2),
    ]
    page = FilesPage(provider=lambda: queue.pop(0), config_provider=lambda: _config())

    page.refresh()
    assert "2026-01-01" in page.last_updated_text()

    page.refresh()
    assert "2026-01-02" in page.last_updated_text()


def test_hash_value_is_not_corrupted(app: QApplication) -> None:
    page = FilesPage(provider=lambda: _view((_row(),)), config_provider=lambda: _config())
    page.refresh()

    # Underlying value is the full hash.
    assert page.row_at(0).sha256 == _HASH
    # Cell shows a preview; the full hash is available via tooltip.
    assert page.source_model.data(page.source_model.index(0, 4)) == f"{_HASH[:16]}…"
    assert (
        page.source_model.data(page.source_model.index(0, 4), Qt.ItemDataRole.ToolTipRole) == _HASH
    )


def test_hash_status_is_displayed(app: QApplication) -> None:
    page = FilesPage(
        provider=lambda: _view(
            (
                _row(sha256=None, hash_status="skipped_size"),
                _row(path="C:\\b", sha256=None, hash_status="not_applicable"),
            )
        ),
        config_provider=lambda: _config(),
    )
    page.refresh()

    statuses = [
        page.source_model.data(page.source_model.index(row, 5)) for row in range(page.row_count())
    ]
    assert statuses == ["skipped_size", "not_applicable"]


def test_long_paths_remain_usable(app: QApplication) -> None:
    long_path = "C:\\" + "nested\\" * 40 + "file.txt"
    page = FilesPage(
        provider=lambda: _view((_row(path=long_path),)),
        config_provider=lambda: _config(),
    )
    page.refresh()

    assert page.table_view.textElideMode() == Qt.TextElideMode.ElideMiddle
    assert page.source_model.data(page.source_model.index(0, 0)) == long_path
    assert (
        page.source_model.data(page.source_model.index(0, 0), Qt.ItemDataRole.ToolTipRole)
        == long_path
    )


def test_collection_failure_produces_safe_error(app: QApplication) -> None:
    page = FilesPage(
        provider=lambda: _view(available=False, error=FILE_ERROR),
        config_provider=lambda: _config(),
    )

    page.refresh()

    assert page.has_error() is True
    assert page.error_text() == FILE_ERROR
    assert page.row_count() == 0
    assert page.file_count_text() == "Files: No data"


def test_provider_exception_produces_safe_error(app: QApplication) -> None:
    def boom() -> FileSnapshotView:
        raise RuntimeError("unexpected failure")

    page = FilesPage(provider=boom, config_provider=lambda: _config())

    assert page.refresh() is None
    assert page.has_error() is True
    assert page.error_text() == FILE_ERROR


def test_disabled_refresh_shows_notice_without_scan(app: QApplication) -> None:
    page = FilesPage(
        provider=lambda: _view(available=False, notice=FIM_DISABLED_NOTICE),
        config_provider=lambda: _config(enabled=False, configured_paths=0),
    )

    page.refresh()

    assert page.has_error() is False
    assert page.notice_text() == FIM_DISABLED_NOTICE
    assert page.file_count_text() == "Files: No data"


def test_no_destructive_control_exists(app: QApplication) -> None:
    page = FilesPage(provider=lambda: _view((_row(),)), config_provider=lambda: _config())

    labels = {button.text().lower() for button in page.findChildren(QPushButton)}

    assert labels <= {"refresh"}
    for destructive in (
        "delete",
        "restore",
        "quarantine",
        "modify",
        "rename",
        "kill",
        "yara",
        "execute",
        "scan",
        "open",
    ):
        assert not any(destructive in label for label in labels)


def test_existing_navigation_still_works(app: QApplication) -> None:
    window = MainWindow()
    try:
        window.navigate_to("files")
        assert window.current_page_key == "files"
        assert window.current_page is window.page("files")

        window.navigate_to("dashboard")
        assert window.current_page_key == "dashboard"
    finally:
        window.close()


# --- Safety / import -------------------------------------------------------


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


def test_missing_values_display_placeholder(app: QApplication) -> None:
    page = FilesPage(
        provider=lambda: _view((_row(size_bytes=None, modified_at=None, sha256=None),)),
        config_provider=lambda: _config(),
    )
    page.refresh()

    assert MISSING in _display_values(page)
