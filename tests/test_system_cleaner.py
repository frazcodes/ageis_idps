"""Tests for System Hygiene & Storage Optimization cleaner service and dialog."""

from __future__ import annotations

import os
import tempfile
from unittest.mock import patch

import pytest
from PySide6.QtWidgets import QApplication

from aegis_desktop.app import create_application
from aegis_desktop.hygiene_dialog import SystemHygieneDialog
from aegis_desktop.services.system_cleaner import (
    HygieneCleanResult,
    HygieneScanResult,
    clean_category_path,
    clean_system_hygiene,
    scan_category,
    scan_system_hygiene,
)
from aegis_desktop.window import MainWindow


@pytest.fixture(scope="module")
def app() -> QApplication:
    return create_application([])


def test_scan_and_clean_temporary_folder() -> None:
    """Verify scanning and cleaning an isolated temporary folder structure."""
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create test files
        file1 = os.path.join(temp_dir, "test1.tmp")
        with open(file1, "wb") as f:
            f.write(b"A" * 1024)

        sub_dir = os.path.join(temp_dir, "staging_cache")
        os.makedirs(sub_dir)
        file2 = os.path.join(sub_dir, "payload.dat")
        with open(file2, "wb") as f:
            f.write(b"B" * 2048)

        # 1. Scan
        cat = scan_category("test_cat", "Test Category", "Test Description", temp_dir)
        assert cat.id == "test_cat"
        assert cat.file_count == 2
        assert cat.size_bytes == 3072
        assert cat.accessible is True
        assert "3.0 KiB" in cat.size_formatted

        # 2. Clean
        cleaned, reclaimed, skipped = clean_category_path(temp_dir)
        assert cleaned == 2
        assert reclaimed == 3072
        assert skipped == 0

        # Files should be removed, but parent temp_dir remains
        assert os.path.exists(temp_dir)
        assert not os.path.exists(file1)
        assert not os.path.exists(file2)


def test_clean_skips_locked_files_gracefully() -> None:
    """Verify that permission errors or locked files increment skipped_files without raising."""
    with tempfile.TemporaryDirectory() as temp_dir:
        file1 = os.path.join(temp_dir, "locked.tmp")
        with open(file1, "wb") as f:
            f.write(b"LOCKED DATA")

        # Mock os.unlink to simulate a locked file raising PermissionError
        with patch("os.unlink", side_effect=PermissionError("File locked by process")):
            cleaned, _reclaimed, skipped = clean_category_path(temp_dir)
            assert cleaned == 0
            assert skipped == 1


def test_system_hygiene_scan_and_clean_results() -> None:
    """Verify system-wide scan and clean results return well-formed dataclasses."""
    scan_res = scan_system_hygiene()
    assert isinstance(scan_res, HygieneScanResult)
    assert scan_res.total_files >= 0
    assert scan_res.total_bytes >= 0
    assert len(scan_res.categories) > 0
    assert isinstance(scan_res.total_bytes_formatted, str)

    # Test clean with empty category_ids (safe no-op)
    clean_res = clean_system_hygiene(category_ids=[])
    assert isinstance(clean_res, HygieneCleanResult)
    assert clean_res.cleaned_files == 0
    assert clean_res.reclaimed_bytes == 0
    assert clean_res.skipped_files == 0


def test_hygiene_dialog_ui(app: QApplication) -> None:
    """Verify SystemHygieneDialog constructs and populates stat cards and categories."""
    dialog = SystemHygieneDialog()
    assert "System Hygiene" in dialog.windowTitle()
    assert dialog._scan_result is not None
    assert dialog._card_junk_val.text() != ""
    assert dialog._card_files_val.text() != ""
    assert len(dialog._category_checkboxes) > 0

    # Trigger a refresh
    dialog.refresh_scan()
    assert dialog._status_banner.text().startswith("✓ Scan complete")
    dialog.close()


def test_main_window_has_hygiene_button(app: QApplication) -> None:
    """Verify MainWindow integrates the System Hygiene button in the sidebar."""
    window = MainWindow()
    assert hasattr(window, "_hygiene_btn")
    assert window._hygiene_btn.text() == "🧹  System Hygiene"
    assert hasattr(window, "open_system_hygiene")
    window.close()


def test_hygiene_dialog_purge_with_window(app: QApplication) -> None:
    """Verify purge execution with parent MainWindow triggers show_toast without error."""
    from datetime import UTC, datetime

    from PySide6.QtWidgets import QMessageBox

    window = MainWindow()
    dialog = SystemHygieneDialog(window)

    with (
        patch(
            "PySide6.QtWidgets.QMessageBox.question",
            return_value=QMessageBox.StandardButton.Yes,
        ),
        patch("aegis_desktop.hygiene_dialog.clean_system_hygiene") as mock_clean,
    ):
        mock_clean.return_value = HygieneCleanResult(
            cleaned_files=10,
            reclaimed_bytes=1024,
            skipped_files=1,
            cleaned_categories=("user_temp",),
            cleaned_at=datetime.now(UTC),
        )
        dialog._on_purge_clicked()

    assert "Purge Complete: 10 files deleted" in dialog._status_banner.text()
    dialog.close()
    window.close()

