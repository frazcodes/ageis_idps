"""Unit tests for Aegis IDPS License Verification and Hardware Locking."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from PySide6.QtWidgets import QApplication

from aegis_desktop.app import create_application
from aegis_desktop.services.license_client import (
    LicenseClient,
    LocalLicense,
    get_hardware_fingerprint,
)
from aegis_desktop.widgets.activation_dialog import ActivationDialog


@pytest.fixture(scope="module")
def app() -> QApplication:
    return create_application([])


def test_hardware_fingerprint_generation() -> None:
    hwid = get_hardware_fingerprint()
    assert isinstance(hwid, str)
    assert len(hwid) == 35  # 8-8-8-8 format: 32 chars + 3 dashes
    assert hwid.count("-") == 3

    # Must be deterministic on the same host
    assert get_hardware_fingerprint() == hwid


def test_local_license_expiration() -> None:
    now = datetime.now(UTC)

    # Active license (expires in future)
    future = (now + timedelta(days=30)).isoformat()
    lic_active = LocalLicense(
        key="AEGIS-1111-2222-3333",
        client_name="Test Client",
        organization="Test Org",
        expires_at=future,
        hardware_id="TEST-HWID",
        activated_at=now.isoformat(),
        token_hash="dummy_hash",
    )
    assert lic_active.is_expired is False

    # Expired license (in past)
    past = (now - timedelta(days=5)).isoformat()
    lic_expired = LocalLicense(
        key="AEGIS-1111-2222-4444",
        client_name="Old Client",
        organization="Test Org",
        expires_at=past,
        hardware_id="TEST-HWID",
        activated_at=now.isoformat(),
        token_hash="dummy_hash",
    )
    assert lic_expired.is_expired is True


def test_activation_dialog_ui_initialization(app: QApplication) -> None:
    client = LicenseClient(server_url="http://127.0.0.1:9999")
    dialog = ActivationDialog(client=client)

    assert dialog.windowTitle() == "Aegis IDPS — License Activation"
    assert dialog._hwid_lbl.text() == client.hardware_id
    assert dialog._key_input.text() == ""
    assert dialog._status_banner.isVisible() is False

    # Typing formats text to uppercase
    dialog._key_input.setText("aegis-test-key")
    assert dialog._key_input.text() == "AEGIS-TEST-KEY"

    # Short key displays validation warning
    dialog._key_input.setText("SHORT")
    dialog._do_activate()
    assert dialog._status_banner.isHidden() is False
    assert "valid license key" in dialog._status_banner.text()
