"""Activation and License Validation Dialog for Aegis IDPS Desktop.

Displayed when Aegis starts up on a machine without a valid local license or when
the existing license has expired or been revoked.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from aegis_desktop.services.license_client import LicenseClient, LocalLicense


class ActivationDialog(QDialog):
    """Sleek obsidian dialog prompting for online license activation."""

    license_activated = Signal(object)  # LocalLicense

    def __init__(
        self,
        client: LicenseClient | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._client = client or LicenseClient()

        self.setWindowTitle("Aegis IDPS — License Activation")
        self.setFixedSize(540, 480)
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.CustomizeWindowHint | Qt.WindowType.WindowTitleHint)
        self.setStyleSheet("background-color: #030712; color: #F1F5F9;")

        self._setup_ui()

    def _setup_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(28, 28, 28, 28)
        main_layout.setSpacing(16)

        # 1. Header with Icon
        hdr_layout = QVBoxLayout()
        hdr_layout.setSpacing(6)

        title = QLabel("🛡️ AEGIS IDPS LICENSE ACTIVATION")
        title.setStyleSheet("font-size: 16px; font-weight: 900; color: #38BDF8; letter-spacing: 0.5px;")

        subtitle = QLabel("This installation is locked. Please enter your 16-character license key to activate this SOC node.")
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("font-size: 12px; color: #94A3B8; line-height: 1.4;")

        hdr_layout.addWidget(title)
        hdr_layout.addWidget(subtitle)
        main_layout.addLayout(hdr_layout)

        # 2. Hardware ID Box
        hwid_card = QFrame()
        hwid_card.setStyleSheet("background-color: #0A0F1D; border: 1px solid #1E293B; border-radius: 8px; padding: 6px;")
        hwid_lay = QVBoxLayout(hwid_card)
        hwid_lay.setContentsMargins(10, 8, 10, 8)
        hwid_lay.setSpacing(4)

        hwid_title = QLabel("THIS MACHINE'S HARDWARE ID (HWID):")
        hwid_title.setStyleSheet("font-size: 10px; font-weight: 700; color: #64748B; letter-spacing: 0.5px;")

        hwid_row = QHBoxLayout()
        self._hwid_lbl = QLabel(self._client.hardware_id)
        self._hwid_lbl.setStyleSheet("font-family: Consolas, monospace; font-size: 11px; font-weight: 700; color: #CBD5E1;")

        copy_hwid_btn = QToolButton()
        copy_hwid_btn.setText("📋 Copy")
        copy_hwid_btn.setStyleSheet(
            "QToolButton { background-color: #1E293B; color: #94A3B8; border-radius: 4px; padding: 2px 8px; font-size: 10px; }"
            "QToolButton:hover { background-color: #334155; color: #F1F5F9; }"
        )
        copy_hwid_btn.clicked.connect(self._copy_hwid)

        hwid_row.addWidget(self._hwid_lbl)
        hwid_row.addStretch(1)
        hwid_row.addWidget(copy_hwid_btn)

        hwid_lay.addWidget(hwid_title)
        hwid_lay.addLayout(hwid_row)
        main_layout.addWidget(hwid_card)

        # 3. Key Input Section
        input_lay = QVBoxLayout()
        input_lay.setSpacing(6)

        key_lbl = QLabel("ENTER LICENSE KEY:")
        key_lbl.setStyleSheet("font-size: 11px; font-weight: 700; color: #E2E8F0;")

        self._key_input = QLineEdit()
        self._key_input.setPlaceholderText("AEGIS-XXXX-XXXX-XXXX")
        self._key_input.setMaxLength(23)
        self._key_input.setStyleSheet(
            "QLineEdit { background-color: #020617; border: 1px solid #334155; border-radius: 6px; "
            "color: #38BDF8; font-family: Consolas, monospace; font-size: 14px; font-weight: 700; "
            "padding: 8px 12px; letter-spacing: 1px; }"
            "QLineEdit:focus { border: 1px solid #0284C7; }"
        )
        self._key_input.textChanged.connect(self._on_key_typed)

        input_lay.addWidget(key_lbl)
        input_lay.addWidget(self._key_input)
        main_layout.addLayout(input_lay)

        # 4. Status / Error Message Banner
        self._status_banner = QLabel("")
        self._status_banner.setWordWrap(True)
        self._status_banner.setVisible(False)
        self._status_banner.setStyleSheet("padding: 8px; border-radius: 6px; font-size: 11px; font-weight: 600;")
        main_layout.addWidget(self._status_banner)

        main_layout.addStretch(1)

        # 5. Buttons Row
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)

        self._exit_btn = QPushButton("Exit")
        self._exit_btn.setStyleSheet(
            "QPushButton { background-color: #0F172A; border: 1px solid #334155; color: #94A3B8; "
            "padding: 8px 18px; border-radius: 6px; font-weight: 600; font-size: 12px; }"
            "QPushButton:hover { background-color: #1E293B; color: #F1F5F9; }"
        )
        self._exit_btn.clicked.connect(self.reject)

        self._activate_btn = QPushButton("⚡ Activate Online")
        self._activate_btn.setStyleSheet(
            "QPushButton { background-color: #0284C7; border: 1px solid #0369A1; color: #FFFFFF; "
            "padding: 8px 24px; border-radius: 6px; font-weight: 700; font-size: 12px; }"
            "QPushButton:hover { background-color: #0369A1; }"
            "QPushButton:disabled { background-color: #1E293B; color: #64748B; border-color: #334155; }"
        )
        self._activate_btn.clicked.connect(self._do_activate)

        btn_row.addStretch(1)
        btn_row.addWidget(self._exit_btn)
        btn_row.addWidget(self._activate_btn)
        main_layout.addLayout(btn_row)

    def _on_key_typed(self, text: str) -> None:
        clean = text.upper().strip()
        if clean != text:
            self._key_input.setText(clean)
        self._status_banner.setVisible(False)

    def _copy_hwid(self) -> None:
        from PySide6.QtWidgets import QApplication
        QApplication.clipboard().setText(self._client.hardware_id)
        self._show_info("Hardware ID copied to clipboard!")

    def _do_activate(self) -> None:
        key = self._key_input.text().strip().upper()
        if len(key) < 10:
            self._show_error("Please enter a valid license key (format: AEGIS-XXXX-XXXX-XXXX).")
            return

        self._activate_btn.setEnabled(False)
        self._activate_btn.setText("Verifying with Cloud...")
        self._show_info("Connecting to Aegis Cloud License Server...")

        # Process activation in background or immediate single shot
        QTimer.singleShot(400, lambda: self._process_activation(key))

    def _process_activation(self, key: str) -> None:
        result = self._client.activate_online(key)

        self._activate_btn.setEnabled(True)
        self._activate_btn.setText("⚡ Activate Online")

        if result.get("success"):
            client_name = result.get("data", {}).get("clientName", "Subscriber")
            days = result.get("data", {}).get("daysRemaining", "Active")
            self._show_success(f"✅ Activation Successful! Welcome, {client_name} ({days} days validity).")

            # Load the newly created local license
            local_lic = self._client.load_local_license()
            QTimer.singleShot(900, lambda: self._finish_success(local_lic))
        else:
            msg = result.get("message", "License activation failed.")
            self._show_error(f"❌ {msg}")

    def _finish_success(self, license_obj: LocalLicense | None) -> None:
        self.license_activated.emit(license_obj)
        self.accept()

    def _show_error(self, msg: str) -> None:
        self._status_banner.setText(msg)
        self._status_banner.setStyleSheet(
            "background-color: #450A0A; border: 1px solid #DC2626; color: #FECACA; "
            "padding: 8px 12px; border-radius: 6px; font-size: 11px; font-weight: 600;"
        )
        self._status_banner.setVisible(True)

    def _show_info(self, msg: str) -> None:
        self._status_banner.setText(msg)
        self._status_banner.setStyleSheet(
            "background-color: #082F49; border: 1px solid #0284C7; color: #BAE6FD; "
            "padding: 8px 12px; border-radius: 6px; font-size: 11px; font-weight: 600;"
        )
        self._status_banner.setVisible(True)

    def _show_success(self, msg: str) -> None:
        self._status_banner.setText(msg)
        self._status_banner.setStyleSheet(
            "background-color: #064E3B; border: 1px solid #059669; color: #D1FAE5; "
            "padding: 8px 12px; border-radius: 6px; font-size: 11px; font-weight: 600;"
        )
        self._status_banner.setVisible(True)

