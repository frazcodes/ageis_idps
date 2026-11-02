"""USB Shield and Removable Media Security Widget for AEGIS SOC.

Displays:
1. Real-time USB hardware device inventory (VID, PID, Class, Drive letter, Storage capacity).
2. Live Removable Drive File Activity stream (Created, Modified, Deleted).
3. Active USB Threat findings (Autorun, double extensions, LNK shortcut exploits, hidden binaries).
4. Operator simulation & remediation triggers.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from aegis_desktop.services.dashboard import format_bytes, format_timestamp
from aegis_desktop.services.usb_service import (
    UsbDeviceView,
    UsbFileEventView,
    UsbSecurityService,
    UsbThreatFindingView,
)


class UsbShieldWidget(QWidget):
    """Real-time USB device inventory, file activity, and threat defense cockpit."""

    def __init__(
        self,
        service: UsbSecurityService | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._service = service or UsbSecurityService()

        self._setup_ui()
        self._connect_signals()
        self.refresh_display()

        # Auto-poll timer (every 4 seconds)
        self._poll_timer = QTimer(self)
        self._poll_timer.timeout.connect(self._on_auto_poll)
        self._poll_timer.start(4000)

    def _setup_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(12)

        # 1. Top Header Bar
        header = QFrame()
        header.setObjectName("Card")
        header.setStyleSheet("background-color: #0B1120; border: 1px solid #1E293B; border-radius: 8px;")
        h_layout = QHBoxLayout(header)
        h_layout.setContentsMargins(12, 10, 12, 10)

        title_col = QVBoxLayout()
        title = QLabel("🛡️ USB ATTACK SHIELD & REMOVABLE MEDIA DEFENSE")
        title.setObjectName("FieldKey")
        title.setStyleSheet("font-size: 14px; font-weight: 800; color: #38BDF8; letter-spacing: 0.5px;")

        self._status_badge = QLabel("STATUS: MONITORING ACTIVE")
        self._status_badge.setObjectName("FieldValue")
        self._status_badge.setStyleSheet(
            "background-color: #064E3B; color: #34D399; font-weight: 700; "
            "padding: 2px 8px; border-radius: 4px; font-size: 11px; max-width: 200px;"
        )
        title_col.addWidget(title)
        title_col.addWidget(self._status_badge)

        h_layout.addLayout(title_col)
        h_layout.addStretch(1)

        # Stats Summary
        self._dev_count_lbl = QLabel("USB Devices: 0")
        self._dev_count_lbl.setObjectName("CardHint")
        self._threat_count_lbl = QLabel("Threats: 0")
        self._threat_count_lbl.setObjectName("CardHint")
        self._events_count_lbl = QLabel("File Events: 0")
        self._events_count_lbl.setObjectName("CardHint")

        h_layout.addWidget(self._dev_count_lbl)
        h_layout.addWidget(self._threat_count_lbl)
        h_layout.addWidget(self._events_count_lbl)
        h_layout.addSpacing(16)

        # Controls
        self._scan_btn = QToolButton()
        self._scan_btn.setText("⚡ Scan USB Now")
        self._scan_btn.setObjectName("SecondaryButton")
        self._scan_btn.setStyleSheet(
            "QToolButton { background-color: #0F172A; border: 1px solid #0284C7; "
            "color: #38BDF8; font-weight: 700; padding: 4px 12px; border-radius: 4px; }"
            "QToolButton:hover { background-color: #0369A1; color: #FFFFFF; }"
        )
        self._scan_btn.clicked.connect(self._manual_scan)

        self._attack_combo = QComboBox()
        self._attack_combo.addItems([
            "Double Extension (.pdf.exe)",
            "Autorun Exploit (autorun.inf)",
            "LNK Shortcut Attack (.lnk)",
            "Hidden Staging Payload (RECYCLER)",
            "BadUSB / Rubber Ducky (Keystroke Injector)",
        ])
        self._attack_combo.setStyleSheet(
            "QComboBox { background-color: #0F172A; border: 1px solid #334155; "
            "color: #E2E8F0; padding: 3px 8px; border-radius: 4px; font-size: 12px; }"
        )

        self._sim_btn = QToolButton()
        self._sim_btn.setText("🧪 Inject Attack (Demo)")
        self._sim_btn.setObjectName("SecondaryButton")
        self._sim_btn.setStyleSheet(
            "QToolButton { background-color: #450A0A; border: 1px solid #DC2626; "
            "color: #FCA5A5; font-weight: 700; padding: 4px 12px; border-radius: 4px; }"
            "QToolButton:hover { background-color: #991B1B; color: #FFFFFF; }"
        )
        self._sim_btn.clicked.connect(self._inject_selected_attack)

        self._clear_btn = QToolButton()
        self._clear_btn.setText("🧹 Clear Alerts")
        self._clear_btn.setObjectName("SecondaryButton")
        self._clear_btn.setStyleSheet(
            "QToolButton { background-color: #0F172A; border: 1px solid #475569; "
            "color: #94A3B8; padding: 4px 8px; border-radius: 4px; }"
            "QToolButton:hover { background-color: #334155; color: #F1F5F9; }"
        )
        self._clear_btn.clicked.connect(self._clear_alerts)

        h_layout.addWidget(self._scan_btn)
        h_layout.addWidget(self._attack_combo)
        h_layout.addWidget(self._sim_btn)
        h_layout.addWidget(self._clear_btn)

        main_layout.addWidget(header)

        # 2. Threat Alert Banner (Visible only when threats exist)
        self._alert_banner = QLabel("")
        self._alert_banner.setVisible(False)
        self._alert_banner.setWordWrap(True)
        self._alert_banner.setStyleSheet(
            "background-color: #7F1D1D; color: #FECACA; border: 1px solid #EF4444; "
            "padding: 8px 12px; border-radius: 6px; font-weight: 700; font-size: 12px;"
        )
        main_layout.addWidget(self._alert_banner)

        # 3. Main Split View: Hardware Devices (Top) & Removable Activity / Threats (Bottom)
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Top Card: USB Device Inventory
        dev_card = QFrame()
        dev_card.setObjectName("Card")
        dev_card.setStyleSheet("background-color: #030712; border: 1px solid #1E293B; border-radius: 8px;")
        dev_lay = QVBoxLayout(dev_card)
        dev_lay.setContentsMargins(10, 8, 10, 8)

        dev_title = QLabel("🔌 CONNECTED USB DEVICES & REMOVABLE STORAGE INVENTORY")
        dev_title.setObjectName("FieldKey")
        dev_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #94A3B8; margin-bottom: 4px;")
        dev_lay.addWidget(dev_title)

        self._dev_table = QTableWidget(0, 7)
        self._dev_table.setHorizontalHeaderLabels([
            "State", "Device / Model", "VID:PID", "Class", "Drive", "Volume Label", "Storage Capacity"
        ])
        self._dev_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._dev_table.setStyleSheet(
            "QTableWidget { background-color: #020617; border: 1px solid #1E293B; "
            "color: #E2E8F0; gridline-color: #0F172A; selection-background-color: #1E293B; }"
            "QHeaderView::section { background-color: #0F172A; color: #94A3B8; font-weight: 700; border: none; padding: 4px; }"
        )
        dev_lay.addWidget(self._dev_table)
        splitter.addWidget(dev_card)

        # Bottom Card: Live Removable File Activity & Threat Stream
        act_card = QFrame()
        act_card.setObjectName("Card")
        act_card.setStyleSheet("background-color: #030712; border: 1px solid #1E293B; border-radius: 8px;")
        act_lay = QVBoxLayout(act_card)
        act_lay.setContentsMargins(10, 8, 10, 8)

        act_title = QLabel("📁 REMOVABLE DRIVE FILE ACTIVITY & THREAT OBSERVATIONS")
        act_title.setObjectName("FieldKey")
        act_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #94A3B8; margin-bottom: 4px;")
        act_lay.addWidget(act_title)

        self._act_table = QTableWidget(0, 6)
        self._act_table.setHorizontalHeaderLabels([
            "Time", "Action", "Threat Level", "File Path", "Size", "Detection Signature / Notes"
        ])
        self._act_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._act_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self._act_table.setStyleSheet(
            "QTableWidget { background-color: #020617; border: 1px solid #1E293B; "
            "color: #E2E8F0; gridline-color: #0F172A; selection-background-color: #1E293B; }"
            "QHeaderView::section { background-color: #0F172A; color: #94A3B8; font-weight: 700; border: none; padding: 4px; }"
        )
        act_lay.addWidget(self._act_table)
        splitter.addWidget(act_card)

        splitter.setSizes([220, 320])
        main_layout.addWidget(splitter, 1)

    def _connect_signals(self) -> None:
        self._service.devices_changed.connect(self._on_devices_changed)
        self._service.threat_detected.connect(self._on_threat_detected)
        self._service.file_activity.connect(self._on_file_activity)

    def refresh_display(self) -> None:
        devices = self._service.active_devices
        threats = self._service.active_threats
        events = self._service.recent_events

        self._dev_count_lbl.setText(f"USB Devices: {len(devices)}")
        self._threat_count_lbl.setText(f"Threats: {len(threats)}")
        self._events_count_lbl.setText(f"File Events: {len(events)}")

        # Status badge update
        if threats:
            self._status_badge.setText(f"🚨 {len(threats)} THREAT(S) DETECTED")
            self._status_badge.setStyleSheet(
                "background-color: #7F1D1D; color: #FECACA; font-weight: 800; "
                "padding: 2px 8px; border-radius: 4px; font-size: 11px; max-width: 200px;"
            )
            latest = threats[0]
            self._alert_banner.setText(
                f"🚨 CRITICAL ALERT on {latest.drive_letter or 'USB'}: {latest.description} — "
                f"Action Required: {latest.remediation_advice}"
            )
            self._alert_banner.setVisible(True)
        else:
            self._status_badge.setText("STATUS: MONITORING ACTIVE")
            self._status_badge.setStyleSheet(
                "background-color: #064E3B; color: #34D399; font-weight: 700; "
                "padding: 2px 8px; border-radius: 4px; font-size: 11px; max-width: 200px;"
            )
            self._alert_banner.setVisible(False)

        # Populate device table
        self._dev_table.setRowCount(len(devices))
        for row, dev in enumerate(devices):
            state_item = QTableWidgetItem("🟢 Connected" if dev.is_connected else "⚪ Ejected")
            state_item.setForeground(QColor("#34D399" if dev.is_connected else "#94A3B8"))

            name_item = QTableWidgetItem(dev.name)
            vid_pid = f"{dev.vendor_id}:{dev.product_id}" if dev.vendor_id else "N/A"
            vid_item = QTableWidgetItem(vid_pid)
            class_item = QTableWidgetItem(dev.device_class.upper())
            drive_item = QTableWidgetItem(dev.drive_letter or "—")
            vol_item = QTableWidgetItem(dev.volume_label or "—")

            cap_str = "—"
            if dev.total_bytes is not None:
                cap_str = f"{format_bytes(dev.total_bytes)}"
                if dev.free_bytes is not None:
                    cap_str += f" ({format_bytes(dev.free_bytes)} free)"
            cap_item = QTableWidgetItem(cap_str)

            self._dev_table.setItem(row, 0, state_item)
            self._dev_table.setItem(row, 1, name_item)
            self._dev_table.setItem(row, 2, vid_item)
            self._dev_table.setItem(row, 3, class_item)
            self._dev_table.setItem(row, 4, drive_item)
            self._dev_table.setItem(row, 5, vol_item)
            self._dev_table.setItem(row, 6, cap_item)

        # Populate file activity & threats table
        self._act_table.setRowCount(len(events))
        for row, evt in enumerate(events):
            t_str = evt.modified_at.strftime("%H:%M:%S") if evt.modified_at else "--:--:--"
            t_item = QTableWidgetItem(t_str)

            act_str = evt.action.upper()
            act_item = QTableWidgetItem(act_str)
            if evt.action == "created":
                act_item.setForeground(QColor("#38BDF8"))
            elif evt.action == "modified":
                act_item.setForeground(QColor("#FBBF24"))
            else:
                act_item.setForeground(QColor("#94A3B8"))

            if evt.is_suspicious:
                threat_category_str = evt.threat_category.upper() if evt.threat_category else "SUSPICIOUS"
                threat_item = QTableWidgetItem(f"🚨 {threat_category_str}")
                threat_item.setForeground(QColor("#EF4444"))
                threat_item.setFont(QFont("Segoe UI", weight=QFont.Weight.Bold))
            else:
                threat_item = QTableWidgetItem("CLEAN")
                threat_item.setForeground(QColor("#10B981"))

            path_item = QTableWidgetItem(evt.path)
            size_item = QTableWidgetItem(format_bytes(evt.size_bytes))
            notes_item = QTableWidgetItem(evt.threat_description or "Benign removable drive activity")
            if evt.is_suspicious:
                notes_item.setForeground(QColor("#FCA5A5"))

            self._act_table.setItem(row, 0, t_item)
            self._act_table.setItem(row, 1, act_item)
            self._act_table.setItem(row, 2, threat_item)
            self._act_table.setItem(row, 3, path_item)
            self._act_table.setItem(row, 4, size_item)
            self._act_table.setItem(row, 5, notes_item)

    def _manual_scan(self) -> None:
        self._service.scan_now()
        self.refresh_display()

    def _on_auto_poll(self) -> None:
        try:
            self._service.scan_now()
            self.refresh_display()
        except Exception:
            pass

    def _inject_selected_attack(self) -> None:
        idx = self._attack_combo.currentIndex()
        attack_types = ["double_extension", "autorun", "lnk", "hidden", "badusb"]
        choice = attack_types[idx] if idx < len(attack_types) else "double_extension"
        self._service.simulate_attack_usb(attack_type=choice)
        self.refresh_display()

    def _clear_alerts(self) -> None:
        self._service.clear_threats()
        self._service.disconnect_simulated()
        self.refresh_display()

    def _on_devices_changed(self, devices: list[Any]) -> None:
        self.refresh_display()

    def _on_threat_detected(self, threat: Any) -> None:
        self.refresh_display()

    def _on_file_activity(self, event: Any) -> None:
        self.refresh_display()
