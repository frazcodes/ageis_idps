"""Desktop presentation and telemetry service for USB Attack Detection.

Provides non-blocking access to connected USB hardware inventory, removable media
file activity stream, and weaponised USB attack detection. Includes simulation
capabilities for SOC operator training and live demos.

Imports of the agent monitor layer are lazy to preserve GUI startup boundaries.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Callable, Sequence

from PySide6.QtCore import QObject, Signal

from aegis_shared.enums import Severity
from aegis_shared.logging import get_logger

if TYPE_CHECKING:
    from aegis_agent.monitors.usb import UsbChanges, UsbMonitor

logger = get_logger(__name__)


@dataclass(frozen=True)
class UsbDeviceView:
    """Safe UI representation of a connected USB device."""

    device_id: str
    name: str = "Unknown USB Device"
    vendor_id: str = ""
    product_id: str = ""
    manufacturer: str = ""
    serial_number: str = ""
    device_class: str = "unknown"
    drive_letter: str | None = None
    volume_label: str | None = None
    file_system: str | None = None
    total_bytes: int | None = None
    free_bytes: int | None = None
    is_connected: bool = True
    connected_at: datetime | None = None


@dataclass(frozen=True)
class UsbFileEventView:
    """Safe UI representation of a file activity event on removable media."""

    path: str
    drive_letter: str
    action: str  # "created", "modified", "deleted"
    size_bytes: int = 0
    modified_at: datetime | None = None
    sha256: str | None = None
    is_suspicious: bool = False
    threat_category: str | None = None
    threat_description: str | None = None


@dataclass(frozen=True)
class UsbThreatFindingView:
    """Safe UI representation of a detected threat on removable media."""

    finding_id: str
    device_id: str | None
    drive_letter: str | None
    file_path: str
    category: str
    severity: str
    description: str
    remediation_advice: str
    detected_at: datetime


class UsbSecurityService(QObject):
    """Coordinates USB hardware monitoring, removable storage audits, and threat alerts."""

    devices_changed = Signal(list)  # list[UsbDeviceView]
    threat_detected = Signal(object)  # UsbThreatFindingView
    file_activity = Signal(object)  # UsbFileEventView

    def __init__(self, *, monitor: UsbMonitor | None = None) -> None:
        super().__init__()
        self._monitor: UsbMonitor | None = monitor
        self._active_devices: list[UsbDeviceView] = []
        self._recent_events: list[UsbFileEventView] = []
        self._active_threats: list[UsbThreatFindingView] = []
        self._simulated_devices: list[UsbDeviceView] = []
        self._initialized = False

    def _ensure_monitor(self) -> UsbMonitor:
        if self._monitor is None:
            from aegis_agent.monitors.usb import UsbCollector, UsbMonitor, UsbThreatDetector

            self._monitor = UsbMonitor(
                collector=UsbCollector(),
                detector=UsbThreatDetector(),
            )
        return self._monitor

    def _init_baseline_if_needed(self) -> None:
        if not self._initialized:
            self._initialized = True
            try:
                mon = self._ensure_monitor()
                snapshot = mon.start()
                self._active_devices = [
                    UsbDeviceView(
                        device_id=d.device_id,
                        name=d.name,
                        vendor_id=d.vendor_id,
                        product_id=d.product_id,
                        manufacturer=d.manufacturer,
                        serial_number=d.serial_number,
                        device_class=d.device_class.value,
                        drive_letter=d.drive_letter,
                        volume_label=d.volume_label,
                        file_system=d.file_system,
                        total_bytes=d.total_bytes,
                        free_bytes=d.free_bytes,
                        is_connected=d.is_connected,
                        connected_at=d.connected_at,
                    )
                    for d in snapshot.devices
                ]
            except Exception as exc:
                logger.warning("Failed establishing initial USB baseline: %s", exc)

    @property
    def active_devices(self) -> list[UsbDeviceView]:
        """Currently active USB devices."""
        self._init_baseline_if_needed()
        return list(self._active_devices) + list(self._simulated_devices)

    @property
    def recent_events(self) -> list[UsbFileEventView]:
        """Recent file events observed on removable drives."""
        return list(self._recent_events)

    @property
    def active_threats(self) -> list[UsbThreatFindingView]:
        """Detected USB attack threats."""
        return list(self._active_threats)

    def scan_now(self) -> None:
        """Poll the monitor for new USB hardware connections and file activity."""
        self._init_baseline_if_needed()
        mon = self._ensure_monitor()
        changes = mon.poll()

        # Update connected devices
        current_map = {d.device_id.upper(): d for d in self._active_devices}
        for d in changes.connected_devices:
            view = UsbDeviceView(
                device_id=d.device_id,
                name=d.name,
                vendor_id=d.vendor_id,
                product_id=d.product_id,
                manufacturer=d.manufacturer,
                serial_number=d.serial_number,
                device_class=d.device_class.value,
                drive_letter=d.drive_letter,
                volume_label=d.volume_label,
                file_system=d.file_system,
                total_bytes=d.total_bytes,
                free_bytes=d.free_bytes,
                is_connected=d.is_connected,
                connected_at=d.connected_at,
            )
            current_map[d.device_id.upper()] = view

        for d in changes.disconnected_devices:
            current_map.pop(d.device_id.upper(), None)

        self._active_devices = list(current_map.values())

        # Collect file events
        for fe in changes.file_events:
            fe_view = UsbFileEventView(
                path=fe.path,
                drive_letter=fe.drive_letter,
                action=fe.action.value,
                size_bytes=fe.size_bytes,
                modified_at=fe.modified_at,
                sha256=fe.sha256,
                is_suspicious=fe.is_suspicious,
                threat_category=fe.threat_category.value if fe.threat_category else None,
                threat_description=fe.threat_description,
            )
            self._recent_events.insert(0, fe_view)
            self.file_activity.emit(fe_view)
        self._recent_events = self._recent_events[:100]

        # Collect threats
        for t in changes.threat_findings:
            t_view = UsbThreatFindingView(
                finding_id=t.finding_id,
                device_id=t.device_id,
                drive_letter=t.drive_letter,
                file_path=t.file_path,
                category=t.category.value,
                severity=t.severity.value,
                description=t.description,
                remediation_advice=t.remediation_advice,
                detected_at=t.detected_at,
            )
            self._active_threats.insert(0, t_view)
            self.threat_detected.emit(t_view)
        self._active_threats = self._active_threats[:50]

        self.devices_changed.emit(self.active_devices)

    def clear_threats(self) -> None:
        """Clear detected threat alerts."""
        self._active_threats.clear()

    def simulate_attack_usb(
        self,
        *,
        attack_type: str = "double_extension",
    ) -> UsbThreatFindingView:
        """Inject a simulated malicious USB device and payload for SOC testing."""
        now = datetime.now(UTC)
        drive = "F:\\"
        dev_id = f"USB\\VID_0781&PID_5583\\SIMULATED_{int(now.timestamp())}"

        sim_device = UsbDeviceView(
            device_id=dev_id,
            name="SanDisk Ultra USB 3.0 (Simulated Rogue)",
            vendor_id="0781",
            product_id="5583",
            manufacturer="SanDisk Corp.",
            serial_number="SAN-DEMO-9912",
            device_class="mass_storage",
            drive_letter=drive,
            volume_label="USB_BACKUP",
            file_system="FAT32",
            total_bytes=32_000_000_000,
            free_bytes=28_400_000_000,
            is_connected=True,
            connected_at=now,
        )

        self._simulated_devices = [d for d in self._simulated_devices if d.drive_letter != drive]
        self._simulated_devices.append(sim_device)

        if attack_type == "autorun":
            fpath = f"{drive}autorun.inf"
            cat = "autorun_script"
            sev = "high"
            desc = "Weaponised autorun.inf configured to execute target: payload.exe"
            advice = "Disable AutoRun/AutoPlay and inspect payload before execution."
        elif attack_type == "lnk":
            fpath = f"{drive}Documents_2026.pdf.lnk"
            cat = "lnk_exploit"
            sev = "critical"
            desc = "Malicious LNK shortcut exploit detected: 'Documents_2026.pdf.lnk'. Embedded shell execution strings: powershell, -enc."
            advice = "Quarantine shortcut and check host for active shell processes."
        elif attack_type == "hidden":
            fpath = f"{drive}RECYCLER\\svchost.exe"
            cat = "hidden_payload"
            sev = "high"
            desc = "Hidden executable payload discovered on USB drive: 'svchost.exe' (inside hidden/recycler staging directory)."
            advice = "Prevent execution from hidden staging folders and isolate device."
        elif attack_type == "badusb":
            sim_device = UsbDeviceView(
                device_id="USB\\VID_16C0&PID_05DF\\RUBBER_DUCKY_01",
                name="USB Keyboard (Digispark Attiny85 Keystroke Injector)",
                vendor_id="16C0",
                product_id="05DF",
                manufacturer="Digistump (BadUSB Profile)",
                serial_number="DUCKY-INJECTOR-01",
                device_class="hid_keyboard",
                is_connected=True,
                connected_at=now,
            )
            self._simulated_devices = [d for d in self._simulated_devices if d.device_id != sim_device.device_id]
            self._simulated_devices.append(sim_device)
            fpath = "[USB_HARDWARE_DESCRIPTOR]"
            cat = "badusb_suspect"
            sev = "high"
            desc = "Potential BadUSB / HID keystroke injection hardware detected: 'USB Keyboard' [VID=16C0, PID=05DF]. Device registers as a keyboard using a microcontroller VID commonly used by Rubber Ducky/Digispark."
            advice = "Disconnect device immediately. Verify physical hardware authenticity."
        else:  # double_extension
            fpath = f"{drive}Confidential_Q3_Financials.pdf.exe"
            cat = "double_extension"
            sev = "critical"
            desc = "Deceptive double extension detected: 'Confidential_Q3_Financials.pdf.exe'. Masquerades as '.pdf' but executes '.exe'."
            advice = "Do not double-click. Quarantine or delete suspicious executable."

        finding_view = UsbThreatFindingView(
            finding_id=f"sim-threat-{int(now.timestamp())}",
            device_id=dev_id,
            drive_letter=drive,
            file_path=fpath,
            category=cat,
            severity=sev,
            description=desc,
            remediation_advice=advice,
            detected_at=now,
        )

        file_event_view = UsbFileEventView(
            path=fpath,
            drive_letter=drive,
            action="created",
            size_bytes=524288,
            modified_at=now,
            is_suspicious=True,
            threat_category=cat,
            threat_description=desc,
        )

        self._active_threats.insert(0, finding_view)
        self._recent_events.insert(0, file_event_view)
        self.threat_detected.emit(finding_view)
        self.file_activity.emit(file_event_view)
        self.devices_changed.emit(self.active_devices)

        return finding_view

    def disconnect_simulated(self) -> None:
        """Disconnect any simulated USB devices."""
        self._simulated_devices.clear()
        self.devices_changed.emit(self.active_devices)
