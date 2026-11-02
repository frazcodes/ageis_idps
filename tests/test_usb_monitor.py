"""Unit and integration test suite for Aegis USB Attack Detection subsystem.

Verifies:
1. Real-time USB connect/disconnect monitoring and diffing.
2. Device identification and hardware inventory (VID, PID, class, manufacturer, capacity).
3. USB file activity monitoring (created, modified, deleted on removable drives).
4. Suspicious USB file detection (autorun.inf, double extensions, LNK exploits, hidden payloads).
5. Canonical SecurityEvent emission for SOC integration.
6. Desktop UsbSecurityService and UsbShieldWidget operation.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Sequence

import pytest
from PySide6.QtWidgets import QApplication

from aegis_agent.monitors.usb import (
    UsbChanges,
    UsbCollector,
    UsbDevice,
    UsbDeviceClass,
    UsbFileAction,
    UsbFileEvent,
    UsbFileRecord,
    UsbMonitor,
    UsbSnapshot,
    UsbThreatCategory,
    UsbThreatDetector,
    UsbThreatFinding,
    build_usb_device_event,
    build_usb_threat_event,
)
from aegis_agent.monitors.usb.collector import classify_usb_device, parse_vid_pid
from aegis_desktop.app import create_application
from aegis_desktop.services.usb_service import UsbSecurityService
from aegis_desktop.widgets.usb_shield import UsbShieldWidget
from aegis_shared.enums import EventType, Severity, SourceKind
from aegis_shared.events import HostRef, SourceRef


@pytest.fixture(scope="module")
def app() -> QApplication:
    return create_application([])


# ==============================================================================
# 1. Device Identification and Parsing Tests
# ==============================================================================


def test_parse_vid_pid_extraction() -> None:
    vid, pid = parse_vid_pid(r"USB\VID_0781&PID_5583\1234567890ABCDEF")
    assert vid == "0781"
    assert pid == "5583"

    vid, pid = parse_vid_pid(r"USB\VID_046D&PID_C52B\5&2C1B20A&0&1")
    assert vid == "046D"
    assert pid == "C52B"

    # Non-matching string
    vid, pid = parse_vid_pid("PCI\\VEN_10DE&DEV_1C82")
    assert vid == ""
    assert pid == ""


def test_classify_usb_device_types() -> None:
    assert classify_usb_device("USB\\STORAGE", "SanDisk Cruzer Disk Device") == UsbDeviceClass.MASS_STORAGE
    assert classify_usb_device("USB\\VID_046D", "Logitech USB Keyboard") == UsbDeviceClass.HID_KEYBOARD
    assert classify_usb_device("USB\\VID_046D", "Optical Gaming Mouse") == UsbDeviceClass.HID_MOUSE
    assert classify_usb_device("USB\\VID_0BDA", "Realtek USB GbE Network Controller") == UsbDeviceClass.NETWORK_ADAPTER
    assert classify_usb_device("USB\\VID_0BDA", "USB Audio Device / Webcam") == UsbDeviceClass.AUDIO_VIDEO
    assert classify_usb_device("USB\\ROOT_HUB30", "USB 3.0 Root Hub") == UsbDeviceClass.HUB


# ==============================================================================
# 2. Suspicious USB Threat Detection Tests
# ==============================================================================


def test_autorun_threat_detection() -> None:
    detector = UsbThreatDetector()

    # Plain autorun
    record = UsbFileRecord(
        path=r"E:\autorun.inf",
        drive_letter="E:\\",
        relative_path="autorun.inf",
        size_bytes=45,
    )
    findings = detector.scan_file(record)
    assert len(findings) == 1
    assert findings[0].category == UsbThreatCategory.AUTORUN_SCRIPT
    assert findings[0].severity == Severity.HIGH

    # Weaponised autorun with open target
    content = b"[AutoRun]\r\nopen=malware.exe\r\naction=Run payload"
    findings_weaponised = detector.scan_file(record, file_bytes=content)
    assert len(findings_weaponised) == 1
    assert "malware.exe" in findings_weaponised[0].description


def test_double_extension_detection() -> None:
    detector = UsbThreatDetector()

    suspicious_names = [
        "Annual_Report_2026.pdf.exe",
        "Employee_Payroll.xlsx.scr",
        "Invoice_INV-9921.docx.vbs",
        "Vacation_Photo.jpg.exe",
        "Contract_Final.pdf.bat",
        "Archive.zip.hta",
    ]

    for name in suspicious_names:
        record = UsbFileRecord(
            path=rf"E:\{name}",
            drive_letter="E:\\",
            relative_path=name,
            size_bytes=10240,
        )
        findings = detector.scan_file(record)
        assert len(findings) == 1, f"Expected threat for {name}"
        assert findings[0].category == UsbThreatCategory.DOUBLE_EXTENSION
        assert findings[0].severity == Severity.CRITICAL


def test_benign_files_produce_no_false_positives() -> None:
    detector = UsbThreatDetector()

    benign_names = [
        "Annual_Report_2026.pdf",
        "Employee_Payroll.xlsx",
        "Invoice.docx",
        "Vacation_Photo.jpg",
        "Presentation.pptx",
        "readme.txt",
        "dataset.csv",
    ]

    for name in benign_names:
        record = UsbFileRecord(
            path=rf"E:\Documents\{name}",
            drive_letter="E:\\",
            relative_path=f"Documents/{name}",
            size_bytes=50000,
        )
        findings = detector.scan_file(record)
        assert len(findings) == 0, f"False positive detected on {name}"


def test_malicious_lnk_shortcut_detection(tmp_path: Path) -> None:
    detector = UsbThreatDetector()

    # Create weaponised .lnk file containing powershell hidden invoke
    lnk_path = tmp_path / "Exploit.pdf.lnk"
    lnk_content = b"\x4c\x00\x00\x00" + b"powershell.exe -WindowStyle Hidden -enc SQBFAFgA"
    lnk_path.write_bytes(lnk_content)

    record = UsbFileRecord(
        path=str(lnk_path),
        drive_letter="E:\\",
        relative_path="Exploit.pdf.lnk",
        size_bytes=len(lnk_content),
    )
    findings = detector.scan_file(record, file_bytes=lnk_content)
    assert len(findings) == 1
    assert findings[0].category == UsbThreatCategory.LNK_EXPLOIT
    assert findings[0].severity == Severity.CRITICAL
    assert "powershell" in findings[0].description


def test_hidden_executable_payload_detection() -> None:
    detector = UsbThreatDetector()

    # Hidden binary in RECYCLER staging folder
    record_recycler = UsbFileRecord(
        path=r"E:\RECYCLER\svchost.exe",
        drive_letter="E:\\",
        relative_path="RECYCLER/svchost.exe",
        size_bytes=65536,
        is_hidden=True,
    )
    findings = detector.scan_file(record_recycler)
    assert len(findings) == 1
    assert findings[0].category == UsbThreatCategory.HIDDEN_PAYLOAD
    assert findings[0].severity == Severity.HIGH


def test_badusb_hardware_detection() -> None:
    detector = UsbThreatDetector()

    # Device with Digispark/Rubber Ducky microcontroller VID registering as Keyboard
    badusb_dev = UsbDevice(
        device_id=r"USB\VID_16C0&PID_05DF\123456",
        name="USB Keyboard",
        vendor_id="16C0",
        product_id="05DF",
        device_class=UsbDeviceClass.HID_KEYBOARD,
    )

    threats = detector.scan_device(badusb_dev)
    assert len(threats) == 1
    assert threats[0].category == UsbThreatCategory.BADUSB_SUSPECT
    assert threats[0].severity == Severity.HIGH
    assert "BadUSB" in threats[0].description


def test_office_macro_threat_detection() -> None:
    detector = UsbThreatDetector()

    record_macro = UsbFileRecord(
        path=r"E:\Q4_Bonus_Plan.docm",
        drive_letter="E:\\",
        relative_path="Q4_Bonus_Plan.docm",
        size_bytes=45000,
    )
    threats = detector.scan_file(record_macro)
    assert len(threats) == 1
    assert threats[0].category == UsbThreatCategory.SUSPICIOUS_EXECUTABLE
    assert "macro" in threats[0].description.lower()


# ==============================================================================
# 3. Real-Time Connect/Disconnect Monitoring Tests
# ==============================================================================


def test_usb_connect_and_disconnect_diffing() -> None:
    now = datetime.now(UTC)

    dev_a = UsbDevice(
        device_id=r"USB\VID_0781&PID_5583\SANDISK_01",
        name="SanDisk Cruzer Glide",
        vendor_id="0781",
        product_id="5583",
        manufacturer="SanDisk",
        device_class=UsbDeviceClass.MASS_STORAGE,
        drive_letter="E:\\",
        volume_label="SANDISK",
        total_bytes=16_000_000_000,
        free_bytes=14_000_000_000,
        is_connected=True,
        connected_at=now,
    )

    dev_b = UsbDevice(
        device_id=r"USB\VID_0951&PID_1666\KINGSTON_02",
        name="Kingston DataTraveler",
        vendor_id="0951",
        product_id="1666",
        manufacturer="Kingston",
        device_class=UsbDeviceClass.MASS_STORAGE,
        drive_letter="F:\\",
        volume_label="KINGSTON",
        total_bytes=32_000_000_000,
        free_bytes=30_000_000_000,
        is_connected=True,
        connected_at=now,
    )

    current_devices: list[UsbDevice] = [dev_a]

    collector = UsbCollector(
        device_provider=lambda: current_devices,
        drive_provider=lambda: [],
        file_provider=lambda _: [],
    )
    monitor = UsbMonitor(collector=collector)

    # 1. Establish baseline (only dev_a present)
    baseline = monitor.start()
    assert len(baseline.devices) == 1
    assert baseline.devices[0].device_id == dev_a.device_id

    # 2. Attach dev_b
    current_devices = [dev_a, dev_b]
    changes_connect = monitor.poll()
    assert len(changes_connect.connected_devices) == 1
    assert changes_connect.connected_devices[0].device_id == dev_b.device_id
    assert len(changes_connect.disconnected_devices) == 0

    # 3. Disconnect dev_a (dev_b still connected)
    current_devices = [dev_b]
    changes_disconnect = monitor.poll()
    assert len(changes_disconnect.connected_devices) == 0
    assert len(changes_disconnect.disconnected_devices) == 1
    assert changes_disconnect.disconnected_devices[0].device_id == dev_a.device_id
    assert changes_disconnect.disconnected_devices[0].is_connected is False


# ==============================================================================
# 4. USB Removable Media File Activity Monitoring Tests
# ==============================================================================


def test_usb_file_activity_tracking() -> None:
    now = datetime.now(UTC)

    f1 = UsbFileRecord(
        path=r"E:\Documents\report.pdf",
        drive_letter="E:\\",
        relative_path="Documents/report.pdf",
        size_bytes=1024,
        modified_at=now,
    )
    f2_clean = UsbFileRecord(
        path=r"E:\work.txt",
        drive_letter="E:\\",
        relative_path="work.txt",
        size_bytes=500,
        modified_at=now,
    )
    f3_threat = UsbFileRecord(
        path=r"E:\Invoice.docx.exe",
        drive_letter="E:\\",
        relative_path="Invoice.docx.exe",
        size_bytes=8192,
        modified_at=now,
    )

    current_files: list[UsbFileRecord] = [f1]

    collector = UsbCollector(
        device_provider=lambda: [],
        drive_provider=lambda: ["E:\\"],
        file_provider=lambda _: current_files,
    )
    monitor = UsbMonitor(collector=collector)
    monitor.start()

    # 1. Add f2 and malicious f3
    current_files = [f1, f2_clean, f3_threat]
    changes = monitor.poll()

    assert len(changes.file_events) == 2
    created_paths = {fe.path for fe in changes.file_events}
    assert r"E:\work.txt" in created_paths
    assert r"E:\Invoice.docx.exe" in created_paths

    # Malicious file detected
    assert len(changes.threat_findings) == 1
    assert changes.threat_findings[0].category == UsbThreatCategory.DOUBLE_EXTENSION

    # 2. Modify f1
    f1_modified = UsbFileRecord(
        path=r"E:\Documents\report.pdf",
        drive_letter="E:\\",
        relative_path="Documents/report.pdf",
        size_bytes=2048,  # Size changed
        modified_at=datetime.now(UTC),
    )
    current_files = [f1_modified, f2_clean, f3_threat]
    changes_mod = monitor.poll()

    assert len(changes_mod.file_events) == 1
    assert changes_mod.file_events[0].action == UsbFileAction.MODIFIED
    assert changes_mod.file_events[0].path == r"E:\Documents\report.pdf"

    # 3. Delete f2
    current_files = [f1_modified, f3_threat]
    changes_del = monitor.poll()

    assert len(changes_del.file_events) == 1
    assert changes_del.file_events[0].action == UsbFileAction.DELETED
    assert changes_del.file_events[0].path == r"E:\work.txt"


# ==============================================================================
# 5. SecurityEvent Generation Tests
# ==============================================================================


def test_build_usb_security_events() -> None:
    source = SourceRef(kind=SourceKind.AGENT, id="agent-01")
    host = HostRef(host_id="host-01", hostname="TEST-WORKSTATION", platform="windows")
    now = datetime.now(UTC)

    dev = UsbDevice(
        device_id=r"USB\VID_0781&PID_5583\12345678",
        name="SanDisk Cruzer",
        vendor_id="0781",
        product_id="5583",
        device_class=UsbDeviceClass.MASS_STORAGE,
        drive_letter="E:\\",
    )

    conn_event = build_usb_device_event(dev, is_connected=True, source=source, host=host, timestamp=now)
    assert conn_event.event_type == EventType.USB_CONNECTED
    assert conn_event.severity == Severity.INFO
    assert conn_event.message is not None
    assert "SanDisk Cruzer" in conn_event.message

    disconn_event = build_usb_device_event(dev, is_connected=False, source=source, host=host, timestamp=now)
    assert disconn_event.event_type == EventType.USB_DISCONNECTED
    assert disconn_event.severity == Severity.LOW

    finding = UsbThreatFinding(
        device_id=dev.device_id,
        drive_letter="E:\\",
        file_path=r"E:\autorun.inf",
        category=UsbThreatCategory.AUTORUN_SCRIPT,
        severity=Severity.HIGH,
        description="Detected autorun.inf",
        remediation_advice="Inspect and isolate",
        detected_at=now,
    )

    threat_event = build_usb_threat_event(finding, source=source, host=host)
    assert threat_event.event_type == EventType.USB_THREAT_DETECTED
    assert threat_event.severity == Severity.HIGH
    assert threat_event.message is not None
    assert "autorun_script" in threat_event.message


# ==============================================================================
# 6. Desktop Presentation Service & Widget Integration
# ==============================================================================


def test_usb_security_service_simulation() -> None:
    service = UsbSecurityService()
    finding = service.simulate_attack_usb(attack_type="double_extension")

    assert finding is not None
    assert finding.category == "double_extension"
    assert len(service.active_threats) >= 1
    assert len(service.active_devices) >= 1

    # Disconnect simulated
    service.disconnect_simulated()
    service.clear_threats()
    assert len(service.active_threats) == 0


def test_usb_shield_widget_display(app: QApplication) -> None:
    service = UsbSecurityService()
    widget = UsbShieldWidget(service=service)

    # Initial state
    assert widget._dev_table.columnCount() == 7
    assert widget._act_table.columnCount() == 6

    # Simulate attack injection
    service.simulate_attack_usb(attack_type="autorun")
    widget.refresh_display()

    assert widget._alert_banner.isHidden() is False
    assert widget._act_table.rowCount() >= 1

    # Clear alerts
    widget._clear_alerts()
    assert widget._alert_banner.isHidden() is True

