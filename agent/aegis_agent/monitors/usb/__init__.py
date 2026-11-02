"""USB attack detection and removable storage monitoring subsystem.

Capabilities:
1. Real-time USB connect/disconnect monitoring.
2. Device identification and inventory (VID, PID, device class, manufacturer, serial number, volume label).
3. USB file activity monitoring (created, modified, deleted on removable drives).
4. Suspicious USB file detection (autorun.inf, double extensions, LNK shortcut exploits, hidden payloads).
"""

from __future__ import annotations

from aegis_agent.monitors.usb.collector import UsbCollector
from aegis_agent.monitors.usb.detector import UsbThreatDetector
from aegis_agent.monitors.usb.events import (
    build_usb_device_event,
    build_usb_threat_event,
)
from aegis_agent.monitors.usb.models import (
    UsbChanges,
    UsbDevice,
    UsbDeviceClass,
    UsbFileAction,
    UsbFileEvent,
    UsbFileRecord,
    UsbSnapshot,
    UsbThreatCategory,
    UsbThreatFinding,
)
from aegis_agent.monitors.usb.monitor import UsbMonitor

__all__ = [
    "UsbChanges",
    "UsbCollector",
    "UsbDevice",
    "UsbDeviceClass",
    "UsbFileAction",
    "UsbFileEvent",
    "UsbFileRecord",
    "UsbMonitor",
    "UsbSnapshot",
    "UsbThreatCategory",
    "UsbThreatDetector",
    "UsbThreatFinding",
    "build_usb_device_event",
    "build_usb_threat_event",
]

