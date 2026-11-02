"""Map USB device, file activity, and threat findings onto canonical SecurityEvents."""

from __future__ import annotations

from datetime import UTC, datetime

from aegis_agent.monitors.usb.models import (
    UsbDevice,
    UsbFileAction,
    UsbFileEvent,
    UsbThreatFinding,
)
from aegis_shared.enums import EventType, Severity
from aegis_shared.events import FileContext, HostRef, SecurityEvent, SourceRef


def build_usb_device_event(
    device: UsbDevice,
    *,
    is_connected: bool,
    source: SourceRef,
    host: HostRef,
    timestamp: datetime | None = None,
) -> SecurityEvent:
    """Build a SecurityEvent for USB connection or disconnection."""
    event_type = EventType.USB_CONNECTED if is_connected else EventType.USB_DISCONNECTED
    action = "connected" if is_connected else "disconnected"
    ts = timestamp or datetime.now(UTC)

    msg = (
        f"USB Device {action}: {device.name} "
        f"[VID={device.vendor_id or 'N/A'}, PID={device.product_id or 'N/A'}, "
        f"Class={device.device_class.value}, Drive={device.drive_letter or 'N/A'}]"
    )

    return SecurityEvent.create(
        event_type=event_type,
        severity=Severity.INFO if is_connected else Severity.LOW,
        source=source,
        host=host,
        timestamp=ts,
        message=msg,
        labels={"subsystem": "usb", "action": action, "class": device.device_class.value},
    )


def build_usb_threat_event(
    finding: UsbThreatFinding,
    *,
    source: SourceRef,
    host: HostRef,
) -> SecurityEvent:
    """Build a SecurityEvent for detected weaponised USB threat."""
    return SecurityEvent.create(
        event_type=EventType.USB_THREAT_DETECTED,
        severity=finding.severity,
        source=source,
        host=host,
        timestamp=finding.detected_at,
        message=f"USB Attack Detected [{finding.category.value}]: {finding.description}",
        labels={"subsystem": "usb", "threat": finding.category.value},
    )

