"""Typed models for USB attack detection and removable media monitoring.

Covers:
1. Real-time USB connect/disconnect device state.
2. Device identification and hardware inventory (VID, PID, Serial, Class, Manufacturer).
3. USB file activity tracking (created, modified, deleted on removable drives).
4. Threat findings for weaponised USB attacks (Autorun, double extensions, LNK exploits, hidden binaries).
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
import uuid

from pydantic import BaseModel, ConfigDict, Field

from aegis_shared.enums import Severity


class UsbDeviceClass(StrEnum):
    """Categorisation of USB device by function / PNP class."""

    MASS_STORAGE = "mass_storage"
    HID_KEYBOARD = "hid_keyboard"
    HID_MOUSE = "hid_mouse"
    HID_DEVICE = "hid_device"
    NETWORK_ADAPTER = "network_adapter"
    SMART_CARD = "smart_card"
    AUDIO_VIDEO = "audio_video"
    WIRELESS = "wireless"
    PRINTER = "printer"
    HUB = "hub"
    VENDOR_SPECIFIC = "vendor_specific"
    UNKNOWN = "unknown"


class UsbFileAction(StrEnum):
    """Action observed on a file residing on a removable drive."""

    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"


class UsbThreatCategory(StrEnum):
    """Specific USB attack vector or suspicious signature."""

    AUTORUN_SCRIPT = "autorun_script"
    DOUBLE_EXTENSION = "double_extension"
    LNK_EXPLOIT = "lnk_exploit"
    HIDDEN_PAYLOAD = "hidden_payload"
    SUSPICIOUS_EXECUTABLE = "suspicious_executable"
    BADUSB_SUSPECT = "badusb_suspect"


class UsbDevice(BaseModel):
    """Complete hardware and filesystem metadata for a connected USB device."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    device_id: str = Field(description="Hardware PNP Device ID or Instance Path")
    name: str = Field(default="Unknown USB Device", description="Friendly device name")
    vendor_id: str = Field(default="", description="4-digit hex Vendor ID (VID)")
    product_id: str = Field(default="", description="4-digit hex Product ID (PID)")
    manufacturer: str = Field(default="", description="Hardware manufacturer string")
    serial_number: str = Field(default="", description="Device hardware serial number")
    device_class: UsbDeviceClass = Field(default=UsbDeviceClass.UNKNOWN)
    drive_letter: str | None = Field(default=None, description="Mounted drive letter e.g. E:\\")
    volume_label: str | None = Field(default=None, description="Removable filesystem volume label")
    file_system: str | None = Field(default=None, description="Filesystem type e.g. FAT32, NTFS, exFAT")
    total_bytes: int | None = Field(default=None, ge=0)
    free_bytes: int | None = Field(default=None, ge=0)
    is_connected: bool = Field(default=True)
    connected_at: datetime | None = Field(default=None)
    disconnected_at: datetime | None = Field(default=None)

    @property
    def identity_key(self) -> str:
        """Stable key used to track device across polling cycles."""
        return self.device_id.strip().upper()


class UsbFileRecord(BaseModel):
    """Safe metadata of a file observed on a removable drive."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    path: str = Field(description="Full normalised file path on the drive")
    drive_letter: str = Field(description="Drive letter prefix e.g. E:\\")
    relative_path: str = Field(description="Path relative to the drive root")
    size_bytes: int = Field(ge=0)
    modified_at: datetime | None = None
    sha256: str | None = None
    is_hidden: bool = False

    @property
    def identity_key(self) -> str:
        return os.path.normcase(self.path)


class UsbFileEvent(BaseModel):
    """File activity event on removable media."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    drive_letter: str
    action: UsbFileAction
    size_bytes: int = 0
    modified_at: datetime | None = None
    sha256: str | None = None
    is_suspicious: bool = False
    threat_category: UsbThreatCategory | None = None
    threat_description: str | None = None


class UsbThreatFinding(BaseModel):
    """A detected threat or anomaly originating from removable media."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str | None = None
    drive_letter: str | None = None
    file_path: str
    category: UsbThreatCategory
    severity: Severity
    description: str
    remediation_advice: str
    detected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class UsbSnapshot(BaseModel):
    """State of connected USB devices and removable drive files at a single moment."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    devices: tuple[UsbDevice, ...] = Field(default_factory=tuple)
    files: tuple[UsbFileRecord, ...] = Field(default_factory=tuple)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def device_map(self) -> dict[str, UsbDevice]:
        return {d.identity_key: d for d in self.devices}

    def file_map(self) -> dict[str, UsbFileRecord]:
        return {f.identity_key: f for f in self.files}


class UsbChanges(BaseModel):
    """Difference between two USB snapshots."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    connected_devices: tuple[UsbDevice, ...] = Field(default_factory=tuple)
    disconnected_devices: tuple[UsbDevice, ...] = Field(default_factory=tuple)
    file_events: tuple[UsbFileEvent, ...] = Field(default_factory=tuple)
    threat_findings: tuple[UsbThreatFinding, ...] = Field(default_factory=tuple)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

