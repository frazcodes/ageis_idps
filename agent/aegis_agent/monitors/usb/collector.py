"""Hardware and filesystem collector for USB devices and removable media.

Enumerates:
1. Physical/virtual USB devices (VID, PID, manufacturer, serial number, PNP class).
2. Mounted removable filesystem partitions (drive letters, volume label, capacities).
3. Files resident on removable drives up to a bounded recursion depth.
"""

from __future__ import annotations

import hashlib
import os
import re
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psutil

from aegis_agent.monitors.usb.models import (
    UsbDevice,
    UsbDeviceClass,
    UsbFileRecord,
    UsbSnapshot,
)
from aegis_shared.logging import get_logger

logger = get_logger(__name__)

# Known vendor IDs for common USB manufacturers
KNOWN_USB_VENDORS: dict[str, str] = {
    "0781": "SanDisk Corp.",
    "058F": "Alcor Micro Corp.",
    "0951": "Kingston Technology",
    "13FE": "Phison Electronics Corp.",
    "090C": "Silicon Motion, Inc.",
    "8564": "Transcend Information, Inc.",
    "046D": "Logitech, Inc.",
    "045E": "Microsoft Corp.",
    "1058": "Western Digital Technologies",
    "0BC2": "Seagate RSS LLC",
    "18A5": "Verbatim, Ltd.",
    "054C": "Sony Corp.",
    "04E8": "Samsung Electronics Co., Ltd.",
    "125F": "ADATA Technology Co., Ltd.",
    "1B1C": "Corsair",
    "03F0": "HP Inc.",
    "1A40": "TERMINUS TECHNOLOGY INC.",
    "17EF": "Lenovo",
    # Maker / BadUSB prototyping microcontrollers
    "16C0": "Digistump / Atmel (BadUSB Profile)",
    "2341": "Arduino SA (BadUSB / HID Profile)",
    "2E8A": "Raspberry Pi (Pico Keystroke Injector Profile)",
    "03EB": "Atmel Corp. (Hak5 Rubber Ducky Profile)",
    "1B4F": "SparkFun Electronics",
    "CAFE": "Flipper Zero / TinyFPGA Profile",
}

_VID_PID_REGEX = re.compile(r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})", re.IGNORECASE)
_SERIAL_REGEX = re.compile(r"USB\\[^\\]+\\([^\s]+)", re.IGNORECASE)


def classify_usb_device(device_id: str, name: str, pnp_class: str = "") -> UsbDeviceClass:
    """Infer USB device class from hardware descriptors."""
    text = f"{device_id} {name} {pnp_class}".lower()

    if "disk" in text or "storage" in text or "mass" in text:
        return UsbDeviceClass.MASS_STORAGE
    if "keyboard" in text or "kbd" in text:
        return UsbDeviceClass.HID_KEYBOARD
    if "mouse" in text or "pointing" in text:
        return UsbDeviceClass.HID_MOUSE
    if "hid" in text or "human interface" in text:
        return UsbDeviceClass.HID_DEVICE
    if "net" in text or "ethernet" in text or "802.11" in text or "wi-fi" in text:
        return UsbDeviceClass.NETWORK_ADAPTER
    if "smart" in text and "card" in text:
        return UsbDeviceClass.SMART_CARD
    if "audio" in text or "video" in text or "camera" in text or "mic" in text:
        return UsbDeviceClass.AUDIO_VIDEO
    if "bluetooth" in text or "wireless" in text:
        return UsbDeviceClass.WIRELESS
    if "print" in text:
        return UsbDeviceClass.PRINTER
    if "hub" in text:
        return UsbDeviceClass.HUB
    return UsbDeviceClass.UNKNOWN


def parse_vid_pid(device_id: str) -> tuple[str, str]:
    """Extract 4-digit hex Vendor ID and Product ID from a device ID string."""
    match = _VID_PID_REGEX.search(device_id)
    if match:
        return match.group(1).upper(), match.group(2).upper()
    return "", ""


class UsbCollector:
    """Safe, bounded enumerator for USB hardware and removable drive filesystems."""

    def __init__(
        self,
        *,
        max_scan_depth: int = 3,
        max_hash_bytes: int = 1_048_576,  # 1 MB
        device_provider: Callable[[], Sequence[UsbDevice]] | None = None,
        drive_provider: Callable[[], Sequence[str]] | None = None,
        file_provider: Callable[[str], Sequence[UsbFileRecord]] | None = None,
    ) -> None:
        self._max_scan_depth = max(1, min(max_scan_depth, 10))
        self._max_hash_bytes = max_hash_bytes
        self._custom_device_provider = device_provider
        self._custom_drive_provider = drive_provider
        self._custom_file_provider = file_provider

    def collect(self) -> UsbSnapshot:
        """Capture a snapshot of connected USB devices and removable drive files."""
        now = datetime.now(UTC)

        devices = self._collect_devices(now)
        files: list[UsbFileRecord] = []

        # Find all mounted removable drive letters
        removable_drives = self._find_removable_drives()

        for drive in removable_drives:
            files.extend(self._collect_drive_files(drive))

        return UsbSnapshot(
            devices=tuple(devices),
            files=tuple(files),
            timestamp=now,
        )

    def _collect_devices(self, timestamp: datetime) -> list[UsbDevice]:
        if self._custom_device_provider:
            return list(self._custom_device_provider())

        devices: list[UsbDevice] = []

        if sys.platform == "win32":
            devices.extend(self._collect_windows_devices(timestamp))
        else:
            # Fallback for non-Windows (Linux / mock)
            devices.extend(self._collect_generic_devices(timestamp))

        return devices

    def _collect_windows_devices(self, timestamp: datetime) -> list[UsbDevice]:
        devices: list[UsbDevice] = []
        seen_ids: set[str] = set()

        # Step 1: Active physical PnP USB hardware devices from Windows CIM
        try:
            import json
            import subprocess

            cmd = [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-CimInstance Win32_PnPEntity -Filter \"Status = 'OK' AND DeviceID LIKE 'USB%'\" | "
                "Select-Object DeviceID, Name, Manufacturer, PNPClass | ConvertTo-Json -Compress",
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            if res.returncode == 0 and res.stdout.strip():
                raw = json.loads(res.stdout)
                items = raw if isinstance(raw, list) else [raw]
                for item in items:
                    dev_id = str(item.get("DeviceID") or "").strip()
                    if not dev_id or dev_id.upper() in seen_ids:
                        continue
                    seen_ids.add(dev_id.upper())

                    name = str(item.get("Name") or "USB Device").strip()
                    pnp_cls = str(item.get("PNPClass") or "").strip()
                    mfg = str(item.get("Manufacturer") or "").strip()
                    vid, pid = parse_vid_pid(dev_id)
                    dev_cls = classify_usb_device(dev_id, name, pnp_cls)

                    # Lookup vendor
                    if vid and vid in KNOWN_USB_VENDORS and (not mfg or "standard" in mfg.lower()):
                        mfg = KNOWN_USB_VENDORS[vid]

                    # Serial extraction from PnP ID
                    serial = ""
                    parts = dev_id.split("\\")
                    if len(parts) >= 3 and "&" not in parts[2]:
                        serial = parts[2]

                    devices.append(
                        UsbDevice(
                            device_id=dev_id,
                            name=name,
                            vendor_id=vid,
                            product_id=pid,
                            manufacturer=mfg,
                            serial_number=serial,
                            device_class=dev_cls,
                            is_connected=True,
                            connected_at=timestamp,
                        )
                    )
        except Exception as exc:
            logger.debug("CIM PnP query failed, falling back to volume enumeration: %s", exc)

        # Step 2: Removable disk partitions & volume mapping
        removable_drives = self._find_removable_drives()
        for drive_path in removable_drives:
            norm_drive = os.path.normpath(drive_path)
            device_id = f"USB\\STORAGE_DRIVE\\{norm_drive.replace(':', '').replace('\\', '')}"

            if device_id.upper() in seen_ids:
                continue
            seen_ids.add(device_id.upper())

            total, free, fstype = None, None, None
            try:
                usage = psutil.disk_usage(drive_path)
                total, free = usage.total, usage.free
            except Exception:
                pass

            for part in psutil.disk_partitions(all=False):
                if os.path.normpath(part.mountpoint).upper() == norm_drive.upper():
                    fstype = part.fstype
                    break

            volume_label = None
            try:
                import ctypes
                vol_buf = ctypes.create_unicode_buffer(261)
                ctypes.windll.kernel32.GetVolumeInformationW(
                    drive_path if drive_path.endswith("\\") else drive_path + "\\",
                    vol_buf,
                    ctypes.sizeof(vol_buf),
                    None,
                    None,
                    None,
                    None,
                    0,
                )
                volume_label = vol_buf.value
            except Exception:
                pass

            if not volume_label:
                volume_label = Path(drive_path).name or norm_drive

            devices.append(
                UsbDevice(
                    device_id=device_id,
                    name=f"Removable Storage ({norm_drive})",
                    vendor_id="GENERIC",
                    product_id="FLASH",
                    manufacturer="Removable USB Drive",
                    serial_number=f"VOL-{norm_drive[:1]}",
                    device_class=UsbDeviceClass.MASS_STORAGE,
                    drive_letter=norm_drive,
                    volume_label=volume_label,
                    file_system=fstype,
                    total_bytes=total,
                    free_bytes=free,
                    is_connected=True,
                    connected_at=timestamp,
                )
            )

        return devices

    def _collect_generic_devices(self, timestamp: datetime) -> list[UsbDevice]:
        devices: list[UsbDevice] = []
        for part in psutil.disk_partitions(all=False):
            if "removable" in part.opts.lower():
                devices.append(
                    UsbDevice(
                        device_id=f"USB\\STORAGE\\{part.device}",
                        name=f"Removable Media ({part.mountpoint})",
                        vendor_id="",
                        product_id="",
                        device_class=UsbDeviceClass.MASS_STORAGE,
                        drive_letter=part.mountpoint,
                        file_system=part.fstype,
                        is_connected=True,
                        connected_at=timestamp,
                    )
                )
        return devices

    def _find_removable_drives(self) -> list[str]:
        if self._custom_drive_provider:
            return list(self._custom_drive_provider())

        drives: list[str] = []
        seen = set()

        # Method A: ctypes GetDriveTypeW (DRIVE_REMOVABLE = 2)
        if sys.platform == "win32":
            try:
                import ctypes
                for letter in "EFGHIJKLMNOPQRSTUVWXYZ":
                    root = f"{letter}:\\"
                    if ctypes.windll.kernel32.GetDriveTypeW(root) == 2:  # DRIVE_REMOVABLE
                        drives.append(root)
                        seen.add(root.upper())
            except Exception:
                pass

        # Method B: psutil partitions
        for part in psutil.disk_partitions(all=False):
            opts = part.opts.lower()
            norm = os.path.normpath(part.mountpoint)
            if ("removable" in opts or part.fstype.lower() in {"fat32", "exfat", "vfat"}) and norm.upper() not in seen:
                drives.append(part.mountpoint)
                seen.add(norm.upper())

        return drives

    def _collect_drive_files(self, drive_root: str) -> list[UsbFileRecord]:
        if self._custom_file_provider:
            return list(self._custom_file_provider(drive_root))

        records: list[UsbFileRecord] = []
        root_path = Path(drive_root)
        if not root_path.exists():
            return records

        norm_root = os.path.normcase(os.path.abspath(drive_root))

        try:
            for current_root, dirs, files in os.walk(drive_root, topdown=True):
                # Calculate current depth relative to root
                rel = os.path.relpath(current_root, drive_root)
                depth = 0 if rel == "." else len(Path(rel).parts)

                if depth >= self._max_scan_depth:
                    dirs.clear()  # Do not recurse deeper than max_scan_depth
                    continue

                for fname in files:
                    full_path = os.path.join(current_root, fname)
                    try:
                        st = os.stat(full_path)
                        rel_file = os.path.relpath(full_path, drive_root)

                        # Check if hidden
                        is_hidden = fname.startswith(".")
                        if sys.platform == "win32":
                            try:
                                import ctypes
                                attrs = ctypes.windll.kernel32.GetFileAttributesW(full_path)
                                if attrs != -1 and (attrs & 2):  # FILE_ATTRIBUTE_HIDDEN = 2
                                    is_hidden = True
                            except Exception:
                                pass

                        sha256_hex = None
                        if 0 < st.st_size <= self._max_hash_bytes:
                            sha256_hex = self._compute_sha256(full_path)

                        mtime = (
                            datetime.fromtimestamp(st.st_mtime, tz=UTC)
                            if st.st_mtime
                            else None
                        )

                        records.append(
                            UsbFileRecord(
                                path=os.path.normpath(full_path),
                                drive_letter=drive_root,
                                relative_path=rel_file,
                                size_bytes=st.st_size,
                                modified_at=mtime,
                                sha256=sha256_hex,
                                is_hidden=is_hidden,
                            )
                        )
                    except (PermissionError, FileNotFoundError, OSError):
                        continue
        except (PermissionError, OSError) as exc:
            logger.debug("Failed traversing removable drive %s: %s", drive_root, exc)

        return records

    def _compute_sha256(self, path: str) -> str | None:
        try:
            hasher = hashlib.sha256()
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return None

