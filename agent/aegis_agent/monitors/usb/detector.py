"""Rule-based threat detector for removable USB media.

Detects common weaponised USB attacks:
1. Autorun execution: autorun.inf files targeting auto-play/execution.
2. Double extensions: e.g. document.pdf.exe, invoice.docx.scr.
3. LNK shortcut weaponisation: .lnk files invoking command shells or script hosts.
4. Hidden executable payloads: executables located in hidden directories (e.g. RECYCLER) or with hidden attributes.
5. Suspicious root scripts/binaries: raw scripts or executables directly on the drive root.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Sequence

from aegis_agent.monitors.usb.models import (
    UsbDevice,
    UsbDeviceClass,
    UsbFileRecord,
    UsbThreatCategory,
    UsbThreatFinding,
)
from aegis_shared.enums import Severity
from aegis_shared.logging import get_logger

logger = get_logger(__name__)

# Extensions known to masquerade behind common document extensions
_DANGEROUS_TARGET_EXTS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".ps1", ".hta", ".cpl", ".pif", ".jar", ".com"
}

# Deceptive document/media extensions
_DECEPTIVE_PRE_EXTS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".txt", ".rtf", ".jpg", ".jpeg", ".png", ".mp4", ".mp3",
    ".zip", ".rar", ".7z", ".iso", ".csv"
}

# Double extension pattern
_DOUBLE_EXT_PATTERN = re.compile(
    r"^.+(\.(?:pdf|docx?|xlsx?|pptx?|txt|rtf|jpe?g|png|mp4|mp3|zip|rar|7z|iso|csv))"
    r"(\.(?:exe|scr|bat|cmd|vbs|vbe|js|jse|wsf|wsh|ps1|hta|cpl|pif|jar|com))$",
    re.IGNORECASE,
)

# Malicious LOLBINs or script engines frequently spawned by LNK files
_LNK_SUSPICIOUS_STRINGS = [
    b"cmd.exe", b"powershell", b"pwsh", b"wscript", b"cscript",
    b"mshta", b"rundll32", b"certutil", b"bitsadmin", b"regsvr32",
    b"curl", b"wget", b"-enc", b"-encodedcommand", b"hidden",
    b"bypass", b"/c ", b"/k "
]

# Suspicious directories often used to stage USB malware
_SUSPICIOUS_DIR_NAMES = {
    "recycler", "$recycle.bin", "system volume information",
    ".trashes", ".fseventsd", ".hidden"
}

# Known vendor IDs of microcontrollers frequently used for BadUSB / HID injection
BADUSB_SUSPICIOUS_VIDS = {
    "16C0",  # Digistump / Atmel (Digispark)
    "2341",  # Arduino SA
    "2E8A",  # Raspberry Pi Foundation (Raspberry Pi Pico)
    "03EB",  # Atmel Corp. (Hak5 Rubber Ducky / AVR)
    "1B4F",  # SparkFun Electronics
    "CAFE",  # Flipper Zero / TinyFPGA BadUSB
}

# Suspicious weaponised macro document extensions
_MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".settingcontent-ms", ".iqy"}


class UsbThreatDetector:
    """Evaluates files discovered on removable drives against USB threat rules."""

    def scan_file(
        self,
        record: UsbFileRecord,
        *,
        device_id: str | None = None,
        file_bytes: bytes | None = None,
    ) -> list[UsbThreatFinding]:
        """Scan a single USB file record and return any detected threat findings."""
        findings: list[UsbThreatFinding] = []
        filename = Path(record.path).name.strip()
        filename_lower = filename.lower()
        rel_path = record.relative_path.replace("\\", "/").strip("/").lower()

        # 1. Check for autorun.inf
        if filename_lower == "autorun.inf":
            desc = "Detected autorun.inf in removable drive. Potential auto-execution vector."
            if file_bytes:
                try:
                    text = file_bytes.decode("utf-8", errors="ignore").lower()
                    if "open=" in text or "shellexecute=" in text:
                        match_target = re.search(r"(?:open|shellexecute)\s*=\s*([^\r\n]+)", text)
                        target_str = match_target.group(1) if match_target else "unknown target"
                        desc = f"Weaponised autorun.inf configured to execute target: {target_str.strip()}"
                except Exception:
                    pass

            findings.append(
                UsbThreatFinding(
                    device_id=device_id,
                    drive_letter=record.drive_letter,
                    file_path=record.path,
                    category=UsbThreatCategory.AUTORUN_SCRIPT,
                    severity=Severity.HIGH,
                    description=desc,
                    remediation_advice="Disable Windows AutoRun/AutoPlay and inspect or remove autorun.inf immediately.",
                )
            )

        # 2. Check for double extension disguise
        match = _DOUBLE_EXT_PATTERN.match(filename)
        if match:
            doc_ext, exec_ext = match.group(1), match.group(2)
            findings.append(
                UsbThreatFinding(
                    device_id=device_id,
                    drive_letter=record.drive_letter,
                    file_path=record.path,
                    category=UsbThreatCategory.DOUBLE_EXTENSION,
                    severity=Severity.CRITICAL,
                    description=(
                        f"Deceptive double extension detected: '{filename}'. "
                        f"Masquerades as '{doc_ext}' but executes executable payload '{exec_ext}'."
                    ),
                    remediation_advice="Do not double-click. Quarantine or delete the suspicious executable.",
                )
            )

        # 3. Check for weaponised LNK shortcut
        if filename_lower.endswith(".lnk"):
            content = file_bytes
            if content is None and os.path.exists(record.path):
                try:
                    with open(record.path, "rb") as f:
                        content = f.read(4096)  # Read header + string table
                except Exception:
                    content = None

            if content:
                content_lower = content.lower()
                matched_engines = [
                    engine.decode("ascii")
                    for engine in _LNK_SUSPICIOUS_STRINGS
                    if engine in content_lower
                ]
                if matched_engines:
                    findings.append(
                        UsbThreatFinding(
                            device_id=device_id,
                            drive_letter=record.drive_letter,
                            file_path=record.path,
                            category=UsbThreatCategory.LNK_EXPLOIT,
                            severity=Severity.CRITICAL,
                            description=(
                                f"Malicious LNK shortcut exploit detected: '{filename}'. "
                                f"Embedded shell execution strings found: {', '.join(matched_engines[:4])}."
                            ),
                            remediation_advice="Quarantine shortcut and check host for active shell processes.",
                        )
                    )

        # 4. Check for hidden executable payload
        ext = Path(filename).suffix.lower()
        is_binary = ext in _DANGEROUS_TARGET_EXTS

        parts = [p.lower() for p in rel_path.split("/") if p]
        in_suspicious_dir = any(part in _SUSPICIOUS_DIR_NAMES for part in parts)

        if is_binary and (record.is_hidden or in_suspicious_dir):
            reason = "inside hidden/recycler staging directory" if in_suspicious_dir else "marked with hidden attribute"
            findings.append(
                UsbThreatFinding(
                    device_id=device_id,
                    drive_letter=record.drive_letter,
                    file_path=record.path,
                    category=UsbThreatCategory.HIDDEN_PAYLOAD,
                    severity=Severity.HIGH,
                    description=f"Hidden executable payload discovered on USB drive: '{filename}' ({reason}).",
                    remediation_advice="Inspect file origin and prevent execution from hidden staging folders.",
                )
            )
        elif is_binary and not match and len(parts) <= 1:
            # Binary directly at the root of removable drive (not already flagged as double extension)
            findings.append(
                UsbThreatFinding(
                    device_id=device_id,
                    drive_letter=record.drive_letter,
                    file_path=record.path,
                    category=UsbThreatCategory.SUSPICIOUS_EXECUTABLE,
                    severity=Severity.MEDIUM,
                    description=f"Executable binary or script located at root of USB drive: '{filename}'.",
                    remediation_advice="Verify vendor identity and digital signature before running.",
                )
            )

        # 5. Check for weaponised Office Macro or SettingContent-ms files
        if ext in _MACRO_EXTENSIONS:
            findings.append(
                UsbThreatFinding(
                    device_id=device_id,
                    drive_letter=record.drive_letter,
                    file_path=record.path,
                    category=UsbThreatCategory.SUSPICIOUS_EXECUTABLE,
                    severity=Severity.HIGH,
                    description=f"Potential weaponised Office macro or shortcut discovered on USB drive: '{filename}'.",
                    remediation_advice="Do not enable macros or open suspicious office documents from untrusted removable media.",
                )
            )

        return findings

    def scan_device(self, device: UsbDevice) -> list[UsbThreatFinding]:
        """Evaluate a connected physical/virtual USB device for hardware-level threats (BadUSB)."""
        findings: list[UsbThreatFinding] = []
        vid_upper = device.vendor_id.strip().upper()

        # Check for BadUSB / Keystroke Injection hardware profiles
        if device.device_class == UsbDeviceClass.HID_KEYBOARD and vid_upper in BADUSB_SUSPICIOUS_VIDS:
            findings.append(
                UsbThreatFinding(
                    device_id=device.device_id,
                    drive_letter=device.drive_letter,
                    file_path="[USB_HARDWARE_DESCRIPTOR]",
                    category=UsbThreatCategory.BADUSB_SUSPECT,
                    severity=Severity.HIGH,
                    description=(
                        f"Potential BadUSB / HID keystroke injection hardware detected: '{device.name}' "
                        f"[VID={device.vendor_id}, PID={device.product_id}]. "
                        f"Device registers as a keyboard using a microcontroller VID commonly used by Rubber Ducky/Digispark."
                    ),
                    remediation_advice="Disconnect device immediately. Verify physical hardware authenticity.",
                )
            )
        return findings

    def scan_files(
        self,
        records: Sequence[UsbFileRecord],
        *,
        device_id: str | None = None,
    ) -> list[UsbThreatFinding]:
        """Scan a collection of files discovered on a removable drive."""
        all_findings: list[UsbThreatFinding] = []
        for r in records:
            all_findings.extend(self.scan_file(r, device_id=device_id))
        return all_findings

