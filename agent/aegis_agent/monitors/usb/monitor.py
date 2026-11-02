"""Snapshot-diffing USB device and removable storage monitor.

Lifecycle mirrors the Aegis process and file integrity monitors:
- ``start()``: establishes initial baseline of connected USB devices and files.
- ``snapshot()``: inspects current state without mutating the baseline.
- ``poll()``: calculates diffs (connected/disconnected devices, created/modified/deleted files),
  invokes threat detection on active files, updates baseline, and returns ``UsbChanges``.
"""

from __future__ import annotations

from datetime import UTC, datetime

from aegis_agent.monitors.usb.collector import UsbCollector
from aegis_agent.monitors.usb.detector import UsbThreatDetector
from aegis_agent.monitors.usb.models import (
    UsbChanges,
    UsbDevice,
    UsbFileAction,
    UsbFileEvent,
    UsbFileRecord,
    UsbSnapshot,
    UsbThreatFinding,
)
from aegis_shared.logging import get_logger

logger = get_logger(__name__)


class UsbMonitor:
    """Detects USB insertions, removals, removable file changes, and weaponised USB threats."""

    def __init__(
        self,
        *,
        collector: UsbCollector | None = None,
        detector: UsbThreatDetector | None = None,
    ) -> None:
        self._collector = collector or UsbCollector()
        self._detector = detector or UsbThreatDetector()
        self._baseline: UsbSnapshot | None = None

    @property
    def has_baseline(self) -> bool:
        """Whether a baseline snapshot has been established."""
        return self._baseline is not None

    def start(self) -> UsbSnapshot:
        """Establish baseline USB device and filesystem state."""
        self._baseline = self._collector.collect()
        return self._baseline

    def stop(self) -> None:
        """Drop the baseline snapshot."""
        self._baseline = None

    def snapshot(self) -> UsbSnapshot:
        """Collect current USB status without modifying the baseline."""
        return self._collector.collect()

    def poll(self) -> UsbChanges:
        """Compare the current USB state against the baseline snapshot.

        Advances the baseline to the current snapshot so each device plug/unplug
        and file mutation is emitted once. If poll() is invoked without prior start(),
        all currently visible devices are reported as newly connected.
        """
        now = datetime.now(UTC)
        current = self._collector.collect()
        previous = self._baseline

        if previous is None:
            # First poll without start: report all visible devices as connected
            self._baseline = current
            # Check devices and existing files for threats on initial run
            findings: list[UsbThreatFinding] = []
            file_events: list[UsbFileEvent] = []

            for dev in current.devices:
                findings.extend(self._detector.scan_device(dev))

            for record in current.files:
                file_threats = self._detector.scan_file(record)
                is_suspicious = len(file_threats) > 0
                cat = file_threats[0].category if is_suspicious else None
                desc = file_threats[0].description if is_suspicious else None

                findings.extend(file_threats)
                file_events.append(
                    UsbFileEvent(
                        path=record.path,
                        drive_letter=record.drive_letter,
                        action=UsbFileAction.CREATED,
                        size_bytes=record.size_bytes,
                        modified_at=record.modified_at,
                        sha256=record.sha256,
                        is_suspicious=is_suspicious,
                        threat_category=cat,
                        threat_description=desc,
                    )
                )

            return UsbChanges(
                connected_devices=current.devices,
                disconnected_devices=(),
                file_events=tuple(file_events),
                threat_findings=tuple(findings),
                timestamp=now,
            )

        # 1. Device diffing
        prev_devs = previous.device_map()
        curr_devs = current.device_map()

        connected = [
            dev for key, dev in curr_devs.items() if key not in prev_devs
        ]
        disconnected = [
            dev.model_copy(update={"is_connected": False, "disconnected_at": now})
            for key, dev in prev_devs.items()
            if key not in curr_devs
        ]

        # 2. File diffing on removable drives
        prev_files = previous.file_map()
        curr_files = current.file_map()

        file_events: list[UsbFileEvent] = []
        threat_findings: list[UsbThreatFinding] = []

        # Scan newly connected devices for hardware attacks (e.g. BadUSB)
        for dev in connected:
            threat_findings.extend(self._detector.scan_device(dev))

        # Created files
        for key, record in curr_files.items():
            if key not in prev_files:
                threats = self._detector.scan_file(record)
                threat_findings.extend(threats)

                file_events.append(
                    UsbFileEvent(
                        path=record.path,
                        drive_letter=record.drive_letter,
                        action=UsbFileAction.CREATED,
                        size_bytes=record.size_bytes,
                        modified_at=record.modified_at,
                        sha256=record.sha256,
                        is_suspicious=bool(threats),
                        threat_category=threats[0].category if threats else None,
                        threat_description=threats[0].description if threats else None,
                    )
                )
            else:
                # Existing file: check if modified
                prev_record = prev_files[key]
                if (
                    record.size_bytes != prev_record.size_bytes
                    or record.modified_at != prev_record.modified_at
                    or (record.sha256 and record.sha256 != prev_record.sha256)
                ):
                    threats = self._detector.scan_file(record)
                    threat_findings.extend(threats)

                    file_events.append(
                        UsbFileEvent(
                            path=record.path,
                            drive_letter=record.drive_letter,
                            action=UsbFileAction.MODIFIED,
                            size_bytes=record.size_bytes,
                            modified_at=record.modified_at,
                            sha256=record.sha256,
                            is_suspicious=bool(threats),
                            threat_category=threats[0].category if threats else None,
                            threat_description=threats[0].description if threats else None,
                        )
                    )

        # Deleted files
        for key, record in prev_files.items():
            if key not in curr_files:
                file_events.append(
                    UsbFileEvent(
                        path=record.path,
                        drive_letter=record.drive_letter,
                        action=UsbFileAction.DELETED,
                        size_bytes=record.size_bytes,
                        modified_at=record.modified_at,
                        sha256=record.sha256,
                        is_suspicious=False,
                    )
                )

        # Advance baseline
        self._baseline = current

        return UsbChanges(
            connected_devices=tuple(connected),
            disconnected_devices=tuple(disconnected),
            file_events=tuple(file_events),
            threat_findings=tuple(threat_findings),
            timestamp=now,
        )

