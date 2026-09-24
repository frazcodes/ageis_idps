"""Snapshot-diffing file-integrity monitor.

Mirrors the process and port monitors: the caller drives the lifecycle and the
monitor is daemon-free::

    monitor = FileIntegrityMonitor(collector=FileCollector(paths=[...]))
    monitor.start()            # establish baseline
    changes = monitor.poll()   # detect created/modified/deleted since baseline
    monitor.stop()             # drop the baseline

Diffing pairs records by :attr:`FileIdentity.key` (normalized path). A record
present in both snapshots is a *modification* when its change signature differs;
this is why a file whose content changed is not misreported as delete + create.

Rename detection is intentionally **not** implemented: filesystems do not expose
a reliable rename signal through polling, and faking it from path/hash heuristics
would produce false "renamed" events. A rename is therefore reported as a delete
plus a create, which is honest.
"""

from __future__ import annotations

from aegis_agent.monitors.file_integrity.collector import FileCollector
from aegis_agent.monitors.file_integrity.models import (
    FileChanges,
    FileModification,
    FileSnapshot,
)


class FileIntegrityMonitor:
    """Detect file creations, modifications and deletions by diffing snapshots."""

    def __init__(self, *, collector: FileCollector) -> None:
        self._collector = collector
        self._baseline: FileSnapshot | None = None

    @property
    def has_baseline(self) -> bool:
        """Whether :meth:`start` has established a baseline."""
        return self._baseline is not None

    def start(self) -> FileSnapshot:
        """Establish the baseline snapshot and return it."""
        self._baseline = self._collector.collect()
        return self._baseline

    def snapshot(self) -> FileSnapshot:
        """Collect a fresh snapshot without touching the baseline."""
        return self._collector.collect()

    def poll(self) -> FileChanges:
        """Diff the current snapshot against the baseline.

        The baseline is advanced to the current snapshot so each change is
        reported exactly once. Without a prior :meth:`start`, every visible
        object is reported as created.
        """
        current = self._collector.collect()
        previous = self._baseline
        previous_by_path = previous.by_path() if previous is not None else {}
        current_by_path = current.by_path()

        created = tuple(
            record for key, record in current_by_path.items() if key not in previous_by_path
        )
        deleted = tuple(
            record for key, record in previous_by_path.items() if key not in current_by_path
        )
        modified = tuple(
            FileModification(previous=previous_by_path[key], current=current_by_path[key])
            for key in current_by_path.keys() & previous_by_path.keys()
            if current_by_path[key].differs_from(previous_by_path[key])
        )

        self._baseline = current
        return FileChanges(
            captured_at=current.captured_at,
            created=created,
            modified=modified,
            deleted=deleted,
        )

    def stop(self) -> None:
        """Drop the baseline. Safe to call more than once."""
        self._baseline = None


__all__ = ["FileIntegrityMonitor"]
