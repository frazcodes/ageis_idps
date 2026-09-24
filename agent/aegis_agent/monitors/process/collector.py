"""Read-only process metadata collection via psutil.

Failure handling policy
-----------------------
* ``NoSuchProcess`` / ``ZombieProcess``: the process vanished or is a zombie, so
  it cannot be described reliably. The record is skipped.
* ``AccessDenied`` / ``OSError``: the process exists but a field is unreadable
  (common for other users' processes). The field degrades to ``None`` and the
  process is still reported.
* Any other exception is **not** caught here: unexpected programming errors must
  surface rather than be silently swallowed.

Nothing in this module executes, signals, suspends or modifies a process, and no
environment or memory data is read.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any, TypeVar

import psutil

from aegis_agent.monitors.process.commandline import sanitize_command_line
from aegis_agent.monitors.process.models import ProcessRecord, ProcessSnapshot
from aegis_shared.logging import get_logger

logger = get_logger(__name__)

T = TypeVar("T")

#: Exceptions that mean "this process cannot be described at all" -> skip it.
_SKIP_EXCEPTIONS: tuple[type[BaseException], ...] = (
    psutil.NoSuchProcess,
    psutil.ZombieProcess,
)

#: Exceptions that mean "this field is unreadable" -> use ``None``.
_FIELD_EXCEPTIONS: tuple[type[BaseException], ...] = (psutil.AccessDenied, OSError)

#: Exceptions tolerated while resolving the optional parent process.
_PARENT_EXCEPTIONS: tuple[type[BaseException], ...] = (
    psutil.NoSuchProcess,
    psutil.ZombieProcess,
    psutil.AccessDenied,
    OSError,
)


class ProcessCollector:
    """Enumerate running processes and build safe :class:`ProcessRecord` objects."""

    def collect(self) -> ProcessSnapshot:
        """Return a snapshot of all currently visible processes.

        The snapshot is ordered by PID so output is deterministic.
        """
        records = [
            record
            for proc in self._iter_processes()
            if (record := self._collect_record(proc)) is not None
        ]
        records.sort(key=lambda item: (item.pid, item.create_time or _MIN_UTC))
        return ProcessSnapshot(processes=tuple(records))

    def _iter_processes(self) -> Iterable[Any]:
        """Yield psutil process handles.

        ``psutil.process_iter`` already tolerates processes disappearing while it
        is being iterated; genuine errors are allowed to propagate.
        """
        return psutil.process_iter()

    def _collect_record(self, proc: Any) -> ProcessRecord | None:
        try:
            return ProcessRecord(
                pid=int(proc.pid),
                ppid=self._field(proc.ppid),
                name=self._clean_text(self._field(proc.name)),
                parent_name=self._clean_text(self._parent_name(proc)),
                executable_path=self._clean_text(self._field(proc.exe)),
                username=self._clean_text(self._field(proc.username)),
                command_line=sanitize_command_line(self._command_line(proc)),
                create_time=self._create_time(proc),
            )
        except _SKIP_EXCEPTIONS:
            logger.debug("Skipping process that disappeared or is a zombie")
            return None

    def _field(self, getter: Callable[[], T]) -> T | None:
        """Call a psutil getter, returning ``None`` when access is denied."""
        try:
            return getter()
        except _FIELD_EXCEPTIONS:
            return None

    @staticmethod
    def _clean_text(value: str | None) -> str | None:
        """Treat blank strings (psutil sometimes returns ``""``) as unavailable."""
        if value is None:
            return None
        text = value.strip()
        return text or None

    def _create_time(self, proc: Any) -> datetime | None:
        raw = self._field(proc.create_time)
        if raw is None:
            return None
        try:
            return datetime.fromtimestamp(float(raw), tz=UTC)
        except (TypeError, ValueError, OSError, OverflowError):
            return None

    def _command_line(self, proc: Any) -> str | None:
        parts = self._field(proc.cmdline)
        if not parts:
            return None
        return " ".join(str(part) for part in parts)

    def _parent_name(self, proc: Any) -> str | None:
        """Best-effort parent process name; never fails the whole record."""
        try:
            parent = proc.parent()
        except _PARENT_EXCEPTIONS:
            return None
        if parent is None:
            return None
        return self._field(parent.name)


#: Sort fallback for records without a creation time.
_MIN_UTC = datetime.min.replace(tzinfo=UTC)


def collect_process_snapshot() -> ProcessSnapshot:
    """Convenience wrapper for a single read-only process snapshot."""
    return ProcessCollector().collect()


__all__ = ["ProcessCollector", "collect_process_snapshot"]
