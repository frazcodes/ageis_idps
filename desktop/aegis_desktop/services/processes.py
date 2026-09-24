"""Processes adapter: existing Step 3 process models -> UI-friendly data.

This layer is strictly read-only. It calls the existing
:func:`aegis_agent.monitors.process.collect_process_snapshot` once per refresh and
translates :class:`ProcessRecord` objects into flat :class:`ProcessRow` values for
the Qt table model. It never starts the :class:`ProcessMonitor` lifecycle, never
polls continuously, and never modifies a process.

The collector is imported lazily so simply opening the application (or any other
page) does not load psutil or the process monitor.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from aegis_shared.logging import get_logger

if TYPE_CHECKING:  # pragma: no cover - typing only
    from aegis_agent.monitors.process import ProcessRecord, ProcessSnapshot

logger = get_logger(__name__)

#: Non-sensitive message shown when process collection fails.
PROCESS_ERROR = "Unable to collect process information"
#: Placeholder for a value the collector could not read (e.g. access denied).
MISSING = "—"


@dataclass(frozen=True)
class ProcessRow:
    """One process, flattened for display and sorting."""

    pid: int | None
    name: str | None
    executable: str | None
    username: str | None
    ppid: int | None
    parent_name: str | None
    create_time: datetime | None
    identity: str | None
    #: Whether a (sanitized) command line was available. The command line itself is
    #: treated as sensitive and is never shown.
    command_line_available: bool


@dataclass(frozen=True)
class ProcessSnapshotView:
    """Read-only view of one process snapshot."""

    available: bool
    error: str | None
    collected_at: datetime | None
    rows: tuple[ProcessRow, ...]

    @property
    def count(self) -> int:
        """Number of processes in the snapshot."""
        return len(self.rows)


def _default_collector() -> ProcessSnapshot:
    # Imported lazily: opening the application must not load the process monitor.
    from aegis_agent.monitors.process import collect_process_snapshot

    return collect_process_snapshot()


def _to_row(record: ProcessRecord) -> ProcessRow:
    return ProcessRow(
        pid=record.pid,
        name=record.name,
        executable=record.executable_path,
        username=record.username,
        ppid=record.ppid,
        parent_name=record.parent_name,
        create_time=record.create_time,
        identity=record.identity.key,
        command_line_available=record.command_line is not None,
    )


def collect_process_view(
    *,
    collector: Callable[[], ProcessSnapshot] | None = None,
) -> ProcessSnapshotView:
    """Collect one process snapshot and translate it for the UI.

    Args:
        collector: Overrides the existing collector (tests inject one). The
            default is a one-shot call to the Step 3 collector; the
            :class:`ProcessMonitor` lifecycle is never started.

    Returns:
        A :class:`ProcessSnapshotView`; on failure ``available`` is ``False`` and
        a safe, non-sensitive ``error`` message is provided.
    """
    collect = collector or _default_collector
    try:
        snapshot = collect()
    except Exception as exc:
        # Never surface stack traces or sensitive details in the UI.
        logger.warning("Process collection failed: %s", exc)
        return ProcessSnapshotView(
            available=False,
            error=PROCESS_ERROR,
            collected_at=None,
            rows=(),
        )

    return ProcessSnapshotView(
        available=True,
        error=None,
        collected_at=snapshot.captured_at,
        rows=tuple(_to_row(record) for record in snapshot.processes),
    )


__all__ = [
    "MISSING",
    "PROCESS_ERROR",
    "ProcessRow",
    "ProcessSnapshotView",
    "collect_process_view",
]
