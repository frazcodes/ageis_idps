"""Snapshot-diffing process monitor.

The monitor compares the current process set against a baseline and reports
:class:`ProcessChanges`. It is deliberately single-threaded and daemon-free: a
caller (a test, the CLI, or a future scheduler) drives the lifecycle::

    monitor = ProcessMonitor()
    monitor.start()            # establish baseline
    changes = monitor.poll()   # detect starts/exits since the baseline
    monitor.stop()             # drop the baseline

Comparison is keyed on :attr:`ProcessIdentity.key` (PID + creation time), so a
reused PID is correctly reported as one process stopping and another starting.
"""

from __future__ import annotations

from aegis_agent.monitors.process.collector import ProcessCollector
from aegis_agent.monitors.process.models import ProcessChanges, ProcessSnapshot


class ProcessMonitor:
    """Detect process starts and exits by diffing successive snapshots."""

    def __init__(self, *, collector: ProcessCollector | None = None) -> None:
        self._collector = collector or ProcessCollector()
        self._baseline: ProcessSnapshot | None = None

    @property
    def has_baseline(self) -> bool:
        """Whether :meth:`start` has established a baseline."""
        return self._baseline is not None

    def start(self) -> ProcessSnapshot:
        """Establish the baseline snapshot and return it."""
        self._baseline = self._collector.collect()
        return self._baseline

    def snapshot(self) -> ProcessSnapshot:
        """Collect a fresh snapshot without touching the baseline."""
        return self._collector.collect()

    def poll(self) -> ProcessChanges:
        """Diff the current snapshot against the baseline.

        The baseline is advanced to the current snapshot, so each change is
        reported exactly once. Without a prior :meth:`start`, every visible
        process is reported as started.
        """
        current = self._collector.collect()
        previous = self._baseline
        previous_by_key = previous.by_identity() if previous is not None else {}
        current_by_key = current.by_identity()

        started = tuple(
            record for key, record in current_by_key.items() if key not in previous_by_key
        )
        stopped = tuple(
            record for key, record in previous_by_key.items() if key not in current_by_key
        )

        self._baseline = current
        return ProcessChanges(captured_at=current.captured_at, started=started, stopped=stopped)

    def stop(self) -> None:
        """Drop the baseline. Safe to call more than once."""
        self._baseline = None


__all__ = ["ProcessMonitor"]
