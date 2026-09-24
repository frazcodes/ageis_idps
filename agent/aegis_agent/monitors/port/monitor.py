"""Snapshot-diffing listening-port monitor.

Mirrors :class:`aegis_agent.monitors.process.monitor.ProcessMonitor`: the caller
drives the lifecycle and the monitor is daemon-free::

    monitor = PortMonitor()
    monitor.start()            # establish baseline
    changes = monitor.poll()   # detect ports opened/closed since the baseline
    monitor.stop()             # drop the baseline

Comparison is keyed on :attr:`PortIdentity.key`, which includes the owning
process identity. A port whose ownership changes is therefore reported as the
old endpoint stopping and the new one starting, never as unchanged.
"""

from __future__ import annotations

from aegis_agent.monitors.port.collector import PortCollector
from aegis_agent.monitors.port.models import PortChanges, PortSnapshot


class PortMonitor:
    """Detect listening ports opening and closing by diffing successive snapshots."""

    def __init__(self, *, collector: PortCollector | None = None) -> None:
        self._collector = collector or PortCollector()
        self._baseline: PortSnapshot | None = None

    @property
    def has_baseline(self) -> bool:
        """Whether :meth:`start` has established a baseline."""
        return self._baseline is not None

    def start(self) -> PortSnapshot:
        """Establish the baseline snapshot and return it."""
        self._baseline = self._collector.collect()
        return self._baseline

    def snapshot(self) -> PortSnapshot:
        """Collect a fresh snapshot without touching the baseline."""
        return self._collector.collect()

    def poll(self) -> PortChanges:
        """Diff the current snapshot against the baseline.

        The baseline is advanced to the current snapshot so each change is
        reported exactly once. Without a prior :meth:`start`, every visible
        listening endpoint is reported as started.
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
        return PortChanges(captured_at=current.captured_at, started=started, stopped=stopped)

    def stop(self) -> None:
        """Drop the baseline. Safe to call more than once."""
        self._baseline = None


__all__ = ["PortMonitor"]
