"""Read-only process monitoring.

Public API
----------
* :func:`collect_process_snapshot` / :class:`ProcessCollector` - enumerate processes.
* :class:`ProcessRecord` / :class:`ProcessSnapshot` / :class:`ProcessChanges` - models.
* :class:`ProcessMonitor` - snapshot diffing (``start``/``snapshot``/``poll``/``stop``).
* :func:`changes_to_events` - map changes onto ``aegis_shared`` ``SecurityEvent``.
* :func:`sanitize_command_line` - best-effort command-line secret redaction.

The monitor is read-only: it never starts, stops, signals or inspects the memory
of any process, and it reads no environment variables.
"""

from __future__ import annotations

from aegis_agent.monitors.process.collector import ProcessCollector, collect_process_snapshot
from aegis_agent.monitors.process.commandline import sanitize_command_line
from aegis_agent.monitors.process.events import build_process_event, changes_to_events
from aegis_agent.monitors.process.models import (
    ProcessChanges,
    ProcessIdentity,
    ProcessRecord,
    ProcessSnapshot,
)
from aegis_agent.monitors.process.monitor import ProcessMonitor

__all__ = [
    "ProcessChanges",
    "ProcessCollector",
    "ProcessIdentity",
    "ProcessMonitor",
    "ProcessRecord",
    "ProcessSnapshot",
    "build_process_event",
    "changes_to_events",
    "collect_process_snapshot",
    "sanitize_command_line",
]
