"""Adapters from monitor change sets to pipeline-ready canonical events.

The monitors stay independently usable; this module is the single place the
pipeline knows about them. It simply forwards each monitor's existing
``changes_to_events`` mapping, so no monitor code is rewritten and no event
schema is duplicated.
"""

from __future__ import annotations

from datetime import datetime

from aegis_agent.monitors.file_integrity.events import (
    changes_to_events as file_changes_to_events,
)
from aegis_agent.monitors.file_integrity.models import FileChanges
from aegis_agent.monitors.port.events import changes_to_events as port_changes_to_events
from aegis_agent.monitors.port.models import PortChanges
from aegis_agent.monitors.process.events import changes_to_events as process_changes_to_events
from aegis_agent.monitors.process.models import ProcessChanges
from aegis_shared.events import HostRef, SecurityEvent, SourceRef


def collect_process_events(
    changes: ProcessChanges,
    *,
    source: SourceRef,
    host: HostRef,
    timestamp: datetime | None = None,
) -> tuple[SecurityEvent, ...]:
    """Map process changes to canonical events."""
    return process_changes_to_events(changes, source=source, host=host, timestamp=timestamp)


def collect_port_events(
    changes: PortChanges,
    *,
    source: SourceRef,
    host: HostRef,
    timestamp: datetime | None = None,
) -> tuple[SecurityEvent, ...]:
    """Map port changes to canonical events."""
    return port_changes_to_events(changes, source=source, host=host, timestamp=timestamp)


def collect_file_events(
    changes: FileChanges,
    *,
    source: SourceRef,
    host: HostRef,
    timestamp: datetime | None = None,
) -> tuple[SecurityEvent, ...]:
    """Map file-integrity changes to canonical events."""
    return file_changes_to_events(changes, source=source, host=host, timestamp=timestamp)


def collect_monitor_events(
    *,
    source: SourceRef,
    host: HostRef,
    timestamp: datetime | None = None,
    process_changes: ProcessChanges | None = None,
    port_changes: PortChanges | None = None,
    file_changes: FileChanges | None = None,
) -> tuple[SecurityEvent, ...]:
    """Combine any provided monitor change sets into one ordered event stream.

    Ordering is deterministic: process, then port, then file-integrity.
    """
    events: list[SecurityEvent] = []
    if process_changes is not None:
        events.extend(
            collect_process_events(process_changes, source=source, host=host, timestamp=timestamp)
        )
    if port_changes is not None:
        events.extend(
            collect_port_events(port_changes, source=source, host=host, timestamp=timestamp)
        )
    if file_changes is not None:
        events.extend(
            collect_file_events(file_changes, source=source, host=host, timestamp=timestamp)
        )
    return tuple(events)


__all__ = [
    "collect_file_events",
    "collect_monitor_events",
    "collect_port_events",
    "collect_process_events",
]
