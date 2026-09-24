"""Map process changes onto the canonical :class:`aegis_shared.events.SecurityEvent`.

Event generation is kept separate from collection and snapshot diffing so that
the monitor stays free of transport concerns and the mapping is easy to test.
The shared schema already models everything needed:

* ``EventType.PROCESS_STARTED`` / ``EventType.PROCESS_STOPPED`` (category ``host``)
* :class:`~aegis_shared.events.ProcessContext` for process metadata
* :class:`~aegis_shared.events.ActorRef` for the owning user

No new event types or fields were required.
"""

from __future__ import annotations

from datetime import datetime

from aegis_agent.monitors.process.models import ProcessChanges, ProcessRecord
from aegis_shared.enums import EventType, Severity
from aegis_shared.events import ActorRef, HostRef, ProcessContext, SecurityEvent, SourceRef


def build_process_event(
    record: ProcessRecord,
    *,
    event_type: EventType,
    source: SourceRef,
    host: HostRef,
    timestamp: datetime | None = None,
    severity: Severity = Severity.INFO,
) -> SecurityEvent:
    """Build a ``SecurityEvent`` for a single process start or stop.

    Args:
        record: The process the event is about.
        event_type: ``PROCESS_STARTED`` or ``PROCESS_STOPPED``.
        source: The emitting agent (``SourceKind.AGENT``).
        host: Host context, typically from ``SystemInventory.to_host_ref()``.
        timestamp: Observation time; defaults to now (UTC) when omitted.
        severity: Defaults to ``INFO`` - detection decides severity later.
    """
    verb = "started" if event_type is EventType.PROCESS_STARTED else "stopped"
    label = record.name or f"pid {record.pid}"

    kwargs: dict[str, object] = {
        "event_type": event_type,
        "severity": severity,
        "source": source,
        "host": host,
        "actor": ActorRef(user=record.username) if record.username else None,
        "process": ProcessContext(
            pid=record.pid,
            ppid=record.ppid,
            name=record.name,
            executable_path=record.executable_path,
            command_line=record.command_line,
        ),
        "message": f"Process {verb}: {label}",
    }
    if timestamp is not None:
        kwargs["timestamp"] = timestamp

    return SecurityEvent.create(**kwargs)  # type: ignore[arg-type]


def changes_to_events(
    changes: ProcessChanges,
    *,
    source: SourceRef,
    host: HostRef,
    timestamp: datetime | None = None,
) -> tuple[SecurityEvent, ...]:
    """Convert a :class:`ProcessChanges` diff into security events.

    Starts are emitted before stops for a stable, predictable ordering.
    """
    observed_at = timestamp or changes.captured_at
    events = [
        build_process_event(
            record,
            event_type=EventType.PROCESS_STARTED,
            source=source,
            host=host,
            timestamp=observed_at,
        )
        for record in changes.started
    ]
    events.extend(
        build_process_event(
            record,
            event_type=EventType.PROCESS_STOPPED,
            source=source,
            host=host,
            timestamp=observed_at,
        )
        for record in changes.stopped
    )
    return tuple(events)


__all__ = ["build_process_event", "changes_to_events"]
