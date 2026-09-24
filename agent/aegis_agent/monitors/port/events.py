"""Map port changes onto the canonical :class:`aegis_shared.events.SecurityEvent`.

The shared schema already provided the event types
(``EventType.PORT_LISTENING`` / ``EventType.PORT_CLOSED``) and now carries a
:class:`~aegis_shared.events.SocketContext` block for the local endpoint plus a
:class:`~aegis_shared.events.ProcessContext` block for the owner. No second event
format is introduced.
"""

from __future__ import annotations

from datetime import datetime

from aegis_agent.monitors.port.models import PortChanges, PortRecord
from aegis_shared.enums import EventType, Severity
from aegis_shared.events import HostRef, ProcessContext, SecurityEvent, SocketContext, SourceRef


def build_port_event(
    record: PortRecord,
    *,
    event_type: EventType,
    source: SourceRef,
    host: HostRef,
    timestamp: datetime | None = None,
    severity: Severity = Severity.INFO,
) -> SecurityEvent:
    """Build a ``SecurityEvent`` for a single port opening or closing.

    Args:
        record: The listening endpoint the event is about.
        event_type: ``PORT_LISTENING`` or ``PORT_CLOSED``.
        source: The emitting agent (``SourceKind.AGENT``).
        host: Host context, typically from ``SystemInventory.to_host_ref()``.
        timestamp: Observation time; defaults to now (UTC) when omitted.
        severity: Defaults to ``INFO`` - detection decides severity later.
    """
    verb = "listening" if event_type is EventType.PORT_LISTENING else "closed"
    owner = f" (pid {record.pid})" if record.pid is not None else ""

    kwargs: dict[str, object] = {
        "event_type": event_type,
        "severity": severity,
        "source": source,
        "host": host,
        "socket": SocketContext(
            local_address=record.local_address,
            local_port=record.local_port,
            address_family=record.address_family,
            protocol=record.protocol,
            status=record.status,
        ),
        "process": (
            ProcessContext(pid=record.pid, name=record.process_name)
            if record.pid is not None
            else None
        ),
        "message": f"Port {verb}: {record.protocol.value}/{record.endpoint}{owner}",
    }
    if timestamp is not None:
        kwargs["timestamp"] = timestamp

    return SecurityEvent.create(**kwargs)  # type: ignore[arg-type]


def changes_to_events(
    changes: PortChanges,
    *,
    source: SourceRef,
    host: HostRef,
    timestamp: datetime | None = None,
) -> tuple[SecurityEvent, ...]:
    """Convert a :class:`PortChanges` diff into security events.

    Opened ports are emitted before closed ports for a stable ordering.
    """
    observed_at = timestamp or changes.captured_at
    events = [
        build_port_event(
            record,
            event_type=EventType.PORT_LISTENING,
            source=source,
            host=host,
            timestamp=observed_at,
        )
        for record in changes.started
    ]
    events.extend(
        build_port_event(
            record,
            event_type=EventType.PORT_CLOSED,
            source=source,
            host=host,
            timestamp=observed_at,
        )
        for record in changes.stopped
    )
    return tuple(events)


__all__ = ["build_port_event", "changes_to_events"]
