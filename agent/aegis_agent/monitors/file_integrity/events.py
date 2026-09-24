"""Map file-integrity changes onto the canonical ``SecurityEvent``.

The shared schema already provided the event types
(``FILE_CREATED`` / ``FILE_MODIFIED`` / ``FILE_DELETED``) and now carries an
extended :class:`~aegis_shared.events.FileContext` (type, size, mtime, SHA-256
and hash status). No second event format is introduced.
"""

from __future__ import annotations

from datetime import datetime

from aegis_agent.monitors.file_integrity.models import FileChanges, FileRecord
from aegis_shared.enums import EventType, Severity
from aegis_shared.events import FileContext, HostRef, SecurityEvent, SourceRef

_OPERATION_BY_EVENT: dict[EventType, str] = {
    EventType.FILE_CREATED: "created",
    EventType.FILE_MODIFIED: "modified",
    EventType.FILE_DELETED: "deleted",
}


def build_file_event(
    record: FileRecord,
    *,
    event_type: EventType,
    source: SourceRef,
    host: HostRef,
    timestamp: datetime | None = None,
    severity: Severity = Severity.INFO,
) -> SecurityEvent:
    """Build a ``SecurityEvent`` for a single file change.

    Args:
        record: The file the event is about (current state for create/modify,
            last-known state for delete).
        event_type: ``FILE_CREATED``, ``FILE_MODIFIED`` or ``FILE_DELETED``.
        source: The emitting agent (``SourceKind.AGENT``).
        host: Host context, typically from ``SystemInventory.to_host_ref()``.
        timestamp: Observation time; defaults to now (UTC) when omitted.
        severity: Defaults to ``INFO`` - detection decides severity later.
    """
    operation = _OPERATION_BY_EVENT[event_type]

    kwargs: dict[str, object] = {
        "event_type": event_type,
        "severity": severity,
        "source": source,
        "host": host,
        "file": FileContext(
            path=record.path,
            operation=operation,
            file_type=record.file_type,
            size_bytes=record.size_bytes,
            modified_at=record.modified_at,
            hashes={"sha256": record.sha256} if record.sha256 else {},
            hash_status=record.hash_status,
        ),
        "message": f"File {operation}: {record.path}",
    }
    if timestamp is not None:
        kwargs["timestamp"] = timestamp

    return SecurityEvent.create(**kwargs)  # type: ignore[arg-type]


def changes_to_events(
    changes: FileChanges,
    *,
    source: SourceRef,
    host: HostRef,
    timestamp: datetime | None = None,
) -> tuple[SecurityEvent, ...]:
    """Convert a :class:`FileChanges` diff into security events.

    Ordered created, then modified, then deleted for predictability.
    """
    observed_at = timestamp or changes.captured_at
    events = [
        build_file_event(
            record,
            event_type=EventType.FILE_CREATED,
            source=source,
            host=host,
            timestamp=observed_at,
        )
        for record in changes.created
    ]
    events.extend(
        build_file_event(
            modification.current,
            event_type=EventType.FILE_MODIFIED,
            source=source,
            host=host,
            timestamp=observed_at,
        )
        for modification in changes.modified
    )
    events.extend(
        build_file_event(
            record,
            event_type=EventType.FILE_DELETED,
            source=source,
            host=host,
            timestamp=observed_at,
        )
        for record in changes.deleted
    )
    return tuple(events)


__all__ = ["build_file_event", "changes_to_events"]
