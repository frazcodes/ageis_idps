"""Events adapter: existing SecurityEvent pipeline -> UI-friendly data.

Strictly read-only inspection of events **already** buffered in the existing
:class:`~aegis_shared.pipeline.EventPipeline`. It reads the pipeline's own
``peek()`` snapshot and ``stats``/``dedup_window`` posture; it never submits an
event, never drains or clears the buffer, never starts a monitor and never
transmits anything.

It does not create a second event store: the pipeline remains the single source
of truth. No synthetic events are produced to populate the page.

Context summaries are built from the actual event contexts and command-line data
is re-sanitized at the presentation layer; raw secrets are never surfaced.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from aegis_desktop.services.processes import MISSING
from aegis_shared.logging import get_logger, redact
from aegis_shared.pipeline import EventPipeline

if TYPE_CHECKING:  # pragma: no cover - typing only
    from aegis_shared.events import SecurityEvent

logger = get_logger(__name__)


def _sanitize_command_line(command_line: str) -> str | None:
    """Re-sanitize a command line at presentation time.

    Imported lazily so that merely importing the desktop application does not
    load ``aegis_agent.monitors`` (startup-safety requirement). The sanitizer
    itself lives in the existing Step 3 implementation.
    """
    from aegis_agent.monitors.process.commandline import sanitize_command_line

    return sanitize_command_line(command_line)


#: Non-sensitive message shown when the event buffer cannot be read.
EVENT_ERROR = "Unable to read security events"


@dataclass(frozen=True)
class EventRow:
    """One buffered event, flattened for display and sorting."""

    sequence: int
    timestamp: datetime
    event_id: str
    event_type: str
    category: str
    severity: str
    host_id: str | None
    source: str
    summary: str


@dataclass(frozen=True)
class PipelinePosture:
    """Read-only view of the existing pipeline's configuration/state."""

    running: bool
    buffered: int
    capacity: int
    dedup_window: int
    accepted: int
    rejected: int
    dropped: int
    duplicates: int


@dataclass(frozen=True)
class EventSnapshotView:
    """Read-only view of the buffered events plus pipeline posture.

    ``events`` holds the underlying canonical ``SecurityEvent`` objects so the
    detail panel can render structured fields without re-querying the pipeline.
    They are read-only references; the view never mutates them.
    """

    available: bool
    error: str | None
    collected_at: datetime | None
    posture: PipelinePosture
    rows: tuple[EventRow, ...]
    events: tuple[SecurityEvent, ...] = ()

    @property
    def count(self) -> int:
        """Number of buffered events in the view."""
        return len(self.rows)

    def event_by_id(self, event_id: str) -> SecurityEvent | None:
        """Return the buffered event with ``event_id``, if present."""
        for event in self.events:
            if event.event_id == event_id:
                return event
        return None


def _default_pipeline() -> EventPipeline | None:
    """Return the process-wide pipeline if one is running, else ``None``.

    No pipeline runtime is instantiated yet (that is a later architectural step),
    so this returns ``None`` unless an embedder has published one.
    """
    from aegis_shared.pipeline import runtime

    return runtime.get_active_pipeline()


def _source_summary(event: SecurityEvent) -> str:
    version = event.source.version
    base = f"{event.source.kind.value}:{event.source.id}"
    return f"{base} v{version}" if version else base


def _context_summary(event: SecurityEvent) -> str:
    """Build a concise, safe summary from whichever context the event carries."""
    if event.process is not None:
        process = event.process
        name = process.name or "process"
        if process.pid is not None:
            summary = f"Process: {name} (PID {process.pid})"
        else:
            summary = f"Process: {name}"
        if process.command_line:
            # Re-sanitize at presentation time; never surface a raw command line.
            sanitized = _sanitize_command_line(process.command_line)
            if sanitized:
                summary = f"{summary} - {sanitized}"
        return summary

    if event.socket is not None:
        socket = event.socket
        protocol = socket.protocol.value.upper()
        if socket.local_address and socket.local_port is not None:
            address = (
                f"[{socket.local_address}]"
                if socket.address_family.value == "ipv6"
                else socket.local_address
            )
            return f"Socket: {protocol} {address}:{socket.local_port}"
        if socket.local_port is not None:
            return f"Socket: {protocol} port {socket.local_port}"
        return f"Socket: {protocol}"

    if event.file is not None:
        file = event.file
        operation = f" ({file.operation})" if file.operation else ""
        return f"File{operation}: {file.path}"

    if event.network is not None:
        network = event.network
        source = network.src_ip or "?"
        destination = network.dst_ip or "?"
        if network.dst_port is not None:
            destination = f"{destination}:{network.dst_port}"
        return f"Network: {network.protocol.value.upper()} {source} -> {destination}"

    if event.message:
        return event.message
    return MISSING


def _to_row(sequence: int, event: SecurityEvent) -> EventRow:
    return EventRow(
        sequence=sequence,
        timestamp=event.timestamp,
        event_id=event.event_id,
        event_type=event.event_type.value,
        category=event.category.value,
        severity=event.severity.value,
        host_id=event.host.host_id if event.host is not None else None,
        source=_source_summary(event),
        summary=_context_summary(event),
    )


def _posture(pipeline: EventPipeline | None) -> PipelinePosture:
    if pipeline is None:
        return PipelinePosture(
            running=False,
            buffered=0,
            capacity=0,
            dedup_window=0,
            accepted=0,
            rejected=0,
            dropped=0,
            duplicates=0,
        )
    stats = pipeline.stats
    return PipelinePosture(
        running=True,
        buffered=stats.buffered,
        capacity=stats.capacity,
        dedup_window=pipeline.dedup_window,
        accepted=stats.accepted,
        rejected=stats.rejected,
        dropped=stats.dropped,
        duplicates=stats.duplicates,
    )


def collect_event_view(
    *,
    pipeline: EventPipeline | None = None,
    pipeline_provider: Callable[[], EventPipeline | None] | None = None,
) -> EventSnapshotView:
    """Read the buffered events from the existing pipeline for the UI.

    Args:
        pipeline: A pipeline instance to inspect (tests inject one).
        pipeline_provider: Overrides how the active pipeline is resolved.

    The pipeline is only read (``peek``/``stats``); it is never started, drained,
    cleared or submitted to.
    """
    resolved = pipeline
    if resolved is None:
        provider = pipeline_provider or _default_pipeline
        try:
            resolved = provider()
        except Exception as exc:
            logger.warning("Resolving the event pipeline failed: %s", exc)
            resolved = None

    try:
        posture = _posture(resolved)
        envelopes = resolved.peek() if resolved is not None else []
        rows = tuple(_to_row(envelope.sequence, envelope.event) for envelope in envelopes)
        events = tuple(envelope.event for envelope in envelopes)
    except Exception as exc:
        # Never surface stack traces or sensitive details in the UI.
        logger.warning("Reading buffered events failed: %s", exc)
        return EventSnapshotView(
            available=False,
            error=EVENT_ERROR,
            collected_at=None,
            posture=_posture(None),
            rows=(),
        )

    return EventSnapshotView(
        available=True,
        error=None,
        collected_at=rows[-1].timestamp if rows else None,
        posture=posture,
        rows=rows,
        events=events,
    )


def describe_event(event: SecurityEvent) -> dict[str, str]:
    """Return a structured, safe, read-only view of one event for the detail panel.

    Only known fields are included; nested contexts are rendered as flat
    ``section.field`` keys. Sensitive ``raw`` mappings are redacted with the
    shared redactor and command lines are re-sanitized. No ``repr()`` is used.
    """
    details: dict[str, str] = {
        "event_id": event.event_id,
        "schema_version": event.schema_version,
        "event_type": event.event_type.value,
        "category": event.category.value,
        "severity": event.severity.value,
        "timestamp": event.timestamp.isoformat(),
        "source": _source_summary(event),
    }
    if event.message:
        details["message"] = event.message

    if event.host is not None:
        host = event.host
        details["host.host_id"] = host.host_id
        if host.hostname:
            details["host.hostname"] = host.hostname
        details["host.platform"] = host.platform.value
        if host.os_version:
            details["host.os_version"] = host.os_version

    if event.actor is not None:
        actor = event.actor
        if actor.user:
            details["actor.user"] = actor.user
        details["actor.privileged"] = str(actor.privileged).lower()

    if event.process is not None:
        process = event.process
        if process.pid is not None:
            details["process.pid"] = str(process.pid)
        if process.ppid is not None:
            details["process.ppid"] = str(process.ppid)
        if process.name:
            details["process.name"] = process.name
        if process.executable_path:
            details["process.executable_path"] = process.executable_path
        if process.command_line:
            sanitized = _sanitize_command_line(process.command_line)
            if sanitized:
                details["process.command_line"] = sanitized

    if event.socket is not None:
        socket = event.socket
        details["socket.protocol"] = socket.protocol.value
        details["socket.address_family"] = socket.address_family.value
        if socket.local_address:
            details["socket.local_address"] = socket.local_address
        if socket.local_port is not None:
            details["socket.local_port"] = str(socket.local_port)
        if socket.status:
            details["socket.status"] = socket.status

    if event.file is not None:
        file = event.file
        details["file.path"] = file.path
        details["file.file_type"] = file.file_type.value
        if file.operation:
            details["file.operation"] = file.operation
        if file.size_bytes is not None:
            details["file.size_bytes"] = str(file.size_bytes)
        details["file.hash_status"] = file.hash_status.value if file.hash_status else MISSING
        if "sha256" in file.hashes:
            details["file.sha256"] = file.hashes["sha256"]

    if event.network is not None:
        network = event.network
        if network.src_ip:
            details["network.src_ip"] = network.src_ip
        if network.src_port is not None:
            details["network.src_port"] = str(network.src_port)
        if network.dst_ip:
            details["network.dst_ip"] = network.dst_ip
        if network.dst_port is not None:
            details["network.dst_port"] = str(network.dst_port)
        details["network.protocol"] = network.protocol.value
        details["network.direction"] = network.direction.value
        if network.flow_id:
            details["network.flow_id"] = network.flow_id

    if event.labels:
        for key, value in sorted(event.labels.items()):
            details[f"label.{key}"] = value

    if event.raw:
        redacted = redact(event.raw)
        for key, value in sorted(redacted.items()):
            details[f"raw.{key}"] = str(value)

    return details


__all__ = [
    "EVENT_ERROR",
    "EventRow",
    "EventSnapshotView",
    "PipelinePosture",
    "collect_event_view",
    "describe_event",
]
