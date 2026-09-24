"""Map normalized packet records onto the canonical ``SecurityEvent``.

The shared schema already models a packet as a
:class:`~aegis_shared.events.NetworkContext`; this module adds only the
``NETWORK_PACKET_OBSERVED`` event type mapping. No second event format and no
attack-specific event types are introduced - detection is a later step.
"""

from __future__ import annotations

from datetime import datetime

from aegis_network_sensor.models import PacketRecord, format_ip_endpoint
from aegis_shared.enums import EventType, Severity
from aegis_shared.events import HostRef, NetworkContext, SecurityEvent, SourceRef


def describe_packet(record: PacketRecord) -> str:
    """A short, deterministic, payload-free description of the packet."""
    source = format_ip_endpoint(record.src_ip, record.src_port, record.ip_version)
    destination = format_ip_endpoint(record.dst_ip, record.dst_port, record.ip_version)
    length = record.packet_length if record.packet_length is not None else "?"
    return f"{record.protocol.value} {source} -> {destination} len={length}"


def build_network_event(
    record: PacketRecord,
    *,
    event_type: EventType = EventType.NETWORK_PACKET_OBSERVED,
    source: SourceRef,
    host: HostRef | None = None,
    timestamp: datetime | None = None,
    severity: Severity = Severity.INFO,
) -> SecurityEvent:
    """Build a ``SecurityEvent`` for one observed packet.

    Args:
        record: The normalized packet.
        event_type: Defaults to ``NETWORK_PACKET_OBSERVED``.
        source: The emitting sensor (``SourceKind.SENSOR``).
        host: Optional host context; network telemetry often has none.
        timestamp: Overrides the event time; defaults to the packet timestamp.
        severity: Defaults to ``INFO`` - detection decides severity later.
    """
    kwargs: dict[str, object] = {
        "event_type": event_type,
        "severity": severity,
        "source": source,
        "host": host,
        "timestamp": timestamp or record.timestamp,
        "network": NetworkContext(
            src_ip=record.src_ip,
            src_port=record.src_port,
            dst_ip=record.dst_ip,
            dst_port=record.dst_port,
            protocol=record.protocol,
            direction=record.direction,
            interface=record.interface,
            ip_version=record.ip_version,
            packet_length=record.packet_length,
            flow_id=record.flow_id,
        ),
        "message": f"Network packet observed: {describe_packet(record)}",
    }
    return SecurityEvent.create(**kwargs)  # type: ignore[arg-type]


def records_to_events(
    records: tuple[PacketRecord, ...] | list[PacketRecord],
    *,
    source: SourceRef,
    host: HostRef | None = None,
    timestamp: datetime | None = None,
) -> tuple[SecurityEvent, ...]:
    """Convert normalized records to canonical events, preserving order."""
    return tuple(
        build_network_event(record, source=source, host=host, timestamp=timestamp)
        for record in records
    )


__all__ = ["build_network_event", "describe_packet", "records_to_events"]
