"""Map aggregated flows onto the canonical ``SecurityEvent``.

Reuses the existing shared contract only: the ``NETWORK_FLOW_SUMMARY`` event type
(:data:`aegis_shared.enums.EventType.FLOW_SUMMARY`) and the counter/timing fields
already present on :class:`~aegis_shared.events.NetworkContext`. No new event
type, no schema change and no second event format is introduced.

These builders are provided for future detection/export; the network sensor does
not submit flow events automatically, so packet-level pipeline behavior is
unchanged.
"""

from __future__ import annotations

from datetime import datetime

from aegis_network_sensor.flows.models import FlowRecord
from aegis_network_sensor.models import format_ip_endpoint
from aegis_shared.enums import EventType, Severity
from aegis_shared.events import HostRef, NetworkContext, SecurityEvent, SourceRef


def describe_flow(flow: FlowRecord) -> str:
    """A short, deterministic, payload-free description of the flow."""
    source = format_ip_endpoint(flow.src_ip, flow.src_port, flow.ip_version)
    destination = format_ip_endpoint(flow.dst_ip, flow.dst_port, flow.ip_version)
    return (
        f"{flow.protocol.value} {source} -> {destination} "
        f"pkts={flow.packet_count} bytes={flow.byte_count}"
    )


def build_flow_event(
    flow: FlowRecord,
    *,
    event_type: EventType = EventType.FLOW_SUMMARY,
    source: SourceRef,
    host: HostRef | None = None,
    timestamp: datetime | None = None,
    severity: Severity = Severity.INFO,
) -> SecurityEvent:
    """Build a ``SecurityEvent`` summarising one aggregated flow.

    The directional flow is mapped to ``bytes_sent``/``packets_sent`` and
    ``duration_ms`` on the existing :class:`NetworkContext`.
    """
    kwargs: dict[str, object] = {
        "event_type": event_type,
        "severity": severity,
        "source": source,
        "host": host,
        "timestamp": timestamp or flow.last_seen,
        "network": NetworkContext(
            src_ip=flow.src_ip,
            src_port=flow.src_port,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            direction=flow.direction,
            interface=flow.interface,
            ip_version=flow.ip_version,
            flow_id=flow.flow_id,
            packets_sent=flow.packet_count,
            bytes_sent=flow.byte_count,
            duration_ms=flow.duration_ms,
        ),
        "message": f"Network flow summary: {describe_flow(flow)}",
    }
    return SecurityEvent.create(**kwargs)  # type: ignore[arg-type]


def flows_to_events(
    flows: tuple[FlowRecord, ...] | list[FlowRecord],
    *,
    source: SourceRef,
    host: HostRef | None = None,
    timestamp: datetime | None = None,
) -> tuple[SecurityEvent, ...]:
    """Convert aggregated flows to canonical events, preserving order."""
    return tuple(
        build_flow_event(flow, source=source, host=host, timestamp=timestamp) for flow in flows
    )


__all__ = ["build_flow_event", "describe_flow", "flows_to_events"]
