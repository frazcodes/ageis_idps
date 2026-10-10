"""Network adapter: existing Step 4 port models -> UI-friendly data.

Strictly read-only **local listening-endpoint discovery**. It calls the existing
:func:`aegis_agent.monitors.port.collect_port_snapshot` once per refresh and
translates :class:`PortRecord` objects into flat :class:`PortRow` values for the
Qt table model.

It never captures packets, never starts the ``PortMonitor`` lifecycle, never
polls continuously and never changes network configuration. The collector is
imported lazily so opening the application (or any other page) does not load
psutil or the port monitor.

Step 4 exposes protocol, address family, local address/port, socket status, PID
and process name. It does **not** expose a user/owner or an executable path, so
those are not shown (nothing is fabricated).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

from aegis_desktop.services.monitoring import (
    MonitoringStatus,
    get_active_monitoring_controller,
)
from aegis_desktop.services.processes import MISSING
from aegis_shared.logging import get_logger

if TYPE_CHECKING:  # pragma: no cover - typing only
    from aegis_agent.monitors.port import PortRecord, PortSnapshot
    from aegis_network_sensor.flows import FlowRecord
    from aegis_shared.events import SecurityEvent

logger = get_logger(__name__)

#: Non-sensitive message shown when listening-endpoint collection fails.
PORT_ERROR = "Unable to collect listening endpoints"


@dataclass(frozen=True)
class PortRow:
    """One local listening endpoint, flattened for display and sorting."""

    protocol: str
    address_family: str
    local_address: str | None
    local_port: int
    pid: int | None
    process_name: str | None
    status: str | None
    #: Unambiguous combined representation from Step 4 (e.g. ``[::1]:8000``).
    endpoint: str
    identity: str


@dataclass(frozen=True)
class PortSnapshotView:
    """Read-only view of one listening-endpoint snapshot."""

    available: bool
    error: str | None
    collected_at: datetime | None
    rows: tuple[PortRow, ...]

    @property
    def count(self) -> int:
        """Number of endpoints in the snapshot."""
        return len(self.rows)


def _default_collector() -> PortSnapshot:
    # Imported lazily: opening the application must not load the port monitor.
    from aegis_agent.monitors.port import collect_port_snapshot

    return collect_port_snapshot()


def _to_row(record: PortRecord) -> PortRow:
    return PortRow(
        protocol=record.protocol.value,
        address_family=record.address_family.value,
        local_address=record.local_address,
        local_port=record.local_port,
        pid=record.pid,
        process_name=record.process_name,
        status=record.status,
        endpoint=record.endpoint,
        identity=record.identity.key,
    )


def collect_port_view(
    *,
    collector: Callable[[], PortSnapshot] | None = None,
) -> PortSnapshotView:
    """Collect one listening-endpoint snapshot and translate it for the UI.

    Args:
        collector: Overrides the existing collector (tests inject one). The
            default is a one-shot call to the Step 4 collector; the
            ``PortMonitor`` lifecycle is never started.

    Returns:
        A :class:`PortSnapshotView`; on failure ``available`` is ``False`` and a
        safe, non-sensitive ``error`` message is provided.
    """
    collect = collector or _default_collector
    try:
        snapshot = collect()
    except Exception as exc:
        # Never surface stack traces or sensitive details in the UI.
        logger.warning("Listening-endpoint collection failed: %s", exc)
        return PortSnapshotView(
            available=False,
            error=PORT_ERROR,
            collected_at=None,
            rows=(),
        )

    return PortSnapshotView(
        available=True,
        error=None,
        collected_at=snapshot.captured_at,
        rows=tuple(_to_row(record) for record in snapshot.ports),
    )


# ---------------------------------------------------------------------------
# Live network monitoring view (runtime-owned telemetry)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FlowRow:
    """One aggregated directional flow, flattened for display."""

    flow_id: str
    protocol: str
    source: str
    destination: str
    packets: int
    bytes: int
    duration_ms: int
    direction: str
    sni: str | None = None


@dataclass(frozen=True)
class NetworkEventRow:
    """One recent network event from the existing runtime pipeline."""

    timestamp: datetime
    event_type: str
    protocol: str
    source: str
    destination: str
    packets: int | None
    bytes: int | None
    sni: str | None = None


@dataclass(frozen=True)
class NetworkMonitoringView:
    """Read-only view of runtime network monitoring state and telemetry."""

    status: MonitoringStatus
    flows: tuple[FlowRow, ...]
    events: tuple[NetworkEventRow, ...]

    @property
    def available(self) -> bool:
        """Whether the runtime is currently producing network telemetry."""
        return self.status.running


def _format_endpoint(
    address: str | None, port: int | None, ip_version: object
) -> str:
    from aegis_network_sensor.models import format_ip_endpoint

    return format_ip_endpoint(address, port, ip_version)  # type: ignore[arg-type]


def _to_flow_row(flow: FlowRecord) -> FlowRow:
    dst_endpoint = _format_endpoint(flow.dst_ip, flow.dst_port, flow.ip_version)
    dst_display = f"{dst_endpoint} ({flow.sni})" if flow.sni else dst_endpoint
    return FlowRow(
        flow_id=flow.flow_id,
        protocol=flow.protocol.value,
        source=_format_endpoint(flow.src_ip, flow.src_port, flow.ip_version),
        destination=dst_display,
        packets=flow.packet_count,
        bytes=flow.byte_count,
        duration_ms=flow.duration_ms,
        direction=flow.direction.value,
        sni=flow.sni,
    )


def _to_event_row(event: SecurityEvent) -> NetworkEventRow:
    net = event.network
    dst_endpoint = (
        _format_endpoint(net.dst_ip, net.dst_port, net.ip_version)
        if net is not None
        else MISSING
    )
    domain = net.domain if net is not None else None
    if domain and dst_endpoint != MISSING:
        dst_display = f"{dst_endpoint} ({domain})"
    else:
        dst_display = dst_endpoint

    return NetworkEventRow(
        timestamp=event.timestamp,
        event_type=event.event_type.value,
        protocol=net.protocol.value if net is not None else MISSING,
        source=(
            _format_endpoint(net.src_ip, net.src_port, net.ip_version)
            if net is not None
            else MISSING
        ),
        destination=dst_display,
        packets=net.packets_sent if net is not None else None,
        bytes=net.bytes_sent if net is not None else None,
        sni=domain,
    )


def _default_network_events() -> list[SecurityEvent]:
    """Read recent network events from the existing runtime pipeline (read-only)."""
    from aegis_shared.enums import EventCategory
    from aegis_shared.pipeline import get_active_pipeline

    pipeline = get_active_pipeline()
    if pipeline is None:
        return []
    return [
        envelope.event
        for envelope in pipeline.peek()
        if envelope.event.category is EventCategory.NETWORK
    ]


def _stopped_status() -> MonitoringStatus:
    from aegis_desktop.services.monitoring import (
        CAPTURE_INACTIVE,
        NetworkCounters,
    )
    from aegis_desktop.services.monitoring import MonitoringStatus as _Status

    return _Status(
        running=False,
        capture_state=CAPTURE_INACTIVE,
        capture_error=None,
        interface=None,
        counters=NetworkCounters(packets=None, bytes=None, flows=None, active_flows=None),
    )


def collect_network_monitoring_view(
    *,
    controller_provider: Callable[[], Any] | None = None,
    events_provider: Callable[[], Iterable[SecurityEvent]] | None = None,
) -> NetworkMonitoringView:
    """Read live network monitoring state from the running runtime (read-only).

    Uses the single published :class:`MonitoringController`; no capture, no
    second runtime loop and no fabricated telemetry. When monitoring is stopped
    an honest stopped status with empty flows/events is returned.
    """
    provider = controller_provider or get_active_monitoring_controller
    controller = None
    try:
        controller = provider()
    except Exception as exc:
        logger.warning("Resolving monitoring controller failed: %s", exc)

    if controller is None:
        status = _stopped_status()
        flows: tuple[FlowRow, ...] = ()
    else:
        try:
            status = controller.status()
        except Exception as exc:
            logger.warning("Reading monitoring status failed: %s", exc)
            status = _stopped_status()
        flows = tuple(_to_flow_row(flow) for flow in controller.network_flows())

    try:
        source = events_provider or _default_network_events
        events = tuple(_to_event_row(event) for event in source())
    except Exception as exc:
        logger.warning("Reading network events failed: %s", exc)
        events = ()

    return NetworkMonitoringView(status=status, flows=flows, events=events)


__all__ = [
    "MISSING",
    "PORT_ERROR",
    "FlowRow",
    "NetworkEventRow",
    "NetworkMonitoringView",
    "PortRow",
    "PortSnapshotView",
    "collect_network_monitoring_view",
    "collect_port_view",
]
