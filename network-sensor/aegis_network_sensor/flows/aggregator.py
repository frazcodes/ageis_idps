"""Bounded, deterministic aggregation of packets into directional flows.

The aggregator groups normalized :class:`~aegis_network_sensor.models.PacketRecord`
objects by their deterministic directional flow id (the existing 5-tuple identity)
and accumulates packet/byte counters and first/last-seen timestamps.

Boundedness
-----------
State is capped at ``max_flows``. When a new flow would exceed the cap, the
least-recently-observed flow is evicted (deterministic, oldest-first by
observation order) and counted in :attr:`evicted_count`. Memory therefore cannot
grow without limit. No payload is ever stored.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable

from aegis_network_sensor.flows.models import FlowRecord
from aegis_network_sensor.models import PacketRecord
from aegis_network_sensor.normalization import compute_flow_id
from aegis_shared.enums import NetworkDirection
from aegis_shared.logging import get_logger

logger = get_logger(__name__)

#: Default hard cap on the number of concurrently tracked flows.
DEFAULT_MAX_FLOWS = 4096


class FlowAggregator:
    """Aggregate packets into bounded, deterministic directional flow records."""

    def __init__(self, *, max_flows: int = DEFAULT_MAX_FLOWS) -> None:
        if max_flows < 1:
            raise ValueError("max_flows must be at least 1")
        self._max_flows = max_flows
        self._flows: OrderedDict[str, FlowRecord] = OrderedDict()
        self._evicted = 0
        self._changed_ids: set[str] = set()

    @property
    def max_flows(self) -> int:
        """Maximum number of flows held at once."""
        return self._max_flows

    @property
    def flow_count(self) -> int:
        """Number of flows currently tracked."""
        return len(self._flows)

    @property
    def evicted_count(self) -> int:
        """Number of flows evicted because the cap was reached."""
        return self._evicted

    def observe(self, record: PacketRecord) -> FlowRecord:
        """Fold one packet into its flow and return the updated record."""
        key = record.flow_id or compute_flow_id(
            ip_version=record.ip_version,
            protocol=record.protocol,
            src_ip=record.src_ip,
            src_port=record.src_port,
            dst_ip=record.dst_ip,
            dst_port=record.dst_port,
        )
        length = record.packet_length or 0

        existing = self._flows.get(key)
        if existing is None:
            flow = FlowRecord(
                flow_id=key,
                ip_version=record.ip_version,
                protocol=record.protocol,
                src_ip=record.src_ip,
                dst_ip=record.dst_ip,
                ports_applicable=record.ports_applicable,
                src_port=record.src_port,
                dst_port=record.dst_port,
                direction=record.direction,
                interface=record.interface,
                sni=record.sni,
                packet_count=1,
                byte_count=length,
                first_seen=record.timestamp,
                last_seen=record.timestamp,
            )
        else:
            flow = existing.model_copy(
                update={
                    "packet_count": existing.packet_count + 1,
                    "byte_count": existing.byte_count + length,
                    "first_seen": min(existing.first_seen, record.timestamp),
                    "last_seen": max(existing.last_seen, record.timestamp),
                    # Retain the first valid SNI observed; do not overwrite with None.
                    "sni": existing.sni or record.sni,
                    # Preserve the first determinable direction.
                    "direction": (
                        existing.direction
                        if existing.direction is not NetworkDirection.UNKNOWN
                        else record.direction
                    ),
                }
            )

        self._store(key, flow)
        self._changed_ids.add(key)
        return flow

    def observe_many(self, records: Iterable[PacketRecord]) -> tuple[FlowRecord, ...]:
        """Fold many packets in order, returning the updated flow for each."""
        return tuple(self.observe(record) for record in records)

    def drain_changed(self) -> tuple[FlowRecord, ...]:
        """Return only flows that changed since the last drain, then reset.

        This is the batching primitive: callers (e.g. the runtime) should use
        this instead of :meth:`snapshot` when they only need to process flows
        that actually received new packets.  Avoids re-emitting events for
        unchanged flows every poll cycle.
        """
        if not self._changed_ids:
            return ()
        changed = [self._flows[k] for k in self._changed_ids if k in self._flows]
        self._changed_ids.clear()
        return tuple(changed)

    def snapshot(self) -> tuple[FlowRecord, ...]:
        """Return the tracked flows, oldest-observed first."""
        return tuple(self._flows.values())

    def clear(self) -> None:
        """Drop all tracked flows. Cumulative eviction counter is preserved."""
        self._flows.clear()
        self._changed_ids.clear()

    def _store(self, key: str, flow: FlowRecord) -> None:
        self._flows[key] = flow
        self._flows.move_to_end(key)
        while len(self._flows) > self._max_flows:
            self._flows.popitem(last=False)
            self._evicted += 1


__all__ = ["DEFAULT_MAX_FLOWS", "FlowAggregator"]
