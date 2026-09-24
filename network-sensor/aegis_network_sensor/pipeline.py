"""Network event pipeline: the shared transport plus network-packet adapters.

Mirrors :class:`aegis_agent.pipeline.pipeline.HostEventPipeline`. The transport
core (validation, bounded dedup, bounded buffer, counters) is shared, so host and
network telemetry behave identically and can be unified later without a rewrite.
"""

from __future__ import annotations

from datetime import datetime

from aegis_network_sensor.events import records_to_events
from aegis_network_sensor.models import PacketRecord
from aegis_shared.events import HostRef, SourceRef
from aegis_shared.pipeline import DEFAULT_DEDUP_WINDOW, EventPipeline, SubmitResult

__all__ = ["DEFAULT_DEDUP_WINDOW", "NetworkEventPipeline"]


class NetworkEventPipeline(EventPipeline):
    """The shared event pipeline with a network-packet producer adapter."""

    def submit_packets(
        self,
        records: tuple[PacketRecord, ...] | list[PacketRecord],
        *,
        source: SourceRef,
        host: HostRef | None = None,
        timestamp: datetime | None = None,
    ) -> list[SubmitResult]:
        """Convert normalized packet records to events and submit them."""
        events = records_to_events(records, source=source, host=host, timestamp=timestamp)
        return self.submit_all(events)
