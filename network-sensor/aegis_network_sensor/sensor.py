"""Network sensor orchestration: capture -> normalize -> event -> pipeline.

The sensor is a thin coordinator. It never performs detection and never modifies
network state; it only turns passively observed packets into canonical events and
hands them to the (in-memory) network event pipeline.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Any

from aegis_network_sensor.capture import PacketCapture
from aegis_network_sensor.config import SensorSettings
from aegis_network_sensor.flows import FlowAggregator, FlowRecord
from aegis_network_sensor.models import CaptureSummary, PacketRecord
from aegis_network_sensor.normalization import normalize_packet
from aegis_network_sensor.pipeline import NetworkEventPipeline
from aegis_shared.enums import SourceKind
from aegis_shared.events import SourceRef
from aegis_shared.logging import get_logger
from aegis_shared.pipeline import EventEnvelope, PipelineStats

logger = get_logger(__name__)


class SensorDisabledError(RuntimeError):
    """Raised when capture is requested but disabled or unconfigured."""


class NetworkSensor:
    """Coordinate passive capture, normalization and event submission."""

    def __init__(
        self,
        settings: SensorSettings,
        *,
        pipeline: NetworkEventPipeline | None = None,
        flow_aggregator: FlowAggregator | None = None,
    ) -> None:
        self._settings = settings
        self._pipeline = pipeline or NetworkEventPipeline()
        self._local_addresses = frozenset(settings.local_addresses)
        #: Bounded flow telemetry over normalized packets (no payload stored).
        self._flows = flow_aggregator or FlowAggregator()

    @property
    def capture_enabled(self) -> bool:
        """Whether configuration permits capture."""
        return self._settings.capture_enabled

    @property
    def pipeline(self) -> NetworkEventPipeline:
        """The pipeline events are submitted to."""
        return self._pipeline

    @property
    def flow_aggregator(self) -> FlowAggregator:
        """The bounded flow aggregator tracking normalized packets."""
        return self._flows

    @property
    def flows(self) -> tuple[FlowRecord, ...]:
        """Snapshot of the currently tracked flows (metadata only)."""
        return self._flows.snapshot()

    def source_ref(self) -> SourceRef:
        """The sensor's canonical event source reference."""
        identifier = self._settings.sensor_id.strip() or (
            f"sensor-{self._settings.interface.strip() or 'local'}"
        )
        return SourceRef(kind=SourceKind.SENSOR, id=identifier)

    def process_packets(
        self, packets: Iterable[Any], *, timestamp: datetime | None = None
    ) -> CaptureSummary:
        """Normalize and submit already-obtained packets (no capture).

        Useful for offline replay and tests; performs no I/O.
        """
        observed = 0
        skipped = 0
        records: list[PacketRecord] = []
        for packet in packets:
            observed += 1
            record = self._normalize(packet, timestamp=timestamp)
            if record is None:
                skipped += 1
            else:
                records.append(record)
        return self._submit(records, observed=observed, skipped=skipped)

    def capture(self, *, count: int | None = None) -> CaptureSummary:
        """Perform one bounded passive capture and submit the normalized events.

        Raises:
            SensorDisabledError: if capture is disabled or no interface is set.
        """
        if not self._settings.capture_enabled:
            raise SensorDisabledError(
                "capture is disabled; set AEGIS_SENSOR_CAPTURE_ENABLED=true "
                "and AEGIS_SENSOR_INTERFACE to enable it"
            )
        interface = self._settings.interface.strip()
        if not interface:
            raise SensorDisabledError("no capture interface configured")

        requested = count if count is not None else self._settings.max_packets_per_run
        limit = max(1, min(requested, self._settings.max_packets_per_run))

        observed = 0
        skipped = 0
        records: list[PacketRecord] = []

        def _handle(packet: Any) -> None:
            nonlocal observed, skipped
            observed += 1
            record = self._normalize(packet)
            if record is None:
                skipped += 1
            else:
                records.append(record)

        session = PacketCapture(
            interface=interface,
            packet_filter=self._settings.capture_filter,
            promiscuous=self._settings.promiscuous,
        )
        session.capture(
            count=limit,
            on_packet=_handle,
            timeout=self._settings.capture_timeout_seconds,
        )
        return self._submit(records, observed=observed, skipped=skipped)

    def drain(self) -> list[EventEnvelope]:
        """Drain buffered events from the pipeline."""
        return self._pipeline.drain()

    @property
    def stats(self) -> PipelineStats:
        """Pipeline counters."""
        return self._pipeline.stats

    def _normalize(self, packet: Any, *, timestamp: datetime | None = None) -> PacketRecord | None:
        record = normalize_packet(
            packet,
            interface=self._settings.interface or None,
            local_addresses=self._local_addresses,
            timestamp=timestamp,
        )
        if record is None:
            return None
        if (
            record.packet_length is not None
            and record.packet_length > self._settings.max_packet_bytes
        ):
            logger.debug("Skipping oversized packet (%s bytes)", record.packet_length)
            return None
        return record

    def _submit(
        self, records: list[PacketRecord], *, observed: int, skipped: int
    ) -> CaptureSummary:
        # Fold packets into bounded flow telemetry before event submission.
        self._flows.observe_many(records)
        results = self._pipeline.submit_packets(records, source=self.source_ref())
        accepted = sum(1 for result in results if result.accepted)
        stats = self._pipeline.stats
        return CaptureSummary(
            interface=self._settings.interface or None,
            observed=observed,
            normalized=len(records),
            skipped=skipped,
            accepted=accepted,
            rejected=len(results) - accepted,
            buffered=stats.buffered,
            capacity=stats.capacity,
        )


__all__ = ["NetworkSensor", "SensorDisabledError"]
