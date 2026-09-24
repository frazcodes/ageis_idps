"""The unified runtime event pipeline.

A single :class:`EventPipeline` that carries both host and network canonical
events, so detection and risk run over one ordered stream. It reuses the existing
shared transport unchanged and adds only the small producer adapters already
provided by the host and network pipeline subclasses.
"""

from __future__ import annotations

from aegis_agent.pipeline import HostEventPipeline
from aegis_network_sensor.pipeline import NetworkEventPipeline

__all__ = ["RuntimeEventPipeline"]


class RuntimeEventPipeline(HostEventPipeline, NetworkEventPipeline):
    """One in-memory pipeline carrying host and network events.

    Composes the two existing producer adapters
    (:meth:`HostEventPipeline.submit_monitor_changes` and
    :meth:`NetworkEventPipeline.submit_packets`) over the single shared transport.
    No event schema, buffering, validation or dedup logic is reimplemented.
    """
