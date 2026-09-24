"""Network flow telemetry: bounded aggregation of packets into directional flows.

Every normalized packet already carries a deterministic directional flow id (the
5-tuple identity). :class:`FlowAggregator` folds packets into :class:`FlowRecord`
summaries - addresses, ports, protocol, address family, direction, packet/byte
counters and first/last seen - with a hard cap on tracked flows. No payload is
ever stored.

:func:`flows_to_events` maps aggregated flows onto the existing
``NETWORK_FLOW_SUMMARY`` event type and :class:`~aegis_shared.events.NetworkContext`
counter fields; it is provided for future detection/export and is not submitted
automatically.
"""

from __future__ import annotations

from aegis_network_sensor.flows.aggregator import DEFAULT_MAX_FLOWS, FlowAggregator
from aegis_network_sensor.flows.events import build_flow_event, describe_flow, flows_to_events
from aegis_network_sensor.flows.models import FlowRecord

__all__ = [
    "DEFAULT_MAX_FLOWS",
    "FlowAggregator",
    "FlowRecord",
    "build_flow_event",
    "describe_flow",
    "flows_to_events",
]
