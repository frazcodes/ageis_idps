"""Aegis IDPS network sensor (NIDS foundation).

Passive, read-only network telemetry. Capture is **disabled by default** and this
package contains no detection logic. It normalizes observed packets into the
canonical :class:`aegis_shared.events.SecurityEvent` for a future detection
engine.

Importing this package does **not** require scapy. Scapy-dependent symbols
(:class:`NetworkSensor`, :class:`PacketCapture`, :func:`list_interfaces`) are
resolved lazily, so configuration, models and the CLI work without the ``sensor``
extra.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

from aegis_network_sensor.config import SensorSettings, get_sensor_settings
from aegis_network_sensor.models import CaptureSummary, PacketRecord, format_ip_endpoint

if TYPE_CHECKING:  # pragma: no cover - typing only
    from aegis_network_sensor.capture import PacketCapture, list_interfaces
    from aegis_network_sensor.sensor import NetworkSensor, SensorDisabledError

_LAZY_ATTRS: dict[str, str] = {
    "NetworkSensor": "aegis_network_sensor.sensor",
    "SensorDisabledError": "aegis_network_sensor.sensor",
    "PacketCapture": "aegis_network_sensor.capture",
    "CaptureUnavailableError": "aegis_network_sensor.capture",
    "list_interfaces": "aegis_network_sensor.capture",
    "FlowAggregator": "aegis_network_sensor.flows",
    "FlowRecord": "aegis_network_sensor.flows",
    "build_flow_event": "aegis_network_sensor.flows",
    "flows_to_events": "aegis_network_sensor.flows",
}


def __getattr__(name: str) -> object:
    """Resolve scapy-dependent symbols on first use (PEP 562)."""
    module_name = _LAZY_ATTRS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return getattr(importlib.import_module(module_name), name)


__all__ = [
    "CaptureSummary",
    "FlowAggregator",
    "FlowRecord",
    "NetworkSensor",
    "PacketCapture",
    "PacketRecord",
    "SensorDisabledError",
    "SensorSettings",
    "build_flow_event",
    "flows_to_events",
    "format_ip_endpoint",
    "get_sensor_settings",
    "list_interfaces",
]
