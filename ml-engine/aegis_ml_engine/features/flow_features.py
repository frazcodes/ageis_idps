"""Deterministic feature extraction from network flow telemetry.

Converts a :class:`~aegis_network_sensor.flows.models.FlowRecord` into a
fixed-length numeric feature representation suitable for downstream anomaly
detectors.  This module is **pure** -- it performs no I/O, starts no threads,
sniffs no packets and mutates no input.

Feature formulas
----------------
All rates use wall-clock seconds derived from ``FlowRecord.duration_ms``.

``duration_seconds`` = ``duration_ms / 1000``

``packets_per_second`` = ``packet_count / duration_seconds``

``bytes_per_second`` = ``byte_count / duration_seconds``

``average_packet_size`` = ``byte_count / packet_count``

Edge-case contract
------------------
* **duration_ms <= 0**: ``duration_seconds`` is treated as ``0.0``;
  ``packets_per_second`` and ``bytes_per_second`` are ``0.0``.
* **packet_count == 0**: ``average_packet_size`` is ``0.0``.
* Derived values are never negative, never ``NaN`` and never infinity.
* Input ``FlowRecord`` is never mutated.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from aegis_network_sensor.flows.models import FlowRecord
from aegis_shared.enums import AddressFamily, NetworkDirection, TransportProtocol

# ---------------------------------------------------------------------------
# Feature representation
# ---------------------------------------------------------------------------

_FEATURE_VERSION = "1.0.0"


@dataclass(frozen=True)
class NetworkBehaviorFeatures:
    """Immutable numeric features derived from a single flow.

    Only header-level behavioral features are included.  No payload, credentials
    or raw packet contents are stored.
    """

    #: --- Identity / traceability (non-numeric, preserved for correlation) ---
    flow_id: str
    protocol: TransportProtocol
    ip_version: AddressFamily
    direction: NetworkDirection

    #: --- Raw counters (preserved for reference) ---
    packet_count: int
    byte_count: int
    duration_ms: int

    #: --- Derived rate features ---
    #: packet_count / duration_seconds  (0.0 when duration <= 0)
    packets_per_second: float
    #: byte_count / duration_seconds  (0.0 when duration <= 0)
    bytes_per_second: float
    #: byte_count / packet_count  (0.0 when packet_count == 0)
    average_packet_size: float

    #: Feature schema version (deterministic, bump on field changes).
    feature_version: str = _FEATURE_VERSION


# ---------------------------------------------------------------------------
# Pure extraction
# ---------------------------------------------------------------------------

def extract_flow_features(flow: FlowRecord) -> NetworkBehaviorFeatures:
    """Extract behavioral features from a single flow.

    The function is pure: no I/O, no mutation, deterministic output.
    """
    packet_count = flow.packet_count
    byte_count = flow.byte_count
    duration_ms = flow.duration_ms

    duration_seconds = duration_ms / 1000.0

    # Rate features: safe when duration is zero or negative.
    if duration_seconds > 0.0:
        packets_per_second = packet_count / duration_seconds
        bytes_per_second = byte_count / duration_seconds
    else:
        packets_per_second = 0.0
        bytes_per_second = 0.0

    # Average packet size: safe when packet_count is zero.
    average_packet_size = byte_count / packet_count if packet_count > 0 else 0.0

    return NetworkBehaviorFeatures(
        flow_id=flow.flow_id,
        protocol=flow.protocol,
        ip_version=flow.ip_version,
        direction=flow.direction,
        packet_count=packet_count,
        byte_count=byte_count,
        duration_ms=duration_ms,
        packets_per_second=packets_per_second,
        bytes_per_second=bytes_per_second,
        average_packet_size=average_packet_size,
    )


def extract_batch(flows: Sequence[FlowRecord]) -> tuple[NetworkBehaviorFeatures, ...]:
    """Extract features from a sequence of flows, preserving input order.

    The function is pure: no I/O, no mutation, deterministic output.
    Empty input returns an empty tuple.  Output length equals input length.
    """
    return tuple(extract_flow_features(flow) for flow in flows)


__all__ = [
    "_FEATURE_VERSION",
    "NetworkBehaviorFeatures",
    "extract_batch",
    "extract_flow_features",
]
