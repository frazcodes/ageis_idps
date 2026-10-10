"""Typed model for aggregated directional network flows (scapy-free).

A :class:`FlowRecord` is the metadata summary of one directional 5-tuple observed
by the passive sensor: addresses, ports, protocol, address family, direction,
packet/byte counters and first/last seen timestamps. It stores **no payload** and
no application data - only header metadata that passive observation already
exposes.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegis_shared.enums import AddressFamily, NetworkDirection, TransportProtocol


def _ensure_aware_utc(value: datetime | None, field_name: str) -> datetime | None:
    """Reject naive timestamps and normalise aware ones to UTC."""
    if value is None:
        return None
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{field_name} must be timezone-aware UTC")
    return value.astimezone(UTC)


class FlowRecord(BaseModel):
    """Aggregated metadata for one directional flow. Contains no payload."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    #: Deterministic identity: ``ip_version|protocol|src -> dst``.
    flow_id: str = Field(min_length=1, max_length=256)
    ip_version: AddressFamily = AddressFamily.UNKNOWN
    protocol: TransportProtocol = TransportProtocol.OTHER
    src_ip: str | None = Field(default=None, max_length=64)
    dst_ip: str | None = Field(default=None, max_length=64)
    #: ``True`` for TCP/UDP, where ports are meaningful; ``False`` for ICMP etc.
    ports_applicable: bool = False
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    direction: NetworkDirection = NetworkDirection.UNKNOWN
    interface: str | None = Field(default=None, max_length=64)
    #: TLS Server Name Indication (SNI) hostname, if observed in the flow.
    sni: str | None = Field(default=None, max_length=253)
    packet_count: int = Field(default=0, ge=0)
    byte_count: int = Field(default=0, ge=0)
    first_seen: datetime
    last_seen: datetime

    @field_validator("first_seen", "last_seen")
    @classmethod
    def _timestamps_are_aware(cls, value: datetime | None, info: Any) -> datetime | None:
        return _ensure_aware_utc(value, info.field_name)

    @model_validator(mode="after")
    def _is_consistent(self) -> FlowRecord:
        if not self.ports_applicable and (self.src_port is not None or self.dst_port is not None):
            raise ValueError("src_port/dst_port must be None when ports_applicable is False")
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must not precede first_seen")
        return self

    @property
    def duration_ms(self) -> int:
        """Observed flow duration in whole milliseconds (never negative)."""
        delta = (self.last_seen - self.first_seen).total_seconds()
        return max(0, int(delta * 1000))

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible mapping."""
        return self.model_dump(mode="json")


__all__ = ["FlowRecord"]
