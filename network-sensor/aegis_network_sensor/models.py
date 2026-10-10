"""Normalized network telemetry models (scapy-free).

:class:`PacketRecord` is the typed, normalized representation of one passively
observed packet. It deliberately stores **no payload** and no application data -
only the metadata future NIDS analysis needs.

Unavailable vs not-applicable
-----------------------------
Ports are only meaningful for TCP/UDP. ``ports_applicable`` distinguishes the two
cases explicitly, and the model rejects ports when they do not apply, so an
unknown port can never be mistaken for port ``0``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegis_shared.enums import AddressFamily, NetworkDirection, TransportProtocol


def format_ip_endpoint(address: str | None, port: int | None, ip_version: AddressFamily) -> str:
    """Render an endpoint, bracketing IPv6 hosts to avoid port ambiguity."""
    if port is None:
        return address or "-"
    host = address or "*"
    if ip_version is AddressFamily.IPV6:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


class PacketRecord(BaseModel):
    """Metadata about one observed packet. Contains no payload."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    interface: str | None = Field(default=None, max_length=64)
    ip_version: AddressFamily = AddressFamily.UNKNOWN
    src_ip: str | None = Field(default=None, max_length=64)
    dst_ip: str | None = Field(default=None, max_length=64)
    protocol: TransportProtocol = TransportProtocol.OTHER
    #: ``True`` for TCP/UDP, where ports are meaningful; ``False`` for ICMP etc.
    ports_applicable: bool = False
    #: ``None`` means unavailable (or not applicable when ``ports_applicable`` is False).
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    #: Observed frame/packet length in bytes.
    packet_length: int | None = Field(default=None, ge=0)
    direction: NetworkDirection = NetworkDirection.UNKNOWN
    #: Deterministic identifier of the directional flow this packet belongs to.
    flow_id: str | None = Field(default=None, max_length=256)
    #: TLS Server Name Indication (SNI) hostname, if observed in a ClientHello frame.
    sni: str | None = Field(default=None, max_length=253)

    @field_validator("timestamp")
    @classmethod
    def _timestamp_is_aware(cls, value: datetime | None, info: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            raise ValueError(f"{info.field_name} must be timezone-aware UTC")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _ports_are_consistent(self) -> PacketRecord:
        if not self.ports_applicable and (self.src_port is not None or self.dst_port is not None):
            raise ValueError("src_port/dst_port must be None when ports_applicable is False")
        return self

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible mapping."""
        return self.model_dump(mode="json")


class CaptureSummary(BaseModel):
    """Counters from one bounded capture or processing run."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    interface: str | None = None
    observed: int = Field(ge=0)
    normalized: int = Field(ge=0)
    skipped: int = Field(ge=0)
    accepted: int = Field(ge=0)
    rejected: int = Field(ge=0)
    buffered: int = Field(ge=0)
    capacity: int = Field(ge=0)

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible mapping."""
        return self.model_dump(mode="json")


__all__ = ["CaptureSummary", "PacketRecord", "format_ip_endpoint"]
