"""Typed models for the read-only port monitor.

Representation layer: :class:`PortRecord` is one local listening endpoint,
:class:`PortSnapshot` is the set observed at one instant, and
:class:`PortChanges` is the difference between two snapshots.

Port identity
-------------
Identity is deterministic and **includes ownership**, composed of:

``protocol | address_family | local_address | local_port | owner``

where ``owner`` is the same PID + creation-time scheme used by the process
monitor. Two consequences follow:

* A port that disappears and reappears is correctly reported as stopped then
  started (different observation, same key only if it is truly the same).
* If ``0.0.0.0:8000`` changes owner from process A to process B, the owner
  component changes, so it is reported as A stopping and B starting - never as
  "unchanged". The owner degrades to ``unowned`` when the PID is unavailable,
  keeping identity deterministic even without privileges.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aegis_agent.monitors.port.addressing import format_endpoint
from aegis_shared.enums import AddressFamily, TransportProtocol


def _ensure_aware_utc(value: datetime | None, field_name: str) -> datetime | None:
    """Reject naive timestamps and normalise aware ones to UTC."""
    if value is None:
        return None
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{field_name} must be timezone-aware UTC")
    return value.astimezone(UTC)


class PortIdentity(BaseModel):
    """Deterministic identity of a listening endpoint, ownership included."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    protocol: TransportProtocol
    address_family: AddressFamily
    local_address: str | None = None
    local_port: int = Field(ge=0, le=65535)
    pid: int | None = Field(default=None, ge=0)
    process_create_time: datetime | None = None

    @property
    def owner_key(self) -> str:
        """Owner component of the identity (``pid:create_time`` or ``unowned``)."""
        if self.pid is None:
            return "unowned"
        created = self.process_create_time.isoformat() if self.process_create_time else "unknown"
        return f"{self.pid}:{created}"

    @property
    def key(self) -> str:
        """Opaque, comparable identity key used to diff snapshots."""
        address = self.local_address or "*"
        return (
            f"{self.protocol.value}|{self.address_family.value}|"
            f"{address}|{self.local_port}|{self.owner_key}"
        )


class PortRecord(BaseModel):
    """Safe metadata about one local listening endpoint.

    Remote peers are deliberately not recorded: this monitor discovers local
    listening ports, not network traffic.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    protocol: TransportProtocol
    address_family: AddressFamily
    local_address: str | None = Field(default=None, max_length=64)
    local_port: int = Field(ge=0, le=65535)
    #: OS state such as ``"LISTEN"``; ``None`` for UDP, which has no state.
    status: str | None = Field(default=None, max_length=32)
    pid: int | None = Field(default=None, ge=0)
    process_name: str | None = Field(default=None, max_length=255)
    process_create_time: datetime | None = Field(default=None)

    @field_validator("process_create_time")
    @classmethod
    def _create_time_is_aware(cls, value: datetime | None, info: Any) -> datetime | None:
        return _ensure_aware_utc(value, info.field_name)

    @property
    def identity(self) -> PortIdentity:
        """The deterministic, ownership-aware identity of this endpoint."""
        return PortIdentity(
            protocol=self.protocol,
            address_family=self.address_family,
            local_address=self.local_address,
            local_port=self.local_port,
            pid=self.pid,
            process_create_time=self.process_create_time,
        )

    @property
    def endpoint(self) -> str:
        """Unambiguous display string, e.g. ``0.0.0.0:8000`` or ``[::1]:8000``."""
        return format_endpoint(self.local_address, self.local_port, self.address_family)

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible mapping."""
        return self.model_dump(mode="json")


class PortSnapshot(BaseModel):
    """The set of listening endpoints observed at one instant."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    captured_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    ports: tuple[PortRecord, ...] = ()

    @field_validator("captured_at")
    @classmethod
    def _captured_at_is_aware(cls, value: datetime | None, info: Any) -> datetime | None:
        return _ensure_aware_utc(value, info.field_name)

    def by_identity(self) -> dict[str, PortRecord]:
        """Map each endpoint to its identity key for snapshot diffing."""
        return {record.identity.key: record for record in self.ports}

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible mapping."""
        return self.model_dump(mode="json")


class PortChanges(BaseModel):
    """Listening endpoints that appeared or disappeared between two snapshots."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    captured_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    started: tuple[PortRecord, ...] = ()
    stopped: tuple[PortRecord, ...] = ()

    @field_validator("captured_at")
    @classmethod
    def _captured_at_is_aware(cls, value: datetime | None, info: Any) -> datetime | None:
        return _ensure_aware_utc(value, info.field_name)

    @property
    def is_empty(self) -> bool:
        """Whether nothing changed."""
        return not self.started and not self.stopped

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible mapping."""
        return self.model_dump(mode="json")


__all__ = ["PortChanges", "PortIdentity", "PortRecord", "PortSnapshot"]
