"""Immutable asset / network-identity models.

An :class:`AssetIdentity` is a factual view of a host Aegis has observed and the
services/network identities attributed to it. :class:`ObservedService` and
:class:`NetworkPeer` are bounded observations derived from existing telemetry.

These models contain only metadata Aegis can actually obtain (inventory facts,
listening endpoints, flow metadata). They never carry payloads, credentials,
usernames, ownership, business roles or any attribution. A "new" observation is
not a verdict.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aegis_shared.enums import NetworkDirection, Platform, TransportProtocol


def _ensure_aware_utc(value: datetime | None, field_name: str) -> datetime | None:
    """Reject naive timestamps and normalise aware ones to UTC."""
    if value is None:
        return None
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{field_name} must be timezone-aware UTC")
    return value.astimezone(UTC)


class AssetStatus(StrEnum):
    """Observed liveness of an asset (factual, not a verdict)."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    UNKNOWN = "unknown"


class ObservedService(BaseModel):
    """A listening endpoint observed for an asset (factual metadata only)."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    #: Deterministic identity derived from host, protocol, address and port.
    service_id: str = Field(min_length=1, max_length=128)
    port: int = Field(ge=0, le=65535)
    protocol: TransportProtocol = TransportProtocol.OTHER
    address: str | None = Field(default=None, max_length=64)
    status: str | None = Field(default=None, max_length=32)
    pid: int | None = Field(default=None, ge=0)
    process_name: str | None = Field(default=None, max_length=255)
    first_seen: datetime
    last_seen: datetime
    #: Whether this endpoint was observed before this observation.
    known: bool = False

    @field_validator("first_seen", "last_seen")
    @classmethod
    def _timestamps_are_aware(cls, value: datetime | None, info: Any) -> datetime | None:
        return _ensure_aware_utc(value, info.field_name)

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible mapping."""
        return self.model_dump(mode="json")


class NetworkPeer(BaseModel):
    """A bounded communication relationship observed for an asset."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    #: Deterministic identity derived from host, endpoints, port and protocol.
    peer_id: str = Field(min_length=1, max_length=160)
    host_id: str = Field(min_length=1, max_length=128)
    local_ip: str | None = Field(default=None, max_length=64)
    remote_ip: str = Field(min_length=1, max_length=64)
    remote_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: TransportProtocol = TransportProtocol.OTHER
    direction: NetworkDirection = NetworkDirection.UNKNOWN
    first_seen: datetime
    last_seen: datetime
    flow_count: int = Field(default=0, ge=0)
    packet_count: int = Field(default=0, ge=0)
    byte_count: int = Field(default=0, ge=0)
    #: Whether this relationship was observed before this observation.
    known: bool = False

    @field_validator("first_seen", "last_seen")
    @classmethod
    def _timestamps_are_aware(cls, value: datetime | None, info: Any) -> datetime | None:
        return _ensure_aware_utc(value, info.field_name)

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible mapping."""
        return self.model_dump(mode="json")


class AssetIdentity(BaseModel):
    """A factual identity view of one observed asset."""

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    asset_id: str = Field(min_length=1, max_length=64)
    host_id: str = Field(min_length=1, max_length=128)
    hostname: str | None = Field(default=None, max_length=255)
    ip_addresses: tuple[str, ...] = ()
    interface_count: int = Field(default=0, ge=0)
    os: str | None = Field(default=None, max_length=255)
    platform: Platform = Platform.UNKNOWN
    architecture: str | None = Field(default=None, max_length=64)
    first_seen: datetime
    last_seen: datetime
    status: AssetStatus = AssetStatus.ACTIVE
    observed_services: tuple[ObservedService, ...] = ()

    @field_validator("first_seen", "last_seen")
    @classmethod
    def _timestamps_are_aware(cls, value: datetime | None, info: Any) -> datetime | None:
        return _ensure_aware_utc(value, info.field_name)

    @property
    def observed_ports(self) -> tuple[int, ...]:
        """Distinct observed service ports, sorted."""
        return tuple(sorted({service.port for service in self.observed_services}))

    @property
    def observed_protocols(self) -> tuple[str, ...]:
        """Distinct observed service protocols, sorted."""
        return tuple(sorted({service.protocol.value for service in self.observed_services}))

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible mapping."""
        return self.model_dump(mode="json")


class AssetSnapshot(BaseModel):
    """A point-in-time, read-only view of the observed assets and peers."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    collected_at: datetime
    assets: tuple[AssetIdentity, ...] = ()
    peers: tuple[NetworkPeer, ...] = ()

    @field_validator("collected_at")
    @classmethod
    def _collected_at_is_aware(cls, value: datetime | None, info: Any) -> datetime | None:
        return _ensure_aware_utc(value, info.field_name)

    @property
    def asset_count(self) -> int:
        """Number of observed assets."""
        return len(self.assets)

    @property
    def active_asset_count(self) -> int:
        """Number of assets currently considered active."""
        return sum(1 for asset in self.assets if asset.status is AssetStatus.ACTIVE)

    @property
    def peer_count(self) -> int:
        """Number of observed network peers."""
        return len(self.peers)

    @property
    def new_observation_count(self) -> int:
        """Observations (services + peers) not seen before this observation."""
        services = sum(
            1 for asset in self.assets for service in asset.observed_services if not service.known
        )
        peers = sum(1 for peer in self.peers if not peer.known)
        return services + peers

    def asset_by_id(self, asset_id: str) -> AssetIdentity | None:
        """Return the asset with ``asset_id``, if present."""
        for asset in self.assets:
            if asset.asset_id == asset_id:
                return asset
        return None

    def asset_by_host(self, host_id: str) -> AssetIdentity | None:
        """Return the asset with ``host_id``, if present."""
        for asset in self.assets:
            if asset.host_id == host_id:
                return asset
        return None

    def peers_for_host(self, host_id: str) -> tuple[NetworkPeer, ...]:
        """Return the peers attributed to ``host_id``."""
        return tuple(peer for peer in self.peers if peer.host_id == host_id)

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible mapping."""
        return self.model_dump(mode="json")


__all__ = [
    "AssetIdentity",
    "AssetSnapshot",
    "AssetStatus",
    "NetworkPeer",
    "ObservedService",
]
