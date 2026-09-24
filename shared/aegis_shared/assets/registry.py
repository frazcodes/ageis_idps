"""Bounded, deterministic in-memory asset registry.

The registry merges observations from existing telemetry into per-asset identity
records (host facts, observed services, network peers). It is deterministic,
bounded (oldest ``last_seen`` evicted first) and keeps no payloads, credentials
or attribution.

It is fed by the existing runtime; the desktop only ever reads snapshots.
"""

from __future__ import annotations

import hashlib
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from aegis_shared.assets.config import AssetSettings
from aegis_shared.assets.models import (
    AssetIdentity,
    AssetSnapshot,
    AssetStatus,
    NetworkPeer,
    ObservedService,
)
from aegis_shared.baseline import NetworkBaseline, ObservationKind
from aegis_shared.enums import NetworkDirection, Platform, TransportProtocol


def _digest(payload: str, length: int = 16) -> str:
    return hashlib.sha1(payload.encode(), usedforsecurity=False).hexdigest()[:length]


def _asset_id(host_id: str) -> str:
    return f"ASSET-{_digest(host_id, 12)}"


def _service_id(asset_id: str, protocol: TransportProtocol, address: str | None, port: int) -> str:
    addr = address or "*"
    return f"SVC-{_digest(f'{asset_id}|{protocol.value}|{addr}|{port}')}"


def _peer_id(
    host_id: str,
    local_ip: str | None,
    remote_ip: str,
    remote_port: int | None,
    protocol: TransportProtocol,
) -> str:
    local = local_ip or "*"
    payload = f"{host_id}|{local}|{remote_ip}|{remote_port}|{protocol.value}"
    return f"PEER-{_digest(payload)}"


@dataclass
class _AssetState:
    asset_id: str
    host_id: str
    hostname: str | None = None
    ip_addresses: set[str] = field(default_factory=set)
    interfaces: set[str] = field(default_factory=set)
    os: str | None = None
    platform: Platform = Platform.UNKNOWN
    architecture: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None


@dataclass
class _ServiceState:
    service_id: str
    port: int
    protocol: TransportProtocol
    address: str | None
    status: str | None
    pid: int | None
    process_name: str | None
    first_seen: datetime
    last_seen: datetime
    known: bool = False


@dataclass
class _PeerState:
    peer_id: str
    host_id: str
    local_ip: str | None
    remote_ip: str
    remote_port: int | None
    protocol: TransportProtocol
    direction: NetworkDirection
    first_seen: datetime
    last_seen: datetime
    flow_count: int = 0
    packet_count: int = 0
    byte_count: int = 0
    known: bool = False


class AssetRegistry:
    """Merge telemetry observations into bounded asset/peer identity records."""

    def __init__(self, settings: AssetSettings | None = None) -> None:
        self._settings = settings or AssetSettings()
        self._assets: OrderedDict[str, _AssetState] = OrderedDict()
        self._services: dict[str, OrderedDict[str, _ServiceState]] = {}
        self._peers: OrderedDict[str, _PeerState] = OrderedDict()
        self._flow_totals: OrderedDict[str, tuple[int, int]] = OrderedDict()
        self._baseline = NetworkBaseline(max_entries=self._settings.baseline_max_entries)

    @property
    def settings(self) -> AssetSettings:
        """The settings this registry is bounded by."""
        return self._settings

    @property
    def baseline(self) -> NetworkBaseline:
        """The known-entity baseline this registry updates."""
        return self._baseline

    @property
    def asset_count(self) -> int:
        """Number of assets currently retained."""
        return len(self._assets)

    @property
    def peer_count(self) -> int:
        """Number of peers currently retained."""
        return len(self._peers)

    # ------------------------------------------------------------------
    # Observation
    # ------------------------------------------------------------------

    def observe_host(
        self,
        *,
        host_id: str,
        hostname: str | None = None,
        platform: Platform = Platform.UNKNOWN,
        os: str | None = None,
        architecture: str | None = None,
        ip_addresses: tuple[str, ...] = (),
        timestamp: datetime,
    ) -> str:
        """Create/update the asset for a host and return its ``asset_id``."""
        asset_id = _asset_id(host_id)
        self._baseline.observe(ObservationKind.HOST, host_id, timestamp)

        state = self._assets.get(asset_id)
        if state is None:
            state = _AssetState(asset_id=asset_id, host_id=host_id)
            self._assets[asset_id] = state
        if hostname:
            state.hostname = hostname
        if platform is not Platform.UNKNOWN:
            state.platform = platform
        if os:
            state.os = os
        if architecture:
            state.architecture = architecture
        state.ip_addresses.update(ip for ip in ip_addresses if ip)
        state.first_seen = state.first_seen or timestamp
        state.last_seen = timestamp

        self._baseline.observe(ObservationKind.IP, host_id, timestamp)
        self._assets.move_to_end(asset_id)
        self._evict_assets()
        return asset_id

    def observe_interface(self, asset_id: str, interface: str | None, timestamp: datetime) -> None:
        """Record an observed network interface for an asset."""
        if not interface:
            return
        state = self._assets.get(asset_id)
        if state is None:
            return
        state.interfaces.add(interface)
        state.last_seen = timestamp

    def observe_local_ip(self, asset_id: str, ip: str | None, timestamp: datetime) -> None:
        """Record a local IP observed for an asset (from known direction)."""
        if not ip:
            return
        state = self._assets.get(asset_id)
        if state is None:
            return
        state.ip_addresses.add(ip)
        self._baseline.observe(ObservationKind.IP, ip, timestamp)
        state.last_seen = timestamp

    def observe_service(
        self,
        asset_id: str,
        *,
        port: int,
        protocol: TransportProtocol,
        address: str | None = None,
        status: str | None = None,
        pid: int | None = None,
        process_name: str | None = None,
        timestamp: datetime,
    ) -> None:
        """Create/update an observed listening service for an asset."""
        state = self._assets.get(asset_id)
        if state is None:
            return
        service_id = _service_id(asset_id, protocol, address, port)
        addr = address or "*"
        known = self._baseline.observe(
            ObservationKind.PORT, f"{asset_id}|{protocol.value}|{addr}|{port}", timestamp
        )
        bucket = self._services.setdefault(asset_id, OrderedDict())
        existing = bucket.get(service_id)
        if existing is None:
            bucket[service_id] = _ServiceState(
                service_id=service_id,
                port=port,
                protocol=protocol,
                address=address,
                status=status,
                pid=pid,
                process_name=process_name,
                first_seen=timestamp,
                last_seen=timestamp,
                known=known,
            )
        else:
            existing.last_seen = timestamp
            existing.status = status or existing.status
            existing.pid = pid if pid is not None else existing.pid
            existing.process_name = process_name or existing.process_name
            existing.known = known
        bucket.move_to_end(service_id)
        while len(bucket) > self._settings.max_services_per_asset:
            bucket.popitem(last=False)
        state.last_seen = timestamp

    def observe_peer(
        self,
        asset_id: str,
        *,
        host_id: str,
        remote_ip: str,
        remote_port: int | None = None,
        local_ip: str | None = None,
        protocol: TransportProtocol = TransportProtocol.OTHER,
        direction: NetworkDirection = NetworkDirection.UNKNOWN,
        flow_id: str | None = None,
        packets: int = 0,
        byte_count: int = 0,
        timestamp: datetime,
    ) -> None:
        """Create/update an observed communication peer for an asset."""
        if not remote_ip:
            return
        peer_id = _peer_id(host_id, local_ip, remote_ip, remote_port, protocol)
        known = self._baseline.observe(
            ObservationKind.RELATIONSHIP,
            f"{host_id}|{remote_ip}|{remote_port}|{protocol.value}",
            timestamp,
        )
        self._baseline.observe(ObservationKind.DESTINATION, remote_ip, timestamp)
        if remote_port is not None:
            self._baseline.observe(
                ObservationKind.DESTINATION_PORT,
                f"dst|{host_id}|{protocol.value}|{remote_port}",
                timestamp,
            )
        if local_ip:
            self._baseline.observe(ObservationKind.IP, local_ip, timestamp)

        state = self._peers.get(peer_id)
        if state is None:
            state = _PeerState(
                peer_id=peer_id,
                host_id=host_id,
                local_ip=local_ip,
                remote_ip=remote_ip,
                remote_port=remote_port,
                protocol=protocol,
                direction=direction,
                first_seen=timestamp,
                last_seen=timestamp,
                known=known,
            )
            self._peers[peer_id] = state
        else:
            state.last_seen = timestamp
            state.known = known
            if direction is not NetworkDirection.UNKNOWN:
                state.direction = direction

        self._apply_flow_counters(state, flow_id, packets, byte_count)
        self._peers.move_to_end(peer_id)
        self._evict_peers()

    def _apply_flow_counters(
        self, state: _PeerState, flow_id: str | None, packets: int, byte_count: int
    ) -> None:
        """Add only the delta since the flow was last seen (no double counting)."""
        if not flow_id:
            state.packet_count += max(0, packets)
            state.byte_count += max(0, byte_count)
            return
        previous = self._flow_totals.get(flow_id)
        if previous is None:
            state.flow_count += 1
            delta_packets, delta_bytes = max(0, packets), max(0, byte_count)
        else:
            delta_packets = max(0, packets - previous[0])
            delta_bytes = max(0, byte_count - previous[1])
        state.packet_count += delta_packets
        state.byte_count += delta_bytes
        self._flow_totals[flow_id] = (
            max(packets, previous[0] if previous else 0),
            max(byte_count, previous[1] if previous else 0),
        )
        self._flow_totals.move_to_end(flow_id)
        while len(self._flow_totals) > self._settings.max_tracked_flows:
            self._flow_totals.popitem(last=False)

    # ------------------------------------------------------------------
    # Snapshot
    # ------------------------------------------------------------------

    def snapshot(self, *, reference_time: datetime | None = None) -> AssetSnapshot:
        """Return an immutable, deterministic view of the current state."""
        reference = reference_time or self._latest_seen() or datetime.now(UTC)
        assets = tuple(
            self._build_asset(state, reference) for state in self._assets.values()
        )
        peers = tuple(self._build_peer(state) for state in self._peers.values())
        return AssetSnapshot(collected_at=reference, assets=assets, peers=peers)

    def _latest_seen(self) -> datetime | None:
        candidates = [state.last_seen for state in self._assets.values() if state.last_seen]
        candidates.extend(state.last_seen for state in self._peers.values())
        return max(candidates) if candidates else None

    def _build_asset(self, state: _AssetState, reference: datetime) -> AssetIdentity:
        services = tuple(
            ObservedService(
                service_id=service.service_id,
                port=service.port,
                protocol=service.protocol,
                address=service.address,
                status=service.status,
                pid=service.pid,
                process_name=service.process_name,
                first_seen=service.first_seen,
                last_seen=service.last_seen,
                known=service.known,
            )
            for service in self._services.get(state.asset_id, {}).values()
        )
        first_seen = state.first_seen or reference
        last_seen = state.last_seen or reference
        active = (reference - last_seen) <= timedelta(seconds=self._settings.active_window_seconds)
        return AssetIdentity(
            asset_id=state.asset_id,
            host_id=state.host_id,
            hostname=state.hostname,
            ip_addresses=tuple(sorted(state.ip_addresses)),
            interface_count=len(state.interfaces),
            os=state.os,
            platform=state.platform,
            architecture=state.architecture,
            first_seen=first_seen,
            last_seen=last_seen,
            status=AssetStatus.ACTIVE if active else AssetStatus.INACTIVE,
            observed_services=services,
        )

    @staticmethod
    def _build_peer(state: _PeerState) -> NetworkPeer:
        return NetworkPeer(
            peer_id=state.peer_id,
            host_id=state.host_id,
            local_ip=state.local_ip,
            remote_ip=state.remote_ip,
            remote_port=state.remote_port,
            protocol=state.protocol,
            direction=state.direction,
            first_seen=state.first_seen,
            last_seen=state.last_seen,
            flow_count=state.flow_count,
            packet_count=state.packet_count,
            byte_count=state.byte_count,
            known=state.known,
        )

    # ------------------------------------------------------------------
    # Bounded eviction / reset
    # ------------------------------------------------------------------

    def _evict_assets(self) -> None:
        while len(self._assets) > self._settings.max_assets:
            asset_id, _ = self._assets.popitem(last=False)
            self._services.pop(asset_id, None)

    def _evict_peers(self) -> None:
        while len(self._peers) > self._settings.max_peers:
            self._peers.popitem(last=False)

    def clear(self) -> None:
        """Drop all asset state and baseline memory (runtime stop)."""
        self._assets.clear()
        self._services.clear()
        self._peers.clear()
        self._flow_totals.clear()
        self._baseline.clear()


__all__ = ["AssetRegistry"]
