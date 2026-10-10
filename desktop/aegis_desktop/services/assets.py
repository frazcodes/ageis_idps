"""Assets adapter: observed asset/network-identity snapshot -> UI-friendly data.

Strictly read-only. It reads the latest asset snapshot published by the running
runtime through the process-wide registry and shapes it for the Assets page and
the investigation context. No asset is fabricated in the GUI and no monitor,
capture, detection or response is started.

Imports of the shared asset layer are lazy so opening the application loads no
security engine.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

from aegis_shared.logging import get_logger

if TYPE_CHECKING:  # pragma: no cover - typing only
    from aegis_shared.assets import AssetSnapshot

logger = get_logger(__name__)


@dataclass(frozen=True)
class ServiceView:
    """One observed listening service (factual metadata)."""

    port: int
    protocol: str
    address: str | None
    status: str | None
    pid: int | None
    process_name: str | None
    first_seen: datetime
    last_seen: datetime
    known: bool


@dataclass(frozen=True)
class PeerView:
    """One observed network peer relationship."""

    remote_ip: str
    remote_port: int | None
    protocol: str
    direction: str
    first_seen: datetime
    last_seen: datetime
    flow_count: int
    packet_count: int
    byte_count: int
    known: bool


@dataclass(frozen=True)
class AssetRow:
    """One asset, flattened for the table and detail view."""

    asset_id: str
    host_id: str
    hostname: str | None
    ip_addresses: tuple[str, ...]
    status: str
    service_count: int
    peer_count: int
    first_seen: datetime
    last_seen: datetime
    os: str | None = None
    platform: str = "unknown"
    architecture: str | None = None
    interface_count: int = 0
    exposure_grade: str = "A"
    exposure_score: int = 0


@dataclass(frozen=True)
class AssetPosture:
    """Read-only asset/peer posture for the dashboard."""

    running: bool
    assets: int
    active_assets: int
    peers: int
    new_observations: int


@dataclass(frozen=True)
class AssetContext:
    """Compact asset context for the investigation/incident views."""

    host_id: str
    hostname: str | None
    ip_addresses: tuple[str, ...]
    observed_ports: tuple[str, ...]
    known_peers: int
    new_peers: int


@dataclass(frozen=True)
class AssetSnapshotView:
    """Read-only view of the observed assets plus per-asset services/peers."""

    available: bool
    error: str | None
    collected_at: datetime | None
    posture: AssetPosture
    rows: tuple[AssetRow, ...]
    services: dict[str, tuple[ServiceView, ...]] = field(default_factory=dict)
    peers: dict[str, tuple[PeerView, ...]] = field(default_factory=dict)
    contexts: dict[str, AssetContext] = field(default_factory=dict)

    @property
    def count(self) -> int:
        """Number of assets in the view."""
        return len(self.rows)

    def services_for(self, asset_id: str) -> tuple[ServiceView, ...]:
        """Observed services for ``asset_id``."""
        return self.services.get(asset_id, ())

    def peers_for(self, asset_id: str) -> tuple[PeerView, ...]:
        """Observed peers for ``asset_id``."""
        return self.peers.get(asset_id, ())


def _default_snapshot() -> AssetSnapshot | None:
    from aegis_shared.assets import get_active_asset_snapshot

    return get_active_asset_snapshot()


def _empty_view() -> AssetSnapshotView:
    return AssetSnapshotView(
        available=True,
        error=None,
        collected_at=None,
        posture=AssetPosture(False, 0, 0, 0, 0),
        rows=(),
    )


_CRITICAL_PORTS: frozenset[int] = frozenset({
    21, 23, 135, 137, 138, 139, 445, 1433, 3389, 4444, 5555, 6667,
})



def calculate_exposure_grade(
    services: tuple[ServiceView, ...],
    peers: tuple[PeerView, ...],
) -> tuple[str, int]:
    """Calculate deterministic exposure score (0-100) and letter grade (A-F)."""
    score = 0
    port_count = len(services)
    if port_count > 8:
        score += 25
    elif port_count > 4:
        score += 15
    elif port_count > 1:
        score += 5

    for svc in services:
        if svc.port in _CRITICAL_PORTS:
            score += 25
        elif not svc.known:
            score += 10

    if len(peers) > 10:
        score += 20
    elif len(peers) > 5:
        score += 10

    unknown_peers = sum(1 for p in peers if not p.known)
    score += min(unknown_peers * 5, 20)

    score = min(max(score, 0), 100)
    if score < 20:
        grade = "A"
    elif score < 40:
        grade = "B"
    elif score < 60:
        grade = "C"
    elif score < 80:
        grade = "D"
    else:
        grade = "F"
    return grade, score


def collect_asset_view(
    *,
    snapshot_provider: Callable[[], AssetSnapshot | None] | None = None,
) -> AssetSnapshotView:
    """Read the published asset snapshot and translate it for the UI.

    With no runtime publishing, an honest empty view is returned - never
    synthetic assets.
    """
    try:
        snapshot = (snapshot_provider or _default_snapshot)()
    except Exception as exc:
        logger.warning("Reading asset snapshot failed: %s", exc)
        return _empty_view()

    if snapshot is None:
        return _empty_view()

    services: dict[str, tuple[ServiceView, ...]] = {}
    peers: dict[str, tuple[PeerView, ...]] = {}
    contexts: dict[str, AssetContext] = {}
    rows: list[AssetRow] = []

    for asset in snapshot.assets:
        asset_services = tuple(
            ServiceView(
                port=service.port,
                protocol=service.protocol.value,
                address=service.address,
                status=service.status,
                pid=service.pid,
                process_name=service.process_name,
                first_seen=service.first_seen,
                last_seen=service.last_seen,
                known=service.known,
            )
            for service in asset.observed_services
        )
        asset_peers = tuple(
            PeerView(
                remote_ip=peer.remote_ip,
                remote_port=peer.remote_port,
                protocol=peer.protocol.value,
                direction=peer.direction.value,
                first_seen=peer.first_seen,
                last_seen=peer.last_seen,
                flow_count=peer.flow_count,
                packet_count=peer.packet_count,
                byte_count=peer.byte_count,
                known=peer.known,
            )
            for peer in snapshot.peers_for_host(asset.host_id)
        )
        services[asset.asset_id] = asset_services
        peers[asset.asset_id] = asset_peers
        contexts[asset.host_id] = AssetContext(
            host_id=asset.host_id,
            hostname=asset.hostname,
            ip_addresses=tuple(asset.ip_addresses),
            observed_ports=tuple(
                f"{service.port}/{service.protocol.value}" for service in asset.observed_services
            ),
            known_peers=sum(1 for peer in asset_peers if peer.known),
            new_peers=sum(1 for peer in asset_peers if not peer.known),
        )
        grade, exp_score = calculate_exposure_grade(asset_services, asset_peers)
        rows.append(
            AssetRow(
                asset_id=asset.asset_id,
                host_id=asset.host_id,
                hostname=asset.hostname,
                ip_addresses=tuple(asset.ip_addresses),
                status=asset.status.value,
                service_count=len(asset_services),
                peer_count=len(asset_peers),
                first_seen=asset.first_seen,
                last_seen=asset.last_seen,
                os=asset.os,
                platform=asset.platform.value,
                architecture=asset.architecture,
                interface_count=asset.interface_count,
                exposure_grade=grade,
                exposure_score=exp_score,
            )
        )

    return AssetSnapshotView(
        available=True,
        error=None,
        collected_at=snapshot.collected_at,
        posture=AssetPosture(
            running=True,
            assets=snapshot.asset_count,
            active_assets=snapshot.active_asset_count,
            peers=snapshot.peer_count,
            new_observations=snapshot.new_observation_count,
        ),
        rows=tuple(rows),
        services=services,
        peers=peers,
        contexts=contexts,
    )


def asset_context_for_host(
    host_id: str | None,
    *,
    snapshot_provider: Callable[[], AssetSnapshot | None] | None = None,
) -> AssetContext | None:
    """Return the asset context for ``host_id``, or ``None`` when unknown."""
    if not host_id:
        return None
    return collect_asset_view(snapshot_provider=snapshot_provider).contexts.get(host_id)


__all__ = [
    "AssetContext",
    "AssetPosture",
    "AssetRow",
    "AssetSnapshotView",
    "PeerView",
    "ServiceView",
    "asset_context_for_host",
    "calculate_exposure_grade",
    "collect_asset_view",
]
