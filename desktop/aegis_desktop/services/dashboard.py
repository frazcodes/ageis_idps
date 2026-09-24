"""Dashboard adapter: existing Aegis models/configuration -> UI-friendly data.

This layer is strictly read-only. It calls the existing
:func:`aegis_agent.inventory.collect_system_inventory` and reads the existing
agent/network-sensor configuration. It starts no monitor, captures no packet,
changes no configuration and performs no response.

Inventory collection is imported lazily so the console can start (and show a
safe error state) even when the agent's optional dependencies are absent.

Detection and risk data is gathered lazily through existing service modules
(``aegis_desktop.services.detections`` and ``aegis_desktop.services.risk``).
These services import detection/risk engines only at call time, so importing
this module never loads detection or risk subsystems.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from aegis_agent.config import AgentSettings, get_agent_settings
from aegis_desktop.services.assets import AssetPosture, collect_asset_view
from aegis_network_sensor.config import SensorSettings, get_sensor_settings
from aegis_shared.logging import get_logger
from aegis_shared.pipeline import DEFAULT_DEDUP_WINDOW, DEFAULT_MAX_EVENTS

if TYPE_CHECKING:  # pragma: no cover - typing only
    from aegis_agent.inventory import SystemInventory

logger = get_logger(__name__)

#: Non-sensitive message shown when inventory collection fails.
INVENTORY_ERROR = "Unable to collect system information"
UNKNOWN = "Unknown"

_BYTE_UNITS = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")


def format_bytes(value: int | None) -> str:
    """Format a byte count deterministically (e.g. ``7.4 GiB``)."""
    if value is None:
        return UNKNOWN
    size = float(value)
    unit_index = 0
    while size >= 1024 and unit_index < len(_BYTE_UNITS) - 1:
        size /= 1024
        unit_index += 1
    if unit_index == 0:
        return f"{int(size)} {_BYTE_UNITS[unit_index]}"
    return f"{size:.1f} {_BYTE_UNITS[unit_index]}"


def format_timestamp(value: datetime | None) -> str:
    """Format a UTC timestamp deterministically, or ``Unknown``."""
    if value is None:
        return UNKNOWN
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%SZ")


@dataclass(frozen=True)
class InventoryView:
    """Read-only view of the existing system inventory."""

    available: bool
    error: str | None
    hostname: str
    host_id: str
    operating_system: str
    platform: str
    architecture: str
    python_version: str
    agent_version: str
    cpu_count: str
    total_memory: str
    boot_time: str
    collected_at: str


@dataclass(frozen=True)
class MonitorState:
    """Configured state of one monitor (configuration, not runtime)."""

    name: str
    configured_enabled: bool
    runtime: str
    detail: str


@dataclass(frozen=True)
class PipelineView:
    """Read-only view of the in-memory event pipeline configuration."""

    host_buffer_capacity: int
    dedup_window: int
    network_buffer_capacity: int
    state: str


@dataclass(frozen=True)
class PipelinePosture:
    """Runtime state of the in-memory event pipeline."""

    running: bool
    buffered: int
    capacity: int
    accepted: int
    rejected: int
    dropped: int
    duplicates: int


@dataclass(frozen=True)
class DetectionPostureView:
    """Detection engine state surfaced to the dashboard."""

    running: bool
    enabled: bool
    rule_count: int
    finding_count: int


@dataclass(frozen=True)
class RiskPostureView:
    """Risk engine state surfaced to the dashboard."""

    running: bool
    assessment_count: int
    scoring_version: str | None
    latest_score: int | None
    latest_level: str | None


@dataclass(frozen=True)
class ActivityItem:
    """One recent security activity entry for the dashboard feed."""

    timestamp: datetime
    kind: str
    severity: str
    description: str


@dataclass(frozen=True)
class DashboardSnapshot:
    """Everything the dashboard displays, gathered in one read-only pass."""

    collected_at: datetime
    inventory: InventoryView
    monitors: tuple[MonitorState, ...]
    pipeline: PipelineView
    pipeline_posture: PipelinePosture
    event_count: int
    process_count: int
    port_count: int
    detection: DetectionPostureView
    risk: RiskPostureView
    activity: tuple[ActivityItem, ...]
    high_risk_findings: tuple[ActivityItem, ...]
    agent_settings: AgentSettings
    sensor_settings: SensorSettings
    assets: AssetPosture
    alerts_state: str
    risk_state: str


def _default_inventory_collector() -> SystemInventory:
    # Imported lazily so the console does not require the agent extra to start.
    from aegis_agent.inventory import collect_system_inventory

    return collect_system_inventory()


def _inventory_view(collector: Callable[[], SystemInventory]) -> InventoryView:
    try:
        inventory = collector()
    except Exception as exc:
        # Never surface stack traces or details; log non-sensitively.
        logger.warning("System inventory collection failed: %s", exc)
        return InventoryView(
            available=False,
            error=INVENTORY_ERROR,
            hostname=UNKNOWN,
            host_id=UNKNOWN,
            operating_system=UNKNOWN,
            platform=UNKNOWN,
            architecture=UNKNOWN,
            python_version=UNKNOWN,
            agent_version=UNKNOWN,
            cpu_count=UNKNOWN,
            total_memory=UNKNOWN,
            boot_time=UNKNOWN,
            collected_at=UNKNOWN,
        )

    operating_system = f"{inventory.os_name} {inventory.os_version or ''}".strip()
    cpu_count = UNKNOWN if inventory.cpu_count is None else str(inventory.cpu_count)
    return InventoryView(
        available=True,
        error=None,
        hostname=inventory.hostname,
        host_id=inventory.host_id,
        operating_system=operating_system,
        platform=inventory.platform.value,
        architecture=inventory.architecture,
        python_version=inventory.python_version,
        agent_version=inventory.agent_version,
        cpu_count=cpu_count,
        total_memory=format_bytes(inventory.total_memory_bytes),
        boot_time=format_timestamp(inventory.boot_time),
        collected_at=format_timestamp(inventory.collected_at),
    )


def _monitor_states(agent: AgentSettings, sensor: SensorSettings) -> tuple[MonitorState, ...]:
    """Configured monitor states from the existing configuration.

    The runtime string is explicit: GUI-2 never starts a monitor, so nothing is
    reported as running.
    """
    not_running = "not running"
    return (
        MonitorState(
            name="Process Monitoring",
            configured_enabled=agent.enable_process_monitor,
            runtime=not_running,
            detail="Endpoint agent process telemetry",
        ),
        MonitorState(
            name="Port Monitoring",
            configured_enabled=agent.enable_port_monitor,
            runtime=not_running,
            detail="Endpoint agent listening-port telemetry",
        ),
        MonitorState(
            name="File Integrity Monitoring",
            configured_enabled=agent.enable_file_integrity,
            runtime=not_running,
            detail=f"{len(agent.file_integrity_paths)} configured path(s)",
        ),
        MonitorState(
            name="Network Sensor",
            configured_enabled=sensor.capture_enabled,
            runtime=not_running,
            detail=sensor.interface or "no interface configured",
        ),
    )


def _pipeline_view(agent: AgentSettings) -> PipelineView:
    return PipelineView(
        host_buffer_capacity=agent.event_buffer_max_events,
        dedup_window=DEFAULT_DEDUP_WINDOW,
        network_buffer_capacity=DEFAULT_MAX_EVENTS,
        state="Not started (no runtime loop)",
    )


def _pipeline_posture() -> PipelinePosture:
    """Read the active pipeline's runtime posture, if one is running."""
    from aegis_shared.pipeline import get_active_pipeline

    pipeline = get_active_pipeline()
    if pipeline is None:
        return PipelinePosture(
            running=False,
            buffered=0,
            capacity=0,
            accepted=0,
            rejected=0,
            dropped=0,
            duplicates=0,
        )
    stats = pipeline.stats
    return PipelinePosture(
        running=True,
        buffered=stats.buffered,
        capacity=stats.capacity,
        accepted=stats.accepted,
        rejected=stats.rejected,
        dropped=stats.dropped,
        duplicates=stats.duplicates,
    )


def _event_count() -> int:
    """Return the number of events currently buffered in the pipeline."""
    from aegis_shared.pipeline import get_active_pipeline

    pipeline = get_active_pipeline()
    if pipeline is None:
        return 0
    return len(pipeline.peek())


def _process_count() -> int:
    """Return the number of running processes, or 0 if collection fails."""
    try:
        from aegis_desktop.services.processes import collect_process_view

        view = collect_process_view()
        return view.count if view.available else 0
    except Exception:
        return 0


def _port_count() -> int:
    """Return the number of listening endpoints, or 0 if collection fails."""
    try:
        from aegis_desktop.services.network import collect_port_view

        view = collect_port_view()
        return view.count if view.available else 0
    except Exception:
        return 0


def _asset_posture(
    asset_view_provider: Callable[[], object] | None = None,
) -> AssetPosture:
    """Read the observed asset/peer posture (real runtime data only)."""
    try:
        view = asset_view_provider() if asset_view_provider is not None else collect_asset_view()
        return view.posture
    except Exception as exc:
        logger.warning("Dashboard asset collection failed: %s", exc)
        return AssetPosture(running=False, assets=0, active_assets=0, peers=0, new_observations=0)


def _detection_posture() -> DetectionPostureView:
    """Read the detection engine posture from the existing service."""
    try:
        from aegis_desktop.services.detections import collect_finding_view

        view = collect_finding_view()
        posture = view.posture
        return DetectionPostureView(
            running=posture.running,
            enabled=posture.enabled,
            rule_count=posture.rule_count,
            finding_count=posture.findings,
        )
    except Exception:
        return DetectionPostureView(
            running=False,
            enabled=False,
            rule_count=0,
            finding_count=0,
        )


def _risk_posture() -> RiskPostureView:
    """Read the risk engine posture from the existing service."""
    try:
        from aegis_desktop.services.risk import collect_risk_view

        view = collect_risk_view()
        posture = view.posture
        latest_score: int | None = None
        latest_level: str | None = None
        if view.rows:
            latest = view.rows[-1]
            latest_score = latest.risk_score
            latest_level = latest.risk_level
        return RiskPostureView(
            running=posture.running,
            assessment_count=posture.assessments,
            scoring_version=posture.scoring_version,
            latest_score=latest_score,
            latest_level=latest_level,
        )
    except Exception:
        return RiskPostureView(
            running=False,
            assessment_count=0,
            scoring_version=None,
            latest_score=None,
            latest_level=None,
        )


def _recent_activity(
    events_view: object | None,
    findings_view: object | None,
) -> tuple[ActivityItem, ...]:
    """Build a compact recent activity feed from events and findings."""
    items: list[ActivityItem] = []

    if events_view is not None and getattr(events_view, "available", False):
        for row in getattr(events_view, "rows", ()):
            items.append(
                ActivityItem(
                    timestamp=row.timestamp,
                    kind="event",
                    severity=row.severity,
                    description=row.summary[:80] if row.summary else row.event_type,
                )
            )

    if findings_view is not None and getattr(findings_view, "available", False):
        for row in getattr(findings_view, "rows", ()):
            items.append(
                ActivityItem(
                    timestamp=row.timestamp,
                    kind="finding",
                    severity=row.severity,
                    description=row.title,
                )
            )

    items.sort(key=lambda item: item.timestamp, reverse=True)
    return tuple(items[:20])


def _high_risk_findings(findings_view: object | None) -> tuple[ActivityItem, ...]:
    """Extract high/critical severity findings for the dashboard."""
    if findings_view is None or not getattr(findings_view, "available", False):
        return ()
    items: list[ActivityItem] = []
    for row in getattr(findings_view, "rows", ()):
        if row.severity in ("high", "critical"):
            items.append(
                ActivityItem(
                    timestamp=row.timestamp,
                    kind="finding",
                    severity=row.severity,
                    description=f"{row.rule_id}: {row.title}",
                )
            )
    items.sort(key=lambda item: item.timestamp, reverse=True)
    return tuple(items)


def collect_dashboard_snapshot(
    *,
    inventory_collector: Callable[[], SystemInventory] | None = None,
    agent_settings: AgentSettings | None = None,
    sensor_settings: SensorSettings | None = None,
    collected_at: datetime | None = None,
    events_view_provider: Callable[[], object] | None = None,
    findings_view_provider: Callable[[], object] | None = None,
    asset_view_provider: Callable[[], object] | None = None,
) -> DashboardSnapshot:
    """Gather a read-only dashboard snapshot from existing Aegis components.

    Args:
        inventory_collector: Overrides inventory collection (tests inject one).
        agent_settings: Overrides agent configuration.
        sensor_settings: Overrides network-sensor configuration.
        collected_at: Overrides the snapshot timestamp.
        events_view_provider: Overrides event view collection.
        findings_view_provider: Overrides findings view collection.
        asset_view_provider: Overrides asset snapshot collection.
    """
    agent = agent_settings or get_agent_settings()
    sensor = sensor_settings or get_sensor_settings()
    collector = inventory_collector or _default_inventory_collector

    events_view = None
    if events_view_provider is not None:
        try:
            events_view = events_view_provider()
        except Exception as exc:
            logger.warning("Dashboard events collection failed: %s", exc)
    else:
        try:
            from aegis_desktop.services.events import collect_event_view

            events_view = collect_event_view()
        except Exception as exc:
            logger.warning("Dashboard events collection failed: %s", exc)

    findings_view = None
    if findings_view_provider is not None:
        try:
            findings_view = findings_view_provider()
        except Exception as exc:
            logger.warning("Dashboard findings collection failed: %s", exc)
    else:
        try:
            from aegis_desktop.services.detections import collect_finding_view

            findings_view = collect_finding_view()
        except Exception as exc:
            logger.warning("Dashboard findings collection failed: %s", exc)

    return DashboardSnapshot(
        collected_at=collected_at or datetime.now(UTC),
        inventory=_inventory_view(collector),
        monitors=_monitor_states(agent, sensor),
        pipeline=_pipeline_view(agent),
        pipeline_posture=_pipeline_posture(),
        event_count=_event_count(),
        process_count=_process_count(),
        port_count=_port_count(),
        detection=_detection_posture(),
        risk=_risk_posture(),
        activity=_recent_activity(events_view, findings_view),
        high_risk_findings=_high_risk_findings(findings_view),
        agent_settings=agent,
        sensor_settings=sensor,
        assets=_asset_posture(asset_view_provider),
        alerts_state="Not connected",
        risk_state="Not connected",
    )


__all__ = [
    "INVENTORY_ERROR",
    "UNKNOWN",
    "ActivityItem",
    "DashboardSnapshot",
    "DetectionPostureView",
    "InventoryView",
    "MonitorState",
    "PipelinePosture",
    "PipelineView",
    "RiskPostureView",
    "collect_dashboard_snapshot",
    "format_bytes",
    "format_timestamp",
]
