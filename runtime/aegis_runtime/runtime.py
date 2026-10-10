"""The minimal Aegis runtime: an in-process orchestrator.

Responsibility, and nothing more: **own lifecycle and connect the existing
components**. It does not implement detection rules, risk formulas, collectors,
event schemas, network normalization or response policy - it wires the components
that already do.

Flow::

    enabled host monitors ─┐
                           ├─► RuntimeEventPipeline ─► DetectionEngine ─► RiskEngine
    network sensor ────────┘            │
                                        └─► peek() (desktop observes read-only)

    host telemetry ─► HostBehaviorFeatures ─► HostAnomalyModel ─┐
                                                               ├─► AnomalySignal
    network flows  ─► NetworkBehaviorFeatures ─► NetworkAnomaly ┘        │
                                                                        ▼
                                                       RiskEngine ─► RiskAssessment.anomaly

Design
------
* **Off by default.** Constructing a runtime starts nothing; only :meth:`start`
  transitions to running, and it respects existing configuration.
* **Single-threaded.** ``start()`` / ``poll_once()`` / ``stop()`` are driven by
  the caller. No background threads, no daemons.
* **Non-destructive.** Detection/risk read the pipeline through a monotonic
  *sequence cursor* and never drain it, so the desktop's Events page keeps seeing
  every buffered event via the existing ``peek()`` semantics.
* **Safe producers.** Monitors are started (baseline) before the first poll so
  the runtime does not flood the pipeline with false "new" events. Packet capture
  is only invoked when it is explicitly enabled in configuration.
* **Failure isolation.** A failing producer is logged non-sensitively and
  recorded by name; it never aborts the cycle or corrupts the lifecycle.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, TypeVar

from aegis_agent.config import AgentSettings, get_agent_settings
from aegis_agent.inventory import collect_system_inventory
from aegis_agent.monitors.file_integrity import FileIntegrityMonitor, collector_from_settings
from aegis_agent.monitors.port import PortMonitor
from aegis_agent.monitors.process import ProcessMonitor
from aegis_network_sensor.config import SensorSettings, get_sensor_settings
from aegis_network_sensor.flows.models import FlowRecord
from aegis_runtime.models import NetworkSensorLike, PollResult, RuntimeState
from aegis_runtime.pipeline import RuntimeEventPipeline
from aegis_shared.assets import (
    AssetRegistry,
    AssetSettings,
    get_asset_settings,
    set_active_asset_snapshot,
)
from aegis_shared.baseline import ObservationKind
from aegis_shared.correlation import (
    HostNetworkCorrelator,
    IncidentCorrelator,
    get_correlation_settings,
    set_active_host_network_correlations,
    set_active_incidents,
)
from aegis_shared.detection import (
    DetectionEngine,
    DetectionFinding,
    SuspiciousCommunicationAnalyzer,
    build_behavior_analyzer,
    build_communication_analyzer,
    get_detection_settings,
    set_active_engine,
)
from aegis_shared.detection.communication import (
    CommunicationObservation,
    CommunicationSignal,
    CommunicationSignalType,
)
from aegis_shared.detection.rules import (
    BEHAVIOR_RULE_IDS,
    RULE_IOC_MATCH,
)
from aegis_shared.enums import (
    EventCategory,
    EventType,
    NetworkDirection,
    SourceKind,
    TransportProtocol,
)
from aegis_shared.events import HostRef, SecurityEvent, SourceRef
from aegis_shared.logging import get_logger
from aegis_shared.pipeline import set_active_pipeline
from aegis_shared.risk import (
    AnomalySignal,
    RiskEngine,
    get_risk_settings,
    set_active_anomaly_signals,
    set_active_risk_engine,
)
from aegis_shared.threat_intel import (
    IOCMatcher,
    get_threat_intel_settings,
    matches_to_findings,
    set_active_ioc_matches,
)
from aegis_shared.version import __version__

if TYPE_CHECKING:
    from aegis_agent.inventory import SystemInventory
    from aegis_ml_engine.anomaly.host_model import HostAnomalyModel
    from aegis_ml_engine.anomaly.model import NetworkAnomalyModel
    from aegis_ml_engine.features.host_features import HostBehaviorFeatures
    from aegis_shared.detection import NetworkBehaviorAnalyzer
    from aegis_shared.risk import RiskAssessment
    from aegis_shared.threat_intel import IOCMatch

logger = get_logger(__name__)

_T = TypeVar("_T")

#: Bound on capture error text shown to observers (no stack traces).
_MAX_CAPTURE_ERROR = 300

#: Hard cap on retained recent findings/assessments (bounded memory).
_MAX_RECENT_FINDINGS = 512


def _capture_error_text(exc: Exception) -> str:
    """Return a bounded, single-line reason for a capture failure."""
    message = " ".join(str(exc).split()) or type(exc).__name__
    if len(message) > _MAX_CAPTURE_ERROR:
        message = message[:_MAX_CAPTURE_ERROR]
    return message


def _flow_event_id(flow: FlowRecord) -> str:
    """Deterministic, bounded event id for one flow state (identity + counters)."""
    payload = f"{flow.flow_id}|{flow.packet_count}|{flow.byte_count}".encode()
    digest = hashlib.sha1(payload, usedforsecurity=False).hexdigest()
    return f"flow-{digest[:32]}"


@dataclass(frozen=True)
class _CommSeed:
    """A communication relationship's factual baseline state for one cycle."""

    event_id: str
    event_type: EventType
    category: EventCategory
    timestamp: datetime
    local_ip: str | None
    remote_ip: str
    remote_port: int | None
    protocol: TransportProtocol
    direction: NetworkDirection
    new_relationship: bool
    new_destination: bool
    new_destination_port: bool


def _dedupe_findings(
    findings: tuple[DetectionFinding, ...],
) -> tuple[DetectionFinding, ...]:
    """Return findings with unique ``finding_id``, preserving first-seen order."""
    seen: set[str] = set()
    unique: list[DetectionFinding] = []
    for finding in findings:
        if finding.finding_id in seen:
            continue
        seen.add(finding.finding_id)
        unique.append(finding)
    return tuple(unique)


class AegisRuntime:
    """In-process orchestrator connecting producers, detection and risk."""

    def __init__(
        self,
        *,
        agent_settings: AgentSettings | None = None,
        sensor_settings: SensorSettings | None = None,
        pipeline: RuntimeEventPipeline | None = None,
        detection_engine: DetectionEngine | None = None,
        risk_engine: RiskEngine | None = None,
        process_monitor: ProcessMonitor | None = None,
        port_monitor: PortMonitor | None = None,
        file_monitor: FileIntegrityMonitor | None = None,
        network_sensor: NetworkSensorLike | None = None,
        network_anomaly_model: NetworkAnomalyModel | None = None,
        host_anomaly_model: HostAnomalyModel | None = None,
        host_baseline_min_observations: int | None = None,
        behavior_analyzer: NetworkBehaviorAnalyzer | None = None,
        ioc_matcher: IOCMatcher | None = None,
        asset_settings: AssetSettings | None = None,
        asset_registry: AssetRegistry | None = None,
        communication_analyzer: SuspiciousCommunicationAnalyzer | None = None,
    ) -> None:
        self._agent = agent_settings or get_agent_settings()
        self._sensor_settings = sensor_settings or get_sensor_settings()
        self._pipeline = pipeline or RuntimeEventPipeline(
            max_events=self._agent.event_buffer_max_events
        )
        self._detection = detection_engine or DetectionEngine.from_settings(
            get_detection_settings()
        )
        self._behavior = behavior_analyzer or build_behavior_analyzer(get_detection_settings())
        self._risk = risk_engine or RiskEngine(get_risk_settings())
        self._correlator = IncidentCorrelator(get_correlation_settings())
        self._host_network = HostNetworkCorrelator(get_correlation_settings())
        self._ioc = ioc_matcher or IOCMatcher.from_settings(get_threat_intel_settings())
        self._assets = asset_registry or AssetRegistry(asset_settings or get_asset_settings())
        self._communication = communication_analyzer or build_communication_analyzer(
            get_detection_settings()
        )

        # Producer overrides exist for tests and embedders. Real monitors are
        # constructed lazily in start() so construction has no side effects.
        self._process_override = process_monitor
        self._port_override = port_monitor
        self._file_override = file_monitor
        self._network_override = network_sensor
        self._anomaly_model_override = network_anomaly_model
        self._host_anomaly_model_override = host_anomaly_model
        self._host_baseline_min_override = host_baseline_min_observations

        self._process: ProcessMonitor | None = None
        self._port: PortMonitor | None = None
        self._file: FileIntegrityMonitor | None = None
        self._network: NetworkSensorLike | None = None

        #: Host baseline observations collected this run (in memory only).
        self._host_baseline: list[HostBehaviorFeatures] = []
        #: Latest host anomaly signal for the current run, if any.
        self._host_anomaly_signal: AnomalySignal | None = None
        #: Monitor changes produced by the most recent host poll (for features).
        self._cycle_process_changes: object | None = None
        self._cycle_port_changes: object | None = None
        self._cycle_file_changes: object | None = None
        #: Findings/assessments produced by the most recent cycle (for correlation).
        self._cycle_findings: tuple[DetectionFinding, ...] = ()
        self._cycle_assessments: tuple[RiskAssessment, ...] = ()
        #: Bounded recent window of findings/assessments (for host<->network
        #: correlation and incident grouping across cycles). No history is kept
        #: beyond the configured window and the hard cap.
        self._recent_findings: list[DetectionFinding] = []
        self._recent_assessments: list[RiskAssessment] = []
        #: Network capture status for read-only observers (desktop).
        self._network_capture_attempted: bool = False
        self._network_capture_error: str | None = None
        #: Full system inventory for the local host (asset identity facts).
        self._inventory: SystemInventory | None = None
        #: Cached port snapshot for the current cycle (one probe per cycle).
        self._cycle_port_snapshot: object | None = None

        self._state = RuntimeState.STOPPED
        self._source = SourceRef(kind=SourceKind.AGENT, id="runtime", version=__version__)
        self._host = self._resolve_host_ref()
        #: Highest pipeline sequence already processed by detection/risk.
        self._cursor = 0

    # -- Properties --------------------------------------------------------

    @property
    def state(self) -> RuntimeState:
        """Current lifecycle state."""
        return self._state

    @property
    def is_running(self) -> bool:
        """Whether the runtime is started."""
        return self._state is RuntimeState.RUNNING

    @property
    def pipeline(self) -> RuntimeEventPipeline:
        """The runtime's unified event pipeline."""
        return self._pipeline

    @property
    def detection_engine(self) -> DetectionEngine:
        """The runtime's detection engine."""
        return self._detection

    @property
    def risk_engine(self) -> RiskEngine:
        """The runtime's risk engine."""
        return self._risk

    @property
    def network_anomaly_model(self) -> NetworkAnomalyModel | None:
        """The optional network anomaly model, or ``None`` when ML is disabled."""
        return self._anomaly_model_override

    @property
    def host_anomaly_model(self) -> HostAnomalyModel | None:
        """The optional host anomaly model, or ``None`` when host ML is disabled."""
        return self._host_anomaly_model_override

    @property
    def host_baseline_size(self) -> int:
        """Number of host baseline observations collected so far this run."""
        return len(self._host_baseline)

    @property
    def network_sensor(self) -> NetworkSensorLike | None:
        """The active network sensor, or ``None`` when capture is not configured."""
        return self._network

    @property
    def network_interface(self) -> str | None:
        """The configured capture interface, or ``None`` when none is set."""
        interface = self._sensor_settings.interface.strip()
        return interface or None

    @property
    def network_capture_state(self) -> str:
        """Current capture state: ``inactive``, ``active`` or ``error``.

        Honest by construction: ``active`` is only reported once a capture has
        actually run without error, so a failed capture is never shown as running.
        """
        if self._network is None:
            return "inactive"
        if self._network_capture_error is not None:
            return "error"
        if self._network_capture_attempted:
            return "active"
        return "inactive"

    @property
    def network_capture_error(self) -> str | None:
        """The most recent capture error text, or ``None`` when none occurred."""
        return self._network_capture_error

    @property
    def network_flows(self) -> tuple[FlowRecord, ...]:
        """Snapshot of flows tracked by the network sensor (metadata only)."""
        if self._network is None:
            return ()
        flows = getattr(self._network, "flows", None)
        if flows is None:
            return ()
        try:
            return tuple(flows)
        except Exception:  # pragma: no cover - defensive
            return ()

    @property
    def network_flow_count(self) -> int:
        """Number of flows currently tracked by the network sensor."""
        if self._network is None:
            return 0
        aggregator = getattr(self._network, "flow_aggregator", None)
        count = getattr(aggregator, "flow_count", None)
        if isinstance(count, int):
            return count
        return len(self.network_flows)

    # -- Lifecycle ---------------------------------------------------------

    def start(self) -> None:
        """Start the runtime.

        Idempotent: calling it while running is a no-op. Creates the configured
        monitors, establishes their baselines, publishes the pipeline and engines
        to the existing registries, and marks the runtime running. It never starts
        packet capture unless it is enabled in configuration.
        """
        if self._state is RuntimeState.RUNNING:
            return

        self._prepare_monitors()

        set_active_pipeline(self._pipeline)
        set_active_engine(self._detection)
        set_active_risk_engine(self._risk)
        set_active_anomaly_signals(None)
        set_active_incidents(None)
        set_active_host_network_correlations(None)
        set_active_ioc_matches(None)
        set_active_asset_snapshot(None)

        self._host_baseline = []
        self._host_anomaly_signal = None
        self._network_capture_attempted = False
        self._network_capture_error = None
        self._recent_findings = []
        self._recent_assessments = []
        self._assets.clear()
        self._cycle_port_snapshot = None
        self._cursor = 0
        self._state = RuntimeState.RUNNING
        logger.info(
            "Aegis runtime started (monitors: %s)",
            ", ".join(self._agent.enabled_monitors) or "none",
        )

    def stop(self) -> None:
        """Stop the runtime and clear the registries.

        Idempotent and safe to call repeatedly. Monitors are stopped (baselines
        dropped) and the published pipeline/engines are cleared, leaving observers
        in the honest "Not running" state.
        """
        if self._state is RuntimeState.STOPPED and not self._any_registry_published():
            return

        for monitor in (self._process, self._port, self._file):
            if monitor is not None:
                monitor.stop()
        self._process = self._port = self._file = None
        self._network = None

        set_active_pipeline(None)
        set_active_engine(None)
        set_active_risk_engine(None)
        set_active_anomaly_signals(None)
        set_active_incidents(None)
        set_active_host_network_correlations(None)
        set_active_ioc_matches(None)
        set_active_asset_snapshot(None)

        self._host_baseline = []
        self._host_anomaly_signal = None
        self._network_capture_attempted = False
        self._network_capture_error = None
        self._recent_findings = []
        self._recent_assessments = []
        self._assets.clear()
        self._cycle_port_snapshot = None
        self._cursor = 0
        self._state = RuntimeState.STOPPED
        logger.info("Aegis runtime stopped")

    # -- Polling -----------------------------------------------------------

    def poll_once(self) -> PollResult:
        """Run one bounded cycle.

        Polls enabled host monitors, optionally runs one bounded network capture
        when configured, then evaluates detection and risk over the events that
        are newly buffered. Events are never drained: detection/risk advance an
        internal sequence cursor so the pipeline stays inspectable.

        When a fitted :attr:`network_anomaly_model` is available, network flow
        events are scored for behavioural anomaly before risk assessment. When a
        :attr:`host_anomaly_model` is configured, host telemetry is first
        collected into an in-memory baseline and the model is fitted once the
        baseline minimum is met; subsequent cycles score host behavior and attach
        the signal to host events. Failures are isolated and never abort the
        cycle.

        Returns a :class:`PollResult`; before :meth:`start` it returns an empty
        result without doing any work.
        """
        if self._state is not RuntimeState.RUNNING:
            return PollResult()

        errors: list[str] = []

        self._cycle_port_snapshot = None

        host_events = self._poll_host_monitors(errors)
        network_events = self._poll_network_sensor(errors)

        envelopes = self._pipeline.peek()
        new_envelopes = [env for env in envelopes if env.sequence >= self._cursor]
        if new_envelopes:
            self._cursor = new_envelopes[-1].sequence + 1

        events = [env.event for env in new_envelopes]

        # Asset / network-identity context from existing telemetry (best-effort).
        # Capture the pre-update baseline state for multi-signal analysis first.
        comm_seeds = self._communication_seeds(events)
        self._update_assets(events, errors)

        # Score network flows and host behavior for behavioural anomaly
        # (best-effort; never aborts the cycle).
        anomaly_signals = self._score_network_flows(events, errors)
        host_signal = self._update_host_behavior(errors)
        if host_signal is not None:
            for event in events:
                if event.category is EventCategory.HOST:
                    anomaly_signals[event.event_id] = host_signal

        # Publish the latest signals for read-only observers (desktop) without
        # creating a second event store.
        set_active_anomaly_signals(anomaly_signals or None)

        # Behavioral network detection over a bounded window of flow events.
        behavior_findings = self._behavior_findings(events)

        # Threat-intelligence context: match observables against local indicators.
        # Matches are published for observers and become findings so they enter the
        # existing RiskEngine / correlation path (no second scoring system).
        ioc_matches = self._ioc_matches(events, errors)
        ioc_findings = matches_to_findings(ioc_matches)

        findings, assessments = self._detect_and_assess(
            events, errors, anomaly_signals, behavior_findings, ioc_findings, comm_seeds
        )

        # Correlate related findings/assessments into incidents (additional,
        # best-effort layer; never changes detection or risk behaviour).
        self._correlate(events, errors)

        return PollResult(
            host_events=host_events,
            network_events=network_events,
            submitted=host_events + network_events,
            findings=findings,
            assessments=assessments,
            errors=tuple(errors),
        )

    # -- Producer steps ----------------------------------------------------

    def _poll_host_monitors(self, errors: list[str]) -> int:
        process_changes = None
        port_changes = None
        file_changes = None

        if self._process is not None:
            process_changes = self._guard("process", self._process.poll, errors)
        if self._port is not None:
            port_changes = self._guard("port", self._port.poll, errors)
        if self._file is not None:
            file_changes = self._guard("file_integrity", self._file.poll, errors)

        # Retain this cycle's changes so host feature extraction can reuse them
        # (the monitors advance their baselines on poll, so they cannot be
        # re-requested).
        self._cycle_process_changes = process_changes
        self._cycle_port_changes = port_changes
        self._cycle_file_changes = file_changes

        if process_changes is None and port_changes is None and file_changes is None:
            return 0

        try:
            results = self._pipeline.submit_monitor_changes(
                source=self._source,
                host=self._host,
                process_changes=process_changes,
                port_changes=port_changes,
                file_changes=file_changes,
            )
        except Exception as exc:
            self._record("pipeline", exc, errors)
            return 0
        return sum(1 for result in results if result.accepted)

    def _poll_network_sensor(self, errors: list[str]) -> int:
        if self._network is None:
            return 0

        before = len(self._pipeline)
        self._network_capture_attempted = True
        try:
            self._network.capture()
        except Exception as exc:
            # Keep the real reason for the desktop, bounded and non-stack-trace.
            self._network_capture_error = _capture_error_text(exc)
            self._record("network_sensor", exc, errors)
            return 0
        self._network_capture_error = None

        # The sensor owns its own pipeline; move its new events into the unified
        # runtime pipeline for a single detection/risk stream.
        self._drain_sensor_into_pipeline()
        return max(0, len(self._pipeline) - before)

    def _drain_sensor_into_pipeline(self) -> None:
        drain = getattr(self._network, "drain", None)
        if callable(drain):
            try:
                envelopes = drain()
            except Exception as exc:  # pragma: no cover - defensive
                self._record("network_sensor", exc, [])
            else:
                self._pipeline.submit_all(envelope.event for envelope in envelopes)
        # Also surface aggregated flows as canonical flow-summary events so the
        # existing network detection rules and network anomaly model run on real
        # flow telemetry (FlowRecord -> Network Event -> pipeline).
        self._submit_flow_events()

    def _submit_flow_events(self) -> None:
        """Submit flow-summary events only for flows that changed this cycle.

        Uses the flow aggregator's ``drain_changed()`` to avoid re-emitting
        events for flows that received no new packets.  The event id is derived
        from the flow's identity and counters, so an unchanged flow is
        deduplicated by the pipeline while an updated flow produces exactly one
        new event.  Bounded by the flow aggregator's cap.
        """
        aggregator = None
        if self._network is not None:
            aggregator = getattr(self._network, "flow_aggregator", None)
        drain = getattr(aggregator, "drain_changed", None) if aggregator else None
        changed = drain() if callable(drain) else self.network_flows
        if not changed:
            return
        try:
            from aegis_network_sensor.flows.events import build_flow_event

            source = getattr(self._network, "source_ref", None)
            source_ref = source() if callable(source) else self._source
            events = []
            for flow in changed:
                event = build_flow_event(flow, source=source_ref, host=self._host)
                events.append(event.model_copy(update={"event_id": _flow_event_id(flow)}))
            self._pipeline.submit_all(events)
        except Exception as exc:
            self._record("network_flow_events", exc, [])

    def _score_network_flows(
        self, events: list[SecurityEvent], errors: list[str]
    ) -> dict[str, AnomalySignal]:
        """Score network flow events for behavioural anomaly (best-effort).

        Returns a mapping of ``event_id -> AnomalySignal`` for the events that
        carried sufficient flow volume context and were scored.  When no model is
        configured, or it has not been fitted, an empty mapping is returned and no
        anomaly is invented.  A failure in scoring is recorded and never aborts
        the cycle.
        """
        model = self._anomaly_model_override
        if model is None or not getattr(model, "is_fitted", False):
            return {}

        scored: list[tuple[str, FlowRecord]] = []
        for event in events:
            flow = self._flow_from_event(event)
            if flow is not None:
                scored.append((event.event_id, flow))
        if not scored:
            return {}

        try:
            from aegis_ml_engine.anomaly.model import anomaly_to_signal
            from aegis_ml_engine.features.flow_features import extract_flow_features

            features = [extract_flow_features(flow) for _, flow in scored]
            results = model.score_many(features)
        except Exception as exc:
            self._record("network_anomaly", exc, errors)
            return {}

        return {
            event_id: anomaly_to_signal(result)
            for (event_id, _), result in zip(scored, results, strict=True)
        }

    @staticmethod
    def _flow_from_event(event: SecurityEvent) -> FlowRecord | None:
        """Reconstruct a :class:`FlowRecord` from a network flow event.

        Returns ``None`` when the event is not a scored flow (no network context,
        no ``flow_id``, or missing volume counters).  This is the inverse of the
        sensor's ``build_flow_event`` and reuses the existing flow model rather
        than introducing a second feature representation.
        """
        net = event.network
        if net is None or not net.flow_id:
            return None
        if net.packets_sent is None or net.bytes_sent is None or net.duration_ms is None:
            return None

        ports_applicable = net.protocol in (TransportProtocol.TCP, TransportProtocol.UDP)
        try:
            return FlowRecord(
                flow_id=net.flow_id,
                ip_version=net.ip_version,
                protocol=net.protocol,
                src_ip=net.src_ip,
                dst_ip=net.dst_ip,
                ports_applicable=ports_applicable,
                src_port=net.src_port if ports_applicable else None,
                dst_port=net.dst_port if ports_applicable else None,
                direction=net.direction,
                interface=net.interface,
                packet_count=net.packets_sent,
                byte_count=net.bytes_sent,
                first_seen=event.timestamp,
                last_seen=event.timestamp + timedelta(milliseconds=net.duration_ms),
            )
        except Exception:
            return None

    def _host_min_observations(self) -> int:
        """Minimum baseline observations before the host model is fitted."""
        if self._host_baseline_min_override is not None:
            return max(2, self._host_baseline_min_override)
        try:
            from aegis_ml_engine.config import get_ml_settings

            return get_ml_settings().host_baseline_min_observations
        except Exception:  # pragma: no cover - defensive
            return 20

    def _host_observation(self, errors: list[str]) -> HostBehaviorFeatures | None:
        """Build a host feature observation from this cycle's telemetry.

        Uses the changes already collected by :meth:`_poll_host_monitors` and,
        when available, a fresh snapshot from each monitor for current-state
        counts. Returns ``None`` only when feature extraction fails (recorded and
        isolated); an all-zero observation is valid.
        """
        try:
            from aegis_ml_engine.features.host_features import extract_host_features

            process_snapshot = self._snapshot_of(self._process, "process", errors)
            port_snapshot = self._port_snapshot(errors)
            return extract_host_features(
                host_id=self._host.host_id,
                process_snapshot=process_snapshot,
                port_snapshot=port_snapshot,
                process_changes=self._cycle_process_changes,  # type: ignore[arg-type]
                port_changes=self._cycle_port_changes,  # type: ignore[arg-type]
                file_changes=self._cycle_file_changes,  # type: ignore[arg-type]
            )
        except Exception as exc:
            self._record("host_features", exc, errors)
            return None

    @staticmethod
    def _snapshot_of(monitor: object, name: str, errors: list[str]) -> Any:
        """Best-effort current snapshot from a monitor (may be unsupported)."""
        if monitor is None:
            return None
        baseline = getattr(monitor, "_baseline", None)
        if baseline is not None:
            return baseline
        snapshot = getattr(monitor, "snapshot", None)
        if not callable(snapshot):
            return None
        return AegisRuntime._guard(name, snapshot, errors)

    def _port_snapshot(self, errors: list[str]) -> Any:
        """Return the cycle's port snapshot, probing at most once per cycle."""
        if self._cycle_port_snapshot is not None:
            return self._cycle_port_snapshot
        self._cycle_port_snapshot = self._snapshot_of(self._port, "port", errors)
        return self._cycle_port_snapshot

    def _update_assets(self, events: list[SecurityEvent], errors: list[str]) -> None:
        """Update assets/peers from this cycle's existing telemetry (best-effort).

        Uses the existing host inventory/host ref, the existing port monitor
        snapshot and the existing aggregated flows. Publishes a read-only
        snapshot for the desktop. Never stores payloads and never blocks.
        """
        if not self._assets.settings.enabled:
            set_active_asset_snapshot(None)
            return
        try:
            timestamp = self._asset_timestamp(events)
            inventory = self._inventory
            asset_id = self._assets.observe_host(
                host_id=self._host.host_id,
                hostname=self._host.hostname,
                platform=self._host.platform,
                os=(
                    f"{inventory.os_name} {inventory.os_version or ''}".strip()
                    if inventory is not None
                    else None
                ),
                architecture=inventory.architecture if inventory is not None else None,
                ip_addresses=tuple(self._host.ip_addresses),
                timestamp=timestamp,
            )
            self._observe_services(asset_id, timestamp, errors)
            self._observe_network_identity(asset_id, events, timestamp)
            set_active_asset_snapshot(self._assets.snapshot())
        except Exception as exc:
            self._record("assets", exc, errors)

    @staticmethod
    def _asset_timestamp(events: list[SecurityEvent]) -> datetime:
        """Use the newest observed event time, else now (deterministic given input)."""
        if events:
            return max(event.timestamp for event in events)
        return datetime.now(UTC)

    def _observe_services(self, asset_id: str, timestamp: datetime, errors: list[str]) -> None:
        """Record currently-listening endpoints from the existing port monitor."""
        snapshot = self._port_snapshot(errors)
        ports = getattr(snapshot, "ports", None)
        if not ports:
            return
        for record in ports:
            self._assets.observe_service(
                asset_id,
                port=record.local_port,
                protocol=record.protocol,
                address=record.local_address,
                status=record.status,
                pid=record.pid,
                process_name=record.process_name,
                timestamp=timestamp,
            )

    def _observe_network_identity(
        self, asset_id: str, events: list[SecurityEvent], timestamp: datetime
    ) -> None:
        """Record observed interfaces and peers from existing network telemetry."""
        local_ips = set(self._sensor_settings.local_addresses)
        for event in events:
            network = event.network
            if network is None:
                continue
            self._assets.observe_interface(asset_id, network.interface, timestamp)
            if network.direction is NetworkDirection.OUTBOUND and network.src_ip:
                local_ips.add(network.src_ip)
                self._assets.observe_local_ip(asset_id, network.src_ip, timestamp)
            elif network.direction is NetworkDirection.INBOUND and network.dst_ip:
                local_ips.add(network.dst_ip)
                self._assets.observe_local_ip(asset_id, network.dst_ip, timestamp)

        for flow in self.network_flows:
            endpoints = self._peer_endpoints(flow, local_ips)
            if endpoints is None:
                continue
            local_ip, remote_ip, remote_port = endpoints
            self._assets.observe_peer(
                asset_id,
                host_id=self._host.host_id,
                remote_ip=remote_ip,
                remote_port=remote_port,
                local_ip=local_ip,
                protocol=flow.protocol,
                direction=flow.direction,
                flow_id=flow.flow_id,
                packets=flow.packet_count,
                byte_count=flow.byte_count,
                timestamp=timestamp,
            )

    @staticmethod
    def _peer_endpoints(
        flow: FlowRecord, local_ips: set[str]
    ) -> tuple[str | None, str, int | None] | None:
        """Resolve ``(local_ip, remote_ip, remote_port)`` or ``None`` when unknown.

        Only returns a relationship when the direction is determinable, so no
        local/remote assignment is invented.
        """
        if flow.direction is NetworkDirection.OUTBOUND and flow.dst_ip:
            return flow.src_ip, flow.dst_ip, flow.dst_port
        if flow.direction is NetworkDirection.INBOUND and flow.src_ip:
            return flow.dst_ip, flow.src_ip, flow.src_port
        if flow.src_ip in local_ips and flow.dst_ip:
            return flow.src_ip, flow.dst_ip, flow.dst_port
        if flow.dst_ip in local_ips and flow.src_ip:
            return flow.dst_ip, flow.src_ip, flow.src_port
        return None

    @staticmethod
    def _resolve_context_endpoints(
        network: object, local_ips: set[str]
    ) -> tuple[str | None, str, int | None] | None:
        """Resolve ``(local_ip, remote_ip, remote_port)`` from a network context."""
        direction = getattr(network, "direction", NetworkDirection.UNKNOWN)
        src_ip = getattr(network, "src_ip", None)
        dst_ip = getattr(network, "dst_ip", None)
        src_port = getattr(network, "src_port", None)
        dst_port = getattr(network, "dst_port", None)
        if direction is NetworkDirection.OUTBOUND and dst_ip:
            return src_ip, dst_ip, dst_port
        if direction is NetworkDirection.INBOUND and src_ip:
            return dst_ip, src_ip, src_port
        if src_ip in local_ips and dst_ip:
            return src_ip, dst_ip, dst_port
        if dst_ip in local_ips and src_ip:
            return dst_ip, src_ip, src_port
        return None

    def _communication_seeds(self, events: list[SecurityEvent]) -> tuple[_CommSeed, ...]:
        """Capture each flow's factual baseline state before it is updated.

        Read-only against the bounded baseline: it answers "was this relationship /
        destination / destination port seen before?" without mutating state.
        """
        baseline = self._assets.baseline
        host_id = self._host.host_id
        local_ips = set(self._sensor_settings.local_addresses)
        seeds: list[_CommSeed] = []
        for event in events:
            if event.event_type is not EventType.FLOW_SUMMARY:
                continue
            network = event.network
            if network is None:
                continue
            resolved = self._resolve_context_endpoints(network, local_ips)
            if resolved is None:
                continue
            local_ip, remote_ip, remote_port = resolved
            protocol = network.protocol
            new_relationship = not baseline.is_known(
                ObservationKind.RELATIONSHIP,
                f"{host_id}|{remote_ip}|{remote_port}|{protocol.value}",
            )
            new_destination = not baseline.is_known(ObservationKind.DESTINATION, remote_ip)
            new_destination_port = remote_port is not None and not baseline.is_known(
                ObservationKind.DESTINATION_PORT,
                f"dst|{host_id}|{protocol.value}|{remote_port}",
            )
            seeds.append(
                _CommSeed(
                    event_id=event.event_id,
                    event_type=event.event_type,
                    category=event.category,
                    timestamp=event.timestamp,
                    local_ip=local_ip,
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    protocol=protocol,
                    direction=network.direction,
                    new_relationship=new_relationship,
                    new_destination=new_destination,
                    new_destination_port=new_destination_port,
                )
            )
        return tuple(seeds)

    def _communication_findings(
        self,
        seeds: tuple[_CommSeed, ...],
        findings: tuple[DetectionFinding, ...],
        anomaly_signals: dict[str, AnomalySignal] | None,
    ) -> tuple[DetectionFinding, ...]:
        """Combine factual signals into AEGIS-NET-007 findings (best-effort)."""
        if not seeds:
            return ()
        host_id = self._host.host_id
        host_finding_ids = tuple(
            sorted(
                finding.finding_id
                for finding in findings
                if finding.host_id == host_id and finding.category is EventCategory.HOST
            )
        )
        behavioral_ids = tuple(
            sorted(
                finding.finding_id
                for finding in findings
                if finding.host_id == host_id and finding.rule_id in BEHAVIOR_RULE_IDS
            )
        )
        ioc_event_ids = {
            finding.event_id for finding in findings if finding.rule_id == RULE_IOC_MATCH
        }
        anomalies = anomaly_signals or {}
        related = tuple(sorted({*host_finding_ids, *behavioral_ids}))

        observations: list[CommunicationObservation] = []
        for seed in seeds:
            signals: list[CommunicationSignal] = []
            if seed.new_relationship:
                signals.append(
                    CommunicationSignal(
                        CommunicationSignalType.NEW_RELATIONSHIP,
                        "baseline",
                        True,
                        "New network relationship observed",
                    )
                )
            if seed.new_destination:
                signals.append(
                    CommunicationSignal(
                        CommunicationSignalType.NEW_DESTINATION,
                        "baseline",
                        True,
                        "New destination observed",
                    )
                )
            if seed.new_destination_port:
                signals.append(
                    CommunicationSignal(
                        CommunicationSignalType.NEW_DESTINATION_PORT,
                        "baseline",
                        True,
                        "New destination port observed",
                    )
                )
            if seed.event_id in anomalies:
                signals.append(
                    CommunicationSignal(
                        CommunicationSignalType.NETWORK_ANOMALY,
                        "network_anomaly_model",
                        True,
                        "Network anomaly signal present",
                    )
                )
            if host_finding_ids:
                signals.append(
                    CommunicationSignal(
                        CommunicationSignalType.HOST_EVIDENCE,
                        "detection",
                        True,
                        "Existing host-side finding present",
                    )
                )
            if behavioral_ids:
                signals.append(
                    CommunicationSignal(
                        CommunicationSignalType.BEHAVIORAL,
                        "network_behavior",
                        True,
                        "Existing network behavioral finding present",
                    )
                )
            if seed.event_id in ioc_event_ids:
                signals.append(
                    CommunicationSignal(
                        CommunicationSignalType.IOC_MATCH,
                        "threat_intel",
                        True,
                        "IOC match present",
                    )
                )
            observations.append(
                CommunicationObservation(
                    host_id=host_id,
                    event_id=seed.event_id,
                    event_type=seed.event_type,
                    category=seed.category,
                    timestamp=seed.timestamp,
                    local_ip=seed.local_ip,
                    remote_ip=seed.remote_ip,
                    remote_port=seed.remote_port,
                    protocol=seed.protocol,
                    direction=seed.direction,
                    signals=tuple(signals),
                    related_finding_ids=related,
                )
            )
        try:
            return self._communication.analyze(observations)
        except Exception as exc:
            self._record("communication", exc, [])
            return ()

    def _update_host_behavior(self, errors: list[str]) -> AnomalySignal | None:
        """Collect baseline then score host behavior once the model is fitted.

        Returns the host :class:`AnomalySignal` for this cycle when a fitted host
        model is available, otherwise ``None``. Never invents an anomaly and
        never fits on a single observation.
        """
        model = self._host_anomaly_model_override
        if model is None:
            return None

        observation = self._host_observation(errors)
        if observation is None:
            return None

        if not getattr(model, "is_fitted", False):
            # Baseline collection phase: accumulate, then fit when ready.
            self._host_baseline.append(observation)
            if len(self._host_baseline) >= self._host_min_observations():
                try:
                    model.fit(tuple(self._host_baseline))
                except Exception as exc:
                    self._record("host_anomaly", exc, errors)
                    return None
                logger.info(
                    "Host anomaly model fitted on %d baseline observations",
                    len(self._host_baseline),
                )
            self._host_anomaly_signal = None
            return None

        try:
            from aegis_ml_engine.anomaly.host_model import host_anomaly_to_signal

            result = model.score(observation)
            signal = host_anomaly_to_signal(result)
        except Exception as exc:
            self._record("host_anomaly", exc, errors)
            return None

        self._host_anomaly_signal = signal
        return signal

    def _behavior_findings(self, events: list[SecurityEvent]) -> tuple[DetectionFinding, ...]:
        """Evaluate behavioral network rules over the bounded flow window.

        Runs only when the analyzer is configured and the cycle produced a new
        flow-summary event. The window is the bounded event pipeline buffer (the
        only window state), so this is deterministic, bounded and needs no reset
        beyond the buffer being cleared on stop.
        """
        if not self._behavior.configured:
            return ()
        if not any(event.event_type is EventType.FLOW_SUMMARY for event in events):
            return ()
        try:
            buffered = [envelope.event for envelope in self._pipeline.peek()]
            return self._behavior.evaluate(buffered)
        except Exception as exc:
            self._record("network_behavior", exc, [])
            return ()

    def _ioc_matches(
        self, events: list[SecurityEvent], errors: list[str]
    ) -> tuple[IOCMatch, ...]:
        """Match event observables against local indicators (best-effort).

        Publishes the current matches for read-only observers. Bounded to the
        cycle's events; never performs I/O or network requests.
        """
        if not self._ioc.enabled:
            set_active_ioc_matches(None)
            return ()
        try:
            matches = self._ioc.match_events(events)
        except Exception as exc:
            self._record("threat_intel", exc, errors)
            return ()
        set_active_ioc_matches(matches or None)
        return matches

    def _detect_and_assess(
        self,
        events: list[SecurityEvent],
        errors: list[str],
        anomaly_signals: dict[str, AnomalySignal] | None = None,
        behavior_findings: tuple[DetectionFinding, ...] = (),
        ioc_findings: tuple[DetectionFinding, ...] = (),
        comm_seeds: tuple[_CommSeed, ...] = (),
    ) -> tuple[int, int]:
        if not events:
            self._cycle_findings = ()
            self._cycle_assessments = ()
            return 0, 0

        try:
            findings: tuple[DetectionFinding, ...] = self._detection.evaluate_many(events)
        except Exception as exc:
            self._record("detection", exc, errors)
            self._cycle_findings = ()
            self._cycle_assessments = ()
            return 0, 0

        findings = _dedupe_findings((*findings, *behavior_findings, *ioc_findings))

        # Multi-signal suspicious-communication analysis over existing evidence.
        comm_findings = self._communication_findings(comm_seeds, findings, anomaly_signals)
        if comm_findings:
            findings = _dedupe_findings((*findings, *comm_findings))

        by_event: dict[str, list[DetectionFinding]] = {}
        for finding in findings:
            by_event.setdefault(finding.event_id, []).append(finding)

        items = [(event, tuple(by_event.get(event.event_id, ()))) for event in events]
        try:
            assessments = self._risk.assess_many(items, anomaly_signals=anomaly_signals)
        except Exception as exc:
            self._record("risk", exc, errors)
            self._cycle_findings = findings
            self._cycle_assessments = ()
            return len(findings), 0

        self._cycle_findings = findings
        self._cycle_assessments = assessments
        return len(findings), len(assessments)

    def _correlate(self, events: list[SecurityEvent], errors: list[str]) -> None:
        """Correlate recent findings/assessments and publish the results.

        Accumulates this cycle's findings into a bounded recent window, then
        computes (a) host<->network evidence correlations and (b) incidents, both
        over that window. Best-effort and additive: a failure is recorded and
        never aborts the cycle. Only real, related findings are correlated.
        """
        try:
            self._accumulate_recent()
            host_network = self._host_network.correlate(self._recent_findings)
            incidents = self._correlator.correlate(
                events, self._recent_findings, self._recent_assessments
            )
        except Exception as exc:
            self._record("correlation", exc, errors)
            return
        set_active_host_network_correlations(host_network or None)
        set_active_incidents(incidents)

    def _accumulate_recent(self) -> None:
        """Extend and prune the bounded recent findings/assessments window.

        Retains only findings within the configured correlation window (relative
        to the newest observation) and at most ``_MAX_RECENT_FINDINGS`` entries.
        Deterministic and bounded; nothing is persisted.
        """
        seen_findings = {f.finding_id for f in self._recent_findings}
        self._recent_findings.extend(
            f for f in self._cycle_findings if f.finding_id not in seen_findings
        )
        seen_assessments = {a.assessment_id for a in self._recent_assessments}
        self._recent_assessments.extend(
            a for a in self._cycle_assessments if a.assessment_id not in seen_assessments
        )

        window = self._host_network.window_seconds
        if self._recent_findings:
            reference = max(f.timestamp for f in self._recent_findings)
            low = reference - timedelta(seconds=window)
            self._recent_findings = [f for f in self._recent_findings if f.timestamp >= low]
            self._recent_assessments = [
                a for a in self._recent_assessments if a.timestamp >= low
            ]

        if len(self._recent_findings) > _MAX_RECENT_FINDINGS:
            self._recent_findings = sorted(
                self._recent_findings, key=lambda f: (f.timestamp, f.finding_id)
            )[-_MAX_RECENT_FINDINGS:]
        if len(self._recent_assessments) > _MAX_RECENT_FINDINGS:
            self._recent_assessments = sorted(
                self._recent_assessments, key=lambda a: (a.timestamp, a.assessment_id)
            )[-_MAX_RECENT_FINDINGS:]

    # -- Helpers -----------------------------------------------------------

    def _prepare_monitors(self) -> None:
        """Construct the configured monitors and establish their baselines."""
        self._process = self._process_override
        self._port = self._port_override
        self._file = self._file_override
        self._network = self._network_override

        if self._agent.enable_process_monitor and self._process is None:
            self._process = ProcessMonitor()
        if self._agent.enable_port_monitor and self._port is None:
            self._port = PortMonitor()
        if self._agent.enable_file_integrity and self._file is None:
            self._file = FileIntegrityMonitor(collector=collector_from_settings())
        if self._sensor_settings.capture_enabled and self._network is None:
            self._network = self._build_network_sensor()

        # Baseline first so the first poll does not report everything as new.
        for name, monitor in (
            ("process", self._process),
            ("port", self._port),
            ("file_integrity", self._file),
        ):
            if monitor is not None:
                try:
                    monitor.start()
                except Exception as exc:
                    self._record(name, exc, [])
                    # Drop the monitor that could not be baselined.
                    if name == "process":
                        self._process = None
                    elif name == "port":
                        self._port = None
                    else:
                        self._file = None

    def _build_network_sensor(self) -> NetworkSensorLike:
        # Imported lazily so scapy is only required when capture is enabled.
        from aegis_network_sensor.pipeline import NetworkEventPipeline
        from aegis_network_sensor.sensor import NetworkSensor

        return NetworkSensor(
            self._sensor_settings,
            pipeline=NetworkEventPipeline(max_events=self._agent.event_buffer_max_events),
        )

    def _resolve_host_ref(self) -> HostRef:
        try:
            self._inventory = collect_system_inventory()
            base_ref = self._inventory.to_host_ref()
            local_ips: list[str] = list(base_ref.ip_addresses)
            if not local_ips:
                try:
                    import socket

                    import psutil

                    addrs = [
                        a.address
                        for iface in psutil.net_if_addrs().values()
                        for a in iface
                        if a.family == socket.AF_INET and not a.address.startswith("127.")
                    ]
                    routable = [a for a in addrs if not a.startswith("169.254.")]
                    local_ips = routable or addrs
                except Exception as exc:
                    logger.debug("Local IP resolution skipped: %s", exc)
            return HostRef(
                host_id=base_ref.host_id,
                hostname=base_ref.hostname,
                platform=base_ref.platform,
                os_version=base_ref.os_version,
                ip_addresses=tuple(local_ips),
                tags=base_ref.tags,
            )
        except Exception as exc:
            self._record("inventory", exc, [])
            self._inventory = None
            return HostRef(host_id="runtime-host")

    @staticmethod
    def _guard(name: str, producer: Callable[[], _T], errors: list[str]) -> _T | None:
        try:
            return producer()
        except Exception as exc:
            AegisRuntime._record(name, exc, errors)
            return None

    @staticmethod
    def _record(name: str, exc: Exception, errors: list[str]) -> None:
        # Non-sensitive: log the producer name and exception type only.
        logger.warning("Runtime producer %r failed: %s", name, type(exc).__name__)
        if errors is not None:
            errors.append(name)

    def _any_registry_published(self) -> bool:
        from aegis_shared.detection import get_active_engine
        from aegis_shared.pipeline import get_active_pipeline
        from aegis_shared.risk import get_active_risk_engine

        return (
            get_active_pipeline() is not None
            or get_active_engine() is not None
            or get_active_risk_engine() is not None
        )


__all__ = ["AegisRuntime"]
