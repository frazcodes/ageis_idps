"""Focused tests for real host behavior anomaly detection (Step 20).

Exercises the :class:`HostAnomalyModel` lifecycle and its integration into the
existing :class:`AegisRuntime` poll cycle: host telemetry -> features -> host
anomaly signal -> risk assessment. No real process table, sockets, filesystem,
capture or persistence is used; monitor outputs are injected.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from datetime import UTC, datetime

import pytest

from aegis_agent.monitors.process.models import ProcessChanges, ProcessRecord
from aegis_ml_engine.anomaly.host_model import (
    HostAnomalyModel,
    host_anomaly_to_signal,
)
from aegis_ml_engine.features.host_features import HostBehaviorFeatures
from aegis_network_sensor.config import SensorSettings
from aegis_runtime import AegisRuntime
from aegis_shared.detection import DetectionFinding, clear_active_engine
from aegis_shared.enums import EventCategory, EventType, Severity, SourceKind
from aegis_shared.events import SecurityEvent, SourceRef
from aegis_shared.pipeline import clear_active_pipeline
from aegis_shared.risk import (
    AnomalySignal,
    RiskEngine,
    clear_active_anomaly_signals,
    clear_active_risk_engine,
    get_active_anomaly_signals,
)
from tests.test_runtime import FakeProcessMonitor, _agent

_TS = datetime(2026, 6, 1, tzinfo=UTC)


# --- Helpers ---------------------------------------------------------------


def _host_features(**overrides: int) -> HostBehaviorFeatures:
    values: dict[str, int | str | None] = {
        "host_id": "host-1",
        "process_count": 100,
        "listening_port_count": 5,
        "file_change_count": 3,
        "new_process_count": 2,
        "terminated_process_count": 1,
        "new_listening_port_count": 1,
        "removed_listening_port_count": 0,
        "file_created_count": 1,
        "file_modified_count": 1,
        "file_deleted_count": 1,
    }
    values.update(overrides)
    return HostBehaviorFeatures(**values)  # type: ignore[arg-type]


def _baseline(count: int = 40) -> list[HostBehaviorFeatures]:
    return [_host_features(new_process_count=i % 5, file_change_count=i % 4) for i in range(count)]


def _process_event(event_id: str = "host-1") -> SecurityEvent:
    return SecurityEvent.create(
        event_id=event_id,
        event_type=EventType.PROCESS_STARTED,
        source=SourceRef(kind=SourceKind.AGENT, id="agent"),
        timestamp=_TS,
    )


class _HostFindingEngine:
    """Minimal detection engine that emits one finding for a host event."""

    enabled = True
    rules: tuple = ()

    def evaluate_many(self, events: Iterable[SecurityEvent]) -> tuple[DetectionFinding, ...]:
        findings = []
        for event in events:
            if event.category is EventCategory.HOST:
                findings.append(
                    DetectionFinding(
                        finding_id=f"RULE-1:{event.event_id}",
                        rule_id="RULE-1",
                        rule_name="Rule",
                        severity=Severity.MEDIUM,
                        title="Host finding",
                        description="A host event occurred.",
                        event_id=event.event_id,
                        event_type=event.event_type,
                        category=event.category,
                        timestamp=event.timestamp,
                    )
                )
        return tuple(findings)


class RecordingRiskEngine(RiskEngine):
    """Risk engine that records the anomaly signals it was handed."""

    def __init__(self) -> None:
        super().__init__()
        self.seen: list[dict[str, AnomalySignal] | None] = []

    def assess_many(
        self,
        items: Iterable[tuple[SecurityEvent, Iterable[DetectionFinding]]],
        *,
        anomaly_signals: dict[str, AnomalySignal] | None = None,
    ) -> tuple:
        self.seen.append(anomaly_signals)
        return super().assess_many(items, anomaly_signals=anomaly_signals)


def _runtime(**kwargs: object) -> AegisRuntime:
    defaults: dict[str, object] = {
        "agent_settings": _agent(),
        "sensor_settings": SensorSettings(capture_enabled=False),
        "detection_engine": _HostFindingEngine(),
    }
    defaults.update(kwargs)
    return AegisRuntime(**defaults)  # type: ignore[arg-type]


@pytest.fixture(autouse=True)
def _clean_registries() -> Iterator[None]:
    clear_active_pipeline()
    clear_active_engine()
    clear_active_risk_engine()
    clear_active_anomaly_signals()
    yield
    clear_active_pipeline()
    clear_active_engine()
    clear_active_risk_engine()
    clear_active_anomaly_signals()


# --- 1. Host model rejects scoring before fitting --------------------------


def test_host_model_rejects_scoring_before_fit() -> None:
    model = HostAnomalyModel()

    assert model.is_fitted is False
    with pytest.raises(RuntimeError, match="fit"):
        model.score(_host_features())
    with pytest.raises(RuntimeError, match="fit"):
        model.score_many([_host_features()])


# --- 2. Host model fits a valid baseline -----------------------------------


def test_host_model_fits_valid_baseline() -> None:
    model = HostAnomalyModel()
    model.fit(_baseline())

    assert model.is_fitted is True
    result = model.score(_host_features())
    assert 0.0 <= result.anomaly_score <= 1.0
    assert result.model_version == model.model_version

    with pytest.raises(ValueError, match="empty"):
        HostAnomalyModel().fit([])


# --- 3. Host model produces deterministic results --------------------------


def test_host_model_is_deterministic() -> None:
    query = _host_features(new_process_count=50, file_change_count=99)
    model_a = HostAnomalyModel()
    model_a.fit(_baseline())
    model_b = HostAnomalyModel()
    model_b.fit(_baseline())

    assert model_a.score(query).anomaly_score == pytest.approx(
        model_b.score(query).anomaly_score
    )


# --- 4. Runtime extracts host features from real monitor outputs ------------


def test_runtime_collects_host_baseline_and_fits() -> None:
    monitor = FakeProcessMonitor(
        ProcessChanges(started=(ProcessRecord(pid=1, create_time=_TS),))
    )
    model = HostAnomalyModel()
    runtime = _runtime(
        agent_settings=_agent(enable_process_monitor=True),
        process_monitor=monitor,
        host_anomaly_model=model,
        host_baseline_min_observations=3,
    )
    runtime.start()

    runtime.poll_once()
    assert runtime.host_baseline_size == 1
    assert model.is_fitted is False  # never fits on a single observation

    runtime.poll_once()
    runtime.poll_once()
    assert model.is_fitted is True  # fitted once the baseline minimum is met
    runtime.stop()


# --- 5. Runtime passes the host anomaly signal into risk assessment ---------


def test_runtime_passes_host_anomaly_to_risk() -> None:
    monitor = FakeProcessMonitor(
        ProcessChanges(started=(ProcessRecord(pid=1, create_time=_TS),))
    )
    risk = RecordingRiskEngine()
    model = HostAnomalyModel()
    model.fit(_baseline())
    runtime = _runtime(
        agent_settings=_agent(enable_process_monitor=True),
        process_monitor=monitor,
        risk_engine=risk,
        host_anomaly_model=model,
    )
    runtime.start()

    result = runtime.poll_once()

    assert result.assessments >= 1
    assert "host_anomaly" not in result.errors
    signals = risk.seen[-1] or {}
    host_events = [e for e in runtime.pipeline.peek() if e.event.category is EventCategory.HOST]
    assert host_events, "expected a host event in the pipeline"
    for envelope in host_events:
        assert envelope.event.event_id in signals
        assert signals[envelope.event.event_id].source == "host_behavior"
    runtime.stop()


# --- 6. Host anomaly appears in the InvestigationView ----------------------


def test_host_anomaly_appears_in_investigation() -> None:
    from aegis_desktop.services.detections import collect_investigation_view
    from aegis_shared.risk import set_active_anomaly_signals, set_active_risk_engine

    event = _process_event("host-1")

    model = HostAnomalyModel()
    model.fit(_baseline())
    signal = host_anomaly_to_signal(model.score(_host_features()))

    set_active_risk_engine(RiskEngine())
    set_active_anomaly_signals({event.event_id: signal})

    finding = DetectionFinding(
        finding_id="RULE-1:host-1",
        rule_id="RULE-1",
        rule_name="Rule",
        severity=Severity.MEDIUM,
        title="Host finding",
        description="A host event occurred.",
        event_id=event.event_id,
        event_type=event.event_type,
        category=event.category,
        timestamp=event.timestamp,
    )
    view = collect_investigation_view(finding, event_lookup=lambda _eid: event)

    assert view.risk is not None
    assert view.risk.anomaly is not None
    assert view.risk.anomaly.source == "host_behavior"
    assert view.risk.anomaly.model_version == model.model_version


# --- 7. Unfitted host model does not create a fake anomaly -----------------


def test_unfitted_host_model_creates_no_anomaly() -> None:
    monitor = FakeProcessMonitor(
        ProcessChanges(started=(ProcessRecord(pid=1, create_time=_TS),))
    )
    risk = RecordingRiskEngine()
    runtime = _runtime(
        agent_settings=_agent(enable_process_monitor=True),
        process_monitor=monitor,
        risk_engine=risk,
        host_anomaly_model=HostAnomalyModel(),  # never fitted (baseline unmet)
        host_baseline_min_observations=100,
    )
    runtime.start()

    result = runtime.poll_once()

    assert result.errors == ()
    assert get_active_anomaly_signals() == {}
    assert (risk.seen[-1] or {}) == {}
    runtime.stop()


# --- 8. Existing network anomaly path remains working ----------------------


def test_network_anomaly_path_still_works_with_host_model_disabled() -> None:
    from tests.test_runtime import FakeNetworkSensor
    from tests.test_runtime_anomaly import _fitted_model, _flow_event

    sensor = FakeNetworkSensor([_flow_event("net-1")])
    risk = RecordingRiskEngine()
    runtime = _runtime(
        agent_settings=_agent(),
        sensor_settings=SensorSettings(capture_enabled=True, interface="eth0"),
        network_sensor=sensor,
        risk_engine=risk,
        network_anomaly_model=_fitted_model(),
    )
    runtime.start()

    result = runtime.poll_once()

    assert result.network_events == 1
    signals = risk.seen[-1] or {}
    assert "net-1" in signals
    runtime.stop()
