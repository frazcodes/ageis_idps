"""Focused integration tests for optional network anomaly scoring (Step 17).

Verifies that a fitted :class:`NetworkAnomalyModel` is optionally wired into the
existing Aegis runtime flow - ``SecurityEvent`` flow -> features -> anomaly
signal -> risk assessment - without changing deterministic detection or risk
scoring. No capture, no privileges, no persistence, no ML training at runtime.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from datetime import UTC, datetime

import pytest

from aegis_ml_engine.anomaly.model import NetworkAnomalyModel, anomaly_to_signal
from aegis_ml_engine.features.flow_features import NetworkBehaviorFeatures
from aegis_network_sensor.config import SensorSettings
from aegis_runtime import AegisRuntime
from aegis_shared.detection import (
    DetectionFinding,
    clear_active_engine,
)
from aegis_shared.enums import (
    AddressFamily,
    EventType,
    NetworkDirection,
    SourceKind,
    TransportProtocol,
)
from aegis_shared.events import NetworkContext, SecurityEvent, SourceRef
from aegis_shared.pipeline import clear_active_pipeline
from aegis_shared.risk import (
    AnomalySignal,
    RiskEngine,
    clear_active_risk_engine,
)
from tests.test_runtime import FakeNetworkSensor, _agent

_TS = datetime(2026, 6, 1, tzinfo=UTC)


# --- Helpers ---------------------------------------------------------------


def _flow_event(
    event_id: str,
    *,
    flow_id: str = "ipv4|tcp|10.0.0.1:1234->10.0.0.2:80",
    packet_count: int = 100,
    byte_count: int = 64000,
    duration_ms: int = 10000,
) -> SecurityEvent:
    """A FLOW_SUMMARY event carrying the volume context a FlowRecord exposes."""
    return SecurityEvent.create(
        event_id=event_id,
        event_type=EventType.FLOW_SUMMARY,
        source=SourceRef(kind=SourceKind.SENSOR, id="sensor"),
        timestamp=_TS,
        network=NetworkContext(
            src_ip="10.0.0.1",
            src_port=1234,
            dst_ip="10.0.0.2",
            dst_port=80,
            protocol=TransportProtocol.TCP,
            direction=NetworkDirection.OUTBOUND,
            ip_version=AddressFamily.IPV4,
            flow_id=flow_id,
            packets_sent=packet_count,
            bytes_sent=byte_count,
            duration_ms=duration_ms,
        ),
    )


def _normal_features(count: int = 40) -> list[NetworkBehaviorFeatures]:
    return [
        NetworkBehaviorFeatures(
            flow_id=f"baseline-{i}",
            protocol=TransportProtocol.TCP,
            ip_version=AddressFamily.IPV4,
            direction=NetworkDirection.OUTBOUND,
            packet_count=100 + i,
            byte_count=64000 + i * 100,
            duration_ms=10000,
            packets_per_second=10.0,
            bytes_per_second=6400.0,
            average_packet_size=640.0,
        )
        for i in range(count)
    ]


def _fitted_model() -> NetworkAnomalyModel:
    model = NetworkAnomalyModel()
    model.fit(_normal_features())
    return model


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


class FailingAnomalyModel:
    """Model double: claims to be fitted but raises on scoring."""

    is_fitted = True

    def score_many(self, features: object) -> tuple:
        raise RuntimeError("scoring blew up")

    def score(self, feature: object) -> object:
        raise RuntimeError("scoring blew up")


def _runtime(**kwargs: object) -> AegisRuntime:
    defaults: dict[str, object] = {
        "agent_settings": _agent(),
        "sensor_settings": SensorSettings(capture_enabled=True, interface="eth0"),
    }
    defaults.update(kwargs)
    return AegisRuntime(**defaults)  # type: ignore[arg-type]


@pytest.fixture(autouse=True)
def _clean_registries() -> Iterator[None]:
    clear_active_pipeline()
    clear_active_engine()
    clear_active_risk_engine()
    yield
    clear_active_pipeline()
    clear_active_engine()
    clear_active_risk_engine()


# --- 1. ML disabled: existing flow processing still works ------------------


def test_runtime_without_ml_still_processes_flows() -> None:
    sensor = FakeNetworkSensor([_flow_event("net-1")])
    runtime = _runtime(network_sensor=sensor)
    runtime.start()

    result = runtime.poll_once()

    assert runtime.network_anomaly_model is None
    assert sensor.captures == 1
    assert result.network_events == 1
    assert result.assessments == 1
    assert result.errors == ()
    runtime.stop()


# --- 2. Fitted model produces an anomaly signal ----------------------------


def test_fitted_model_passes_anomaly_signal_to_risk() -> None:
    sensor = FakeNetworkSensor([_flow_event("net-1")])
    risk = RecordingRiskEngine()
    runtime = _runtime(
        network_sensor=sensor,
        risk_engine=risk,
        network_anomaly_model=_fitted_model(),
    )
    runtime.start()
    runtime.poll_once()

    # The risk engine received a signal keyed by the flow event's id.
    assert risk.seen, "risk engine was not invoked"
    signals = risk.seen[0]
    assert signals is not None
    assert "net-1" in signals
    signal = signals["net-1"]
    assert isinstance(signal, AnomalySignal)
    assert 0.0 <= signal.score <= 1.0
    runtime.stop()


# --- 3. Anomaly reaches RiskAssessment.anomaly -----------------------------


def test_anomaly_reaches_risk_assessment() -> None:
    event = _flow_event("net-1")
    signal = AnomalySignal(
        source="network_anomaly", score=0.9, confidence=1.0, model_version="1.0.0"
    )
    engine = RiskEngine()

    assessments = engine.assess_many(
        [(event, ())],
        anomaly_signals={"net-1": signal},
    )

    assert len(assessments) == 1
    assert assessments[0].anomaly == signal


# --- 4. Anomaly does not change the existing risk score --------------------


def test_anomaly_does_not_change_risk_score() -> None:
    event = _flow_event("net-1")
    signal = AnomalySignal(
        source="network_anomaly", score=0.99, confidence=1.0, model_version="1.0.0"
    )
    engine = RiskEngine()

    without = engine.assess_many([(event, ())])[0]
    with_signal = engine.assess_many([(event, ())], anomaly_signals={"net-1": signal})[0]

    assert with_signal.risk_score == without.risk_score
    assert with_signal.risk_level == without.risk_level
    assert with_signal.severity == without.severity
    assert with_signal.contributors == without.contributors
    assert without.anomaly is None
    assert with_signal.anomaly == signal


# --- 5. Unfitted model invents nothing and does not crash ------------------


def test_unfitted_model_yields_no_anomaly() -> None:
    sensor = FakeNetworkSensor([_flow_event("net-1")])
    risk = RecordingRiskEngine()
    runtime = _runtime(
        network_sensor=sensor,
        risk_engine=risk,
        network_anomaly_model=NetworkAnomalyModel(),  # never fitted
    )
    runtime.start()

    result = runtime.poll_once()

    assert result.assessments == 1
    assert result.errors == ()
    # No signal was fabricated for the unfitted model.
    assert risk.seen[0] == {}
    runtime.stop()


def test_internal_scoring_failure_does_not_break_cycle() -> None:
    sensor = FakeNetworkSensor([_flow_event("net-1")])
    risk = RecordingRiskEngine()
    runtime = _runtime(
        network_sensor=sensor,
        risk_engine=risk,
        network_anomaly_model=FailingAnomalyModel(),
    )
    runtime.start()

    result = runtime.poll_once()

    # The failing scorer is recorded, but detection/risk still ran.
    assert "network_anomaly" in result.errors
    assert result.assessments == 1
    assert runtime.is_running is True
    assert risk.seen[0] == {}
    runtime.stop()


# --- 6. anomaly_to_signal preserves the model result -----------------------


def test_anomaly_to_signal_carries_score_and_version() -> None:
    result = _fitted_model().score(_normal_features()[0])
    signal = anomaly_to_signal(result)

    assert signal.score == result.anomaly_score
    assert signal.model_version == result.model_version
    assert signal.source == "network_anomaly"
