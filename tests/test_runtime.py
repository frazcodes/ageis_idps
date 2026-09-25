"""Deterministic tests for the minimal Aegis runtime (Step 10).

The runtime is an orchestrator only. Tests drive it one-shot with injected
producers and settings; no real process table, sockets, filesystem or packet
capture is used, and no privileges are required.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest

from aegis_agent.config import AgentSettings
from aegis_agent.monitors.file_integrity import FileChanges
from aegis_agent.monitors.port import PortChanges, PortRecord
from aegis_agent.monitors.process import ProcessChanges, ProcessRecord
from aegis_network_sensor.config import SensorSettings
from aegis_runtime import AegisRuntime, PollResult, RuntimeEventPipeline, RuntimeState
from aegis_shared.detection import (
    DetectionEngine,
    DetectionSettings,
    clear_active_engine,
    get_active_engine,
)
from aegis_shared.enums import (
    AddressFamily,
    EventType,
    SourceKind,
    TransportProtocol,
)
from aegis_shared.events import SecurityEvent, SourceRef
from aegis_shared.pipeline import clear_active_pipeline, get_active_pipeline
from aegis_shared.risk import RiskEngine, clear_active_risk_engine, get_active_risk_engine

_TS = datetime(2026, 1, 1, tzinfo=UTC)


# --- Test doubles ----------------------------------------------------------


class FakeProcessMonitor:
    """Fake monitor that reports its changes once, then behaves as unchanged.

    This mirrors the real monitors, whose ``poll`` advances the baseline so each
    change is reported exactly once.
    """

    def __init__(self, changes: ProcessChanges | None = None) -> None:
        self.started = False
        self.stopped = False
        self.polls = 0
        self._pending = changes or ProcessChanges()

    def start(self) -> object:
        self.started = True
        return object()

    def poll(self) -> ProcessChanges:
        self.polls += 1
        changes, self._pending = self._pending, ProcessChanges()
        return changes

    def stop(self) -> None:
        self.stopped = True


class FakePortMonitor:
    def __init__(self, changes: PortChanges | None = None) -> None:
        self.started = False
        self._changes = changes or PortChanges()

    def start(self) -> object:
        self.started = True
        return object()

    def poll(self) -> PortChanges:
        return self._changes

    def stop(self) -> None:
        pass


class FakeFileMonitor:
    def __init__(self, changes: FileChanges | None = None) -> None:
        self.started = False
        self._changes = changes or FileChanges()

    def start(self) -> object:
        self.started = True
        return object()

    def poll(self) -> FileChanges:
        return self._changes

    def stop(self) -> None:
        pass


class FakeNetworkSensor:
    def __init__(self, events: list[SecurityEvent] | None = None, *, fail: bool = False) -> None:
        self.captures = 0
        self._events = events or []
        self._fail = fail

    def capture(self, *, count: int | None = None) -> object:
        self.captures += 1
        if self._fail:
            raise RuntimeError("capture failed")
        return object()

    def drain(self) -> list[object]:
        from aegis_shared.pipeline import EventEnvelope

        return [
            EventEnvelope(sequence=index, enqueued_at=_TS, event=event)
            for index, event in enumerate(self._events)
        ]


class FailingProcessMonitor:
    def start(self) -> object:
        return object()

    def poll(self) -> ProcessChanges:
        raise RuntimeError("poll failed with secret=abc123")

    def stop(self) -> None:
        pass


def _agent(**overrides: object) -> AgentSettings:
    values: dict[str, object] = {
        "enable_process_monitor": False,
        "enable_port_monitor": False,
        "enable_file_integrity": False,
        "event_buffer_max_events": 100,
    }
    values.update(overrides)
    return AgentSettings(**values)  # type: ignore[arg-type]


def _runtime(**kwargs: object) -> AegisRuntime:
    defaults: dict[str, object] = {
        "agent_settings": _agent(),
        # Isolate from developer/.env capture settings so tests never open a
        # live pcap handle or depend on real traffic.
        "sensor_settings": SensorSettings(capture_enabled=False, interface=""),
    }
    defaults.update(kwargs)
    return AegisRuntime(**defaults)  # type: ignore[arg-type]


def _network_event(event_id: str = "net-1") -> SecurityEvent:
    from aegis_shared.events import NetworkContext

    return SecurityEvent.create(
        event_id=event_id,
        event_type=EventType.NETWORK_PACKET_OBSERVED,
        source=SourceRef(kind=SourceKind.SENSOR, id="sensor"),
        timestamp=_TS,
        network=NetworkContext(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            dst_port=443,
            protocol=TransportProtocol.TCP,
            ip_version=AddressFamily.IPV4,
        ),
    )


@pytest.fixture(autouse=True)
def _clean_registries() -> Iterator[None]:
    clear_active_pipeline()
    clear_active_engine()
    clear_active_risk_engine()
    yield
    clear_active_pipeline()
    clear_active_engine()
    clear_active_risk_engine()


# --- Lifecycle -------------------------------------------------------------


def test_new_runtime_is_not_running() -> None:
    runtime = _runtime()

    assert runtime.is_running is False
    assert runtime.state is RuntimeState.STOPPED


def test_start_transitions_to_running() -> None:
    runtime = _runtime()
    runtime.start()

    assert runtime.is_running is True
    assert runtime.state is RuntimeState.RUNNING
    runtime.stop()


def test_repeated_start_is_idempotent() -> None:
    runtime = _runtime()
    runtime.start()
    pipeline = runtime.pipeline
    runtime.start()

    assert runtime.pipeline is pipeline  # not recreated
    runtime.stop()


def test_stop_transitions_to_stopped() -> None:
    runtime = _runtime()
    runtime.start()
    runtime.stop()

    assert runtime.is_running is False
    assert runtime.state is RuntimeState.STOPPED


def test_repeated_stop_is_safe() -> None:
    runtime = _runtime()
    runtime.start()
    runtime.stop()
    runtime.stop()  # must not raise

    assert runtime.is_running is False


def test_stopped_runtime_clears_registries() -> None:
    runtime = _runtime()
    runtime.start()
    runtime.stop()

    assert get_active_pipeline() is None
    assert get_active_engine() is None
    assert get_active_risk_engine() is None


def test_stop_stops_monitors() -> None:
    monitor = FakeProcessMonitor()
    runtime = _runtime(agent_settings=_agent(enable_process_monitor=True), process_monitor=monitor)
    runtime.start()
    runtime.stop()

    assert monitor.stopped is True


# --- Registry --------------------------------------------------------------


def test_start_publishes_registries() -> None:
    runtime = _runtime()
    runtime.start()

    assert get_active_pipeline() is runtime.pipeline
    assert get_active_engine() is runtime.detection_engine
    assert get_active_risk_engine() is runtime.risk_engine
    runtime.stop()


def test_registries_cleared_after_stop() -> None:
    runtime = _runtime()
    runtime.start()
    runtime.stop()

    assert get_active_pipeline() is None
    assert get_active_engine() is None
    assert get_active_risk_engine() is None


# --- Polling ---------------------------------------------------------------


def test_poll_once_before_start_is_safe() -> None:
    runtime = _runtime()

    result = runtime.poll_once()

    assert isinstance(result, PollResult)
    assert result.is_empty


def test_poll_once_performs_one_bounded_cycle() -> None:
    monitor = FakeProcessMonitor(
        ProcessChanges(started=(ProcessRecord(pid=1, name="p", create_time=_TS),))
    )
    runtime = _runtime(agent_settings=_agent(enable_process_monitor=True), process_monitor=monitor)
    runtime.start()

    result = runtime.poll_once()

    assert monitor.polls == 1
    assert result.host_events == 1
    assert result.submitted == 1
    runtime.stop()


def test_host_events_reach_pipeline() -> None:
    monitor = FakeProcessMonitor(
        ProcessChanges(started=(ProcessRecord(pid=1, name="p", create_time=_TS),))
    )
    runtime = _runtime(agent_settings=_agent(enable_process_monitor=True), process_monitor=monitor)
    runtime.start()
    runtime.poll_once()

    events = [envelope.event for envelope in runtime.pipeline.peek()]
    assert len(events) == 1
    assert events[0].event_type is EventType.PROCESS_STARTED
    runtime.stop()


def test_detection_consumes_available_events() -> None:
    monitor = FakeProcessMonitor(
        ProcessChanges(started=(ProcessRecord(pid=1, name="p", create_time=_TS),))
    )
    detection = DetectionEngine.from_settings(
        DetectionSettings(suspicious_process_path_patterns=["*evil*"])
    )
    runtime = _runtime(
        agent_settings=_agent(enable_process_monitor=True),
        process_monitor=monitor,
        detection_engine=detection,
    )
    runtime.start()

    # No matching event -> no findings, but the engine was invoked over the view.
    result = runtime.poll_once()
    assert result.findings == 0
    runtime.stop()


def test_risk_assessments_can_be_generated() -> None:
    monitor = FakeProcessMonitor(
        ProcessChanges(
            started=(
                ProcessRecord(pid=1, name="p", executable_path="C:\\evil\\x.exe", create_time=_TS),
            )
        )
    )
    detection = DetectionEngine.from_settings(
        DetectionSettings(suspicious_process_path_patterns=["*evil*"])
    )
    runtime = _runtime(
        agent_settings=_agent(enable_process_monitor=True),
        process_monitor=monitor,
        detection_engine=detection,
        risk_engine=RiskEngine(),
    )
    runtime.start()

    result = runtime.poll_once()

    assert result.findings >= 1
    assert result.assessments >= 1
    # The event is still inspectable (peek is non-destructive).
    assert any(envelope.event.event_id for envelope in runtime.pipeline.peek())
    runtime.stop()


def test_events_remain_inspectable_after_polling() -> None:
    monitor = FakeProcessMonitor(
        ProcessChanges(started=(ProcessRecord(pid=1, name="p", create_time=_TS),))
    )
    runtime = _runtime(agent_settings=_agent(enable_process_monitor=True), process_monitor=monitor)
    runtime.start()

    runtime.poll_once()
    first = len(runtime.pipeline.peek())
    runtime.poll_once()  # same changes again -> deduped/unchanged, still inspectable
    second = len(runtime.pipeline.peek())

    assert first == 1
    assert second == 1
    runtime.stop()


def test_cursor_prevents_double_processing() -> None:
    monitor = FakeProcessMonitor(
        ProcessChanges(started=(ProcessRecord(pid=1, name="p", create_time=_TS),))
    )
    runtime = _runtime(agent_settings=_agent(enable_process_monitor=True), process_monitor=monitor)
    runtime.start()

    first = runtime.poll_once()
    second = runtime.poll_once()

    assert first.submitted == 1
    assert second.submitted == 0  # nothing new submitted
    runtime.stop()


# --- Network sensor --------------------------------------------------------


def test_network_sensor_not_started_when_capture_disabled() -> None:
    runtime = _runtime(sensor_settings=SensorSettings(capture_enabled=False))
    runtime.start()

    # No network producer was prepared.
    assert runtime.poll_once().network_events == 0
    runtime.stop()


def test_network_sensor_events_flow_when_enabled() -> None:
    sensor = FakeNetworkSensor([_network_event("net-1")])
    runtime = _runtime(
        sensor_settings=SensorSettings(capture_enabled=True, interface="eth0"),
        network_sensor=sensor,
    )
    runtime.start()

    result = runtime.poll_once()

    assert sensor.captures == 1
    assert result.network_events == 1
    runtime.stop()


# --- Configuration safety --------------------------------------------------


def test_default_configuration_is_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    # A local .env (and the process environment) may enable capture for the
    # live console; the shipped defaults themselves must stay disabled.
    for key in ("AEGIS_SENSOR_CAPTURE_ENABLED", "AEGIS_SENSOR_INTERFACE"):
        monkeypatch.delenv(key, raising=False)
    runtime = _runtime(sensor_settings=SensorSettings(_env_file=None))

    assert runtime._agent.enabled_monitors == ()
    assert runtime._sensor_settings.capture_enabled is False
    runtime.start()
    assert runtime.poll_once().submitted == 0
    runtime.stop()


def test_response_defaults_remain_non_enforcing() -> None:
    from aegis_response_engine.config import ResponseEngineSettings

    settings = ResponseEngineSettings()

    assert settings.enforcement_enabled is False
    assert settings.dry_run is True
    assert settings.require_approval is True


# --- Failure isolation -----------------------------------------------------


def test_failing_producer_is_isolated() -> None:
    runtime = _runtime(
        agent_settings=_agent(enable_process_monitor=True),
        process_monitor=FailingProcessMonitor(),
    )
    runtime.start()

    result = runtime.poll_once()

    assert "process" in result.errors
    assert runtime.is_running is True  # lifecycle preserved
    runtime.stop()


def test_failing_producer_does_not_leak_exception_details() -> None:
    runtime = _runtime(
        agent_settings=_agent(enable_process_monitor=True),
        process_monitor=FailingProcessMonitor(),
    )
    runtime.start()

    result = runtime.poll_once()

    assert all("secret" not in error for error in result.errors)
    assert all("abc123" not in error for error in result.errors)
    runtime.stop()


def test_other_producers_continue_after_one_fails() -> None:
    port = FakePortMonitor(
        PortChanges(
            started=(
                PortRecord(
                    protocol=TransportProtocol.TCP,
                    address_family=AddressFamily.IPV4,
                    local_port=8080,
                    status="LISTEN",
                ),
            )
        )
    )
    runtime = _runtime(
        agent_settings=_agent(enable_process_monitor=True, enable_port_monitor=True),
        process_monitor=FailingProcessMonitor(),
        port_monitor=port,
    )
    runtime.start()

    result = runtime.poll_once()

    assert "process" in result.errors
    assert result.submitted >= 1  # the port producer still delivered
    runtime.stop()


# --- Compatibility ---------------------------------------------------------


def test_runtime_pipeline_is_shared_event_pipeline() -> None:
    from aegis_shared.pipeline import EventPipeline

    runtime = _runtime()

    assert isinstance(runtime.pipeline, RuntimeEventPipeline)
    assert isinstance(runtime.pipeline, EventPipeline)


def test_runtime_does_not_start_capture_when_disabled() -> None:
    runtime = _runtime(sensor_settings=SensorSettings(capture_enabled=False))
    runtime.start()
    runtime.poll_once()

    assert runtime._network is None
    runtime.stop()
