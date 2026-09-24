"""Focused tests for desktop-operable network monitoring (Step 22).

Verifies that the single AegisRuntime drives the existing network sensor across
the Start/Stop lifecycle, that capture state is reported honestly (never fake
RUNNING), that real FlowRecord data reaches the runtime and the Network page,
and that the existing detection/anomaly pipeline still works. No real packet
capture, privileges or threads are used.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest

from aegis_agent.monitors.port import PortRecord, PortSnapshot
from aegis_network_sensor.config import SensorSettings
from aegis_network_sensor.sensor import NetworkSensor
from aegis_runtime import AegisRuntime
from aegis_shared.enums import AddressFamily, TransportProtocol
from aegis_shared.pipeline import clear_active_pipeline
from aegis_shared.risk import clear_active_risk_engine
from tests.test_runtime import _agent

_TS = datetime(2026, 6, 1, 10, 0, 0, tzinfo=UTC)

scapy = pytest.importorskip("scapy.layers.inet", reason="scapy not installed")


# --- Fakes / helpers -------------------------------------------------------


class ReplaySensor(NetworkSensor):
    """Real sensor whose bounded ``capture`` replays in-memory scapy packets.

    Exercises the real normalization + flow aggregation + event pipeline without
    touching the OS capture stack.
    """

    def __init__(self, packets_per_run: int = 10) -> None:
        super().__init__(SensorSettings(capture_enabled=False))
        self._packets_per_run = packets_per_run

    def capture(self, *, count: int | None = None) -> object:
        packets = [
            scapy.IP(src="10.0.0.1", dst="10.0.0.2") / scapy.TCP(sport=40000 + i, dport=443)
            for i in range(self._packets_per_run)
        ]
        return self.process_packets(packets)


class FailingSensor:
    """Network sensor double whose capture always fails (permissions/OS)."""

    def __init__(self, message: str = "winpcap is not installed") -> None:
        self._message = message

    def capture(self, *, count: int | None = None) -> object:
        raise RuntimeError(self._message)

    def drain(self) -> list:
        return []

    @property
    def flows(self) -> tuple:
        return ()


def _runtime(**kwargs: object) -> AegisRuntime:
    defaults: dict[str, object] = {
        "agent_settings": _agent(),
        "sensor_settings": SensorSettings(capture_enabled=False),
    }
    defaults.update(kwargs)
    return AegisRuntime(**defaults)  # type: ignore[arg-type]


@pytest.fixture(autouse=True)
def _clean_registries() -> Iterator[None]:
    from aegis_desktop.services.monitoring import clear_active_monitoring_controller

    clear_active_pipeline()
    clear_active_risk_engine()
    clear_active_monitoring_controller()
    yield
    clear_active_pipeline()
    clear_active_risk_engine()
    clear_active_monitoring_controller()


# --- 1. Runtime starts/stops the existing network sensor -------------------


def test_runtime_starts_and_stops_network_sensor() -> None:
    sensor = ReplaySensor()
    runtime = _runtime(network_sensor=sensor)

    assert runtime.network_sensor is None  # not started yet

    runtime.start()
    assert runtime.network_sensor is sensor
    assert runtime.is_running is True

    runtime.stop()
    assert runtime.network_sensor is None
    assert runtime.is_running is False


# --- 2. Capture state reflects actual sensor state -------------------------


def test_capture_state_reflects_sensor_state() -> None:
    # No sensor configured -> inactive, never active.
    runtime = _runtime()
    runtime.start()
    assert runtime.network_capture_state == "inactive"
    runtime.stop()

    # Configured sensor -> inactive until a capture actually runs, then active.
    sensor = ReplaySensor()
    runtime = _runtime(network_sensor=sensor)
    runtime.start()
    assert runtime.network_capture_state == "inactive"
    runtime.poll_once()
    assert runtime.network_capture_state == "active"
    assert runtime.network_capture_error is None
    runtime.stop()


# --- 3. Real FlowRecord data reaches runtime network state -----------------


def test_real_flow_records_reach_runtime_state() -> None:
    sensor = ReplaySensor(packets_per_run=12)
    runtime = _runtime(network_sensor=sensor)
    runtime.start()
    runtime.poll_once()

    flows = runtime.network_flows
    assert len(flows) == 12
    assert runtime.network_flow_count == 12
    sample = flows[0]
    assert sample.protocol is TransportProtocol.TCP
    assert sample.src_ip == "10.0.0.1"
    assert sample.dst_port == 443
    assert sample.packet_count == 1
    assert sample.byte_count > 0

    runtime.stop()
    # Stopped runtime clears active state (no fake historical traffic).
    assert runtime.network_flows == ()


# --- 4. Network service displays real flows --------------------------------


def test_network_service_displays_flows() -> None:
    from aegis_desktop.services.monitoring import (
        MonitoringController,
        set_active_monitoring_controller,
    )
    from aegis_desktop.services.network import collect_network_monitoring_view

    sensor = ReplaySensor(packets_per_run=6)
    controller = MonitoringController(runtime_factory=lambda: _runtime(network_sensor=sensor))
    set_active_monitoring_controller(controller)
    controller.start()
    controller.poll()

    view = collect_network_monitoring_view()

    assert view.available is True
    assert view.status.running is True
    assert view.status.capture_state == "active"
    assert view.status.counters.flows == 6
    assert view.status.counters.packets == 6
    assert len(view.flows) == 6
    row = view.flows[0]
    assert row.protocol == "tcp"
    assert row.destination.endswith(":443")
    assert row.duration_ms >= 0

    controller.stop()
    stopped = collect_network_monitoring_view()
    assert stopped.status.running is False
    assert stopped.flows == ()


# --- 5. Listening ports displayed from the existing port monitor -----------


def test_listening_ports_displayed() -> None:
    from aegis_desktop.services.network import collect_port_view

    snapshot = PortSnapshot(
        captured_at=_TS,
        ports=(
            PortRecord(
                protocol=TransportProtocol.TCP,
                address_family=AddressFamily.IPV4,
                local_address="0.0.0.0",
                local_port=8080,
                status="LISTEN",
                pid=123,
                process_name="svc",
            ),
        ),
    )
    view = collect_port_view(collector=lambda: snapshot)

    assert view.available is True
    assert view.count == 1
    assert view.rows[0].local_port == 8080
    assert view.rows[0].process_name == "svc"
    assert view.rows[0].status == "LISTEN"


# --- 6. Capture failure is an honest error, not fake RUNNING ---------------


def test_capture_failure_reports_error_not_running() -> None:
    runtime = _runtime(network_sensor=FailingSensor("winpcap is not installed"))
    runtime.start()
    result = runtime.poll_once()

    assert "network_sensor" in result.errors
    assert runtime.network_capture_state == "error"
    assert runtime.network_capture_error is not None
    assert "winpcap" in runtime.network_capture_error
    # Host monitoring / lifecycle must remain intact.
    assert runtime.is_running is True
    runtime.stop()


# --- 7. Desktop Network page reflects stopped/running state ----------------


def test_desktop_network_page_reflects_state() -> None:
    pytest.importorskip("PySide6", reason="desktop extra not installed")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from aegis_desktop.app import create_application
    from aegis_desktop.pages.network import NetworkPage
    from aegis_desktop.services.monitoring import (
        MonitoringController,
        set_active_monitoring_controller,
    )

    app = create_application([])
    assert app is not None

    sensor = ReplaySensor(packets_per_run=5)
    controller = MonitoringController(runtime_factory=lambda: _runtime(network_sensor=sensor))
    set_active_monitoring_controller(controller)
    page = NetworkPage()

    page.refresh_live()
    assert page.monitoring_status_text() == "Network Monitoring: STOPPED"
    assert page.capture_status_text() == "Capture: INACTIVE"
    assert "Unavailable" in page.packets_text()

    controller.start()
    controller.poll()
    page.refresh_live()
    assert page.monitoring_status_text() == "Network Monitoring: RUNNING"
    assert page.capture_status_text() == "Capture: ACTIVE"
    assert page.flow_count() == 5
    assert page.event_count() >= 1
    assert page.packets_text() == "Packets: 5"

    controller.stop()
    page.refresh_live()
    assert page.monitoring_status_text() == "Network Monitoring: STOPPED"
    assert page.capture_status_text() == "Capture: INACTIVE"
    assert page.flow_count() == 0


def test_capture_error_shown_on_page() -> None:
    pytest.importorskip("PySide6", reason="desktop extra not installed")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from aegis_desktop.app import create_application
    from aegis_desktop.pages.network import NetworkPage
    from aegis_desktop.services.monitoring import (
        MonitoringController,
        set_active_monitoring_controller,
    )

    app = create_application([])
    assert app is not None

    controller = MonitoringController(
        runtime_factory=lambda: _runtime(network_sensor=FailingSensor("permission denied"))
    )
    set_active_monitoring_controller(controller)
    controller.start()
    controller.poll()

    page = NetworkPage()
    page.refresh_live()

    assert page.monitoring_status_text() == "Network Monitoring: RUNNING"
    assert page.capture_status_text() == "Capture: ERROR"
    assert "permission denied" in page.capture_error_text()
    controller.stop()


# --- 8. Window Start/Stop drives the single timer and runtime --------------


def test_window_start_stop_controls_runtime() -> None:
    pytest.importorskip("PySide6", reason="desktop extra not installed")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from aegis_desktop.app import create_application
    from aegis_desktop.services.monitoring import MonitoringController
    from aegis_desktop.window import MainWindow

    app = create_application([])
    assert app is not None

    sensor = ReplaySensor(packets_per_run=4)
    controller = MonitoringController(runtime_factory=lambda: _runtime(network_sensor=sensor))
    window = MainWindow(controller=controller)
    window.navigate_to("network")

    assert controller.is_running is False
    assert window._timer.isActive() is False

    window.start_monitoring()
    assert controller.is_running is True
    assert window._timer.isActive() is True
    assert window._monitor_button.text() == "Stop Monitoring"

    window._on_tick()
    assert window.page("network").flow_count() == 4

    window.stop_monitoring()
    assert controller.is_running is False
    assert window._timer.isActive() is False
    assert window._monitor_button.text() == "Start Monitoring"
    assert window._header_status.text() == "Monitoring: disabled"
    window.close()


# --- 9. Existing network detection / anomaly pipeline still works ----------


def test_network_detection_and_anomaly_pipeline_still_works() -> None:
    from aegis_ml_engine.anomaly.model import NetworkAnomalyModel
    from aegis_ml_engine.features.flow_features import NetworkBehaviorFeatures
    from aegis_shared.enums import NetworkDirection
    from aegis_shared.risk import get_active_anomaly_signals

    model = NetworkAnomalyModel()
    baseline = [
        NetworkBehaviorFeatures(
            flow_id=f"b{i}",
            protocol=TransportProtocol.TCP,
            ip_version=AddressFamily.IPV4,
            direction=NetworkDirection.OUTBOUND,
            packet_count=20 + i,
            byte_count=1200 + i * 10,
            duration_ms=1000,
            packets_per_second=20.0,
            bytes_per_second=1200.0,
            average_packet_size=60.0,
        )
        for i in range(40)
    ]
    model.fit(baseline)

    sensor = ReplaySensor(packets_per_run=8)
    runtime = _runtime(network_sensor=sensor, network_anomaly_model=model)
    runtime.start()
    result = runtime.poll_once()

    # Real packets produced network events; aggregated flows also produced
    # flow-summary events, so the network anomaly model scores real flows.
    assert result.network_events >= 8
    assert result.assessments >= 1
    signals = get_active_anomaly_signals()
    assert signals
    assert all(sig.source == "network_anomaly" for sig in signals.values())

    runtime.stop()
