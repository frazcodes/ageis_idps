"""Focused tests for the live SOC visualization (Step 32)."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason="desktop extra not installed")

from aegis_agent.config import AgentSettings
from aegis_agent.inventory import SystemInventory
from aegis_desktop.app import create_application
from aegis_desktop.pages.dashboard import DashboardPage
from aegis_desktop.pages.graphs import LineGraphWidget, RiskGaugeWidget
from aegis_desktop.services.alerts import AlertService
from aegis_desktop.services.dashboard import DashboardSnapshot, collect_dashboard_snapshot
from aegis_desktop.services.telemetry import (
    MAX_TELEMETRY_POINTS,
    TelemetryHistory,
    TelemetrySample,
)
from aegis_network_sensor.config import SensorSettings
from aegis_shared.enums import Platform

_TS = datetime(2026, 6, 1, 10, 0, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def app() -> Any:
    return create_application([])


def _inventory() -> SystemInventory:
    return SystemInventory(
        host_id="host-1", hostname="ws-01", platform=Platform.WINDOWS,
        os_name="Windows", os_version="10.0", architecture="AMD64",
        python_version="3.14.3", agent_version="0.1.0", cpu_count=8,
        total_memory_bytes=16 * 1024**3, boot_time=_TS, collected_at=_TS,
    )


def _snapshot(**_kw: Any) -> DashboardSnapshot:
    return collect_dashboard_snapshot(
        inventory_collector=_inventory, agent_settings=AgentSettings(),
        sensor_settings=SensorSettings(capture_enabled=False, interface=""),
        collected_at=_TS,
        events_view_provider=lambda: None, findings_view_provider=lambda: None,
    )


def _finding_row(finding_id: str = "F-001", severity: str = "high") -> Any:
    from aegis_desktop.services.detections import FindingRow
    return FindingRow(
        timestamp=_TS, finding_id=finding_id, rule_id="RULE-001",
        severity=severity, title="Test finding", event_id="E-001",
        event_type="network", category="intrusion", host_id="host-1",
        description="Test finding", evidence_summary="", tags=(),
    )


def _incident_row(incident_id: str = "INC-001", status: str = "open",
                   risk_level: str = "high", risk_score: int = 75) -> Any:
    from aegis_desktop.services.incidents import IncidentRow
    return IncidentRow(
        incident_id=incident_id, created_at=_TS, updated_at=_TS,
        host_id="host-1", status=status, risk_score=risk_score,
        risk_level=risk_level, finding_count=2, finding_ids=("F-001", "F-002"),
        event_ids=("E-001",), risk_assessment_ids=(), summary="Test incident",
        correlation_reason="Multiple findings",
    )


def _sample(packets: int = 0, risk_score: int | None = None) -> TelemetrySample:
    return TelemetrySample(
        timestamp=_TS, packets=packets, bytes=0, flows=0, active_flows=0,
        events=0, findings=0, high_risk_findings=0, open_incidents=0,
        risk_score=risk_score,
    )


# --- 1. Empty history ------------------------------------------------------
def test_telemetry_history_empty() -> None:
    history = TelemetryHistory()
    assert history.count == 0
    assert history.latest() is None
    assert history.samples() == ()


# --- 2. Metric sample creation ----------------------------------------------
def test_telemetry_sample_creation() -> None:
    sample = TelemetrySample(
        timestamp=_TS, packets=100, bytes=5000, flows=10, active_flows=5,
        events=3, findings=1, high_risk_findings=1, open_incidents=0, risk_score=42,
    )
    assert sample.packets == 100
    assert sample.risk_score == 42


# --- 3. Bounded history -----------------------------------------------------
def test_telemetry_history_bounded() -> None:
    history = TelemetryHistory(max_points=5)
    for i in range(8):
        history.add(_sample(packets=i))
    assert history.count == 5


# --- 4. Oldest sample eviction ----------------------------------------------
def test_telemetry_history_eviction() -> None:
    history = TelemetryHistory(max_points=3)
    for i in range(5):
        history.add(_sample(packets=i))
    samples = history.samples()
    assert len(samples) == 3
    assert samples[0].packets == 2
    assert samples[2].packets == 4


# --- 5. Default MAX_TELEMETRY_POINTS is 120 ---------------------------------
def test_default_max_telemetry_points() -> None:
    assert MAX_TELEMETRY_POINTS == 120


# --- 6. Telemetry history clear ---------------------------------------------
def test_telemetry_history_clear() -> None:
    history = TelemetryHistory()
    history.add(_sample(packets=1))
    assert history.count == 1
    history.clear()
    assert history.count == 0


# --- 7. Alert service empty state -------------------------------------------
def test_alert_service_empty() -> None:
    service = AlertService()
    assert service.count == 0
    assert service.all_alerts() == ()


# --- 8. HIGH finding generates alert ----------------------------------------
def test_high_finding_generates_alert() -> None:
    service = AlertService()
    alerts = service.detect(findings=(_finding_row(severity="high"),))
    assert len(alerts) == 1
    assert alerts[0].alert_type == "finding"
    assert alerts[0].severity == "high"


# --- 9. CRITICAL finding generates alert ------------------------------------
def test_critical_finding_generates_alert() -> None:
    service = AlertService()
    alerts = service.detect(findings=(_finding_row(finding_id="F-002", severity="critical"),))
    assert len(alerts) == 1
    assert alerts[0].severity == "critical"


# --- 10. New incident generates alert ---------------------------------------
def test_new_incident_generates_alert() -> None:
    service = AlertService()
    alerts = service.detect(incidents=(_incident_row(),))
    assert len(alerts) == 1
    assert alerts[0].alert_type == "incident"


# --- 11. Same finding does not alert repeatedly -----------------------------
def test_same_finding_no_duplicate_alert() -> None:
    service = AlertService()
    finding = _finding_row()
    a1 = service.detect(findings=(finding,))
    a2 = service.detect(findings=(finding,))
    assert len(a1) == 1
    assert len(a2) == 0


# --- 12. Same incident does not alert repeatedly ---------------------------
def test_same_incident_no_duplicate_alert() -> None:
    service = AlertService()
    inc = _incident_row()
    a1 = service.detect(incidents=(inc,))
    a2 = service.detect(incidents=(inc,))
    assert len(a1) == 1
    assert len(a2) == 0


# --- 13. Low findings do not alert ------------------------------------------
def test_low_finding_no_alert() -> None:
    service = AlertService()
    alerts = service.detect(findings=(_finding_row(severity="low"),))
    assert len(alerts) == 0


# --- 14. Closed incident does not alert -------------------------------------
def test_closed_incident_no_alert() -> None:
    service = AlertService()
    alerts = service.detect(incidents=(_incident_row(status="closed"),))
    assert len(alerts) == 0


# --- 15. Alert history bounded ----------------------------------------------
def test_alert_history_bounded() -> None:
    service = AlertService(max_alerts=3)
    for i in range(5):
        service.detect(findings=(_finding_row(finding_id=f"F-{i:03d}"),))
    assert service.count == 3


# --- 16. Alert clear/reset --------------------------------------------------
def test_alert_clear() -> None:
    service = AlertService()
    service.detect(findings=(_finding_row(),))
    assert service.count == 1
    service.clear()
    assert service.count == 0
    assert len(service.alerted_finding_ids) == 0


# --- 17. Dashboard handles no telemetry (offscreen) -------------------------
def test_dashboard_no_telemetry(app: Any) -> None:
    page = DashboardPage(provider=lambda: _snapshot())
    assert page.has_error() is False
    assert page.live_metric_text("live_packets") == "\u2014"


# --- 18. Dashboard graphs exist ---------------------------------------------
def test_dashboard_graphs_exist(app: Any) -> None:
    page = DashboardPage(provider=lambda: _snapshot())
    assert isinstance(page.network_graph, LineGraphWidget)
    assert isinstance(page.security_graph, LineGraphWidget)
    assert isinstance(page.risk_graph, LineGraphWidget)
    assert isinstance(page.risk_gauge, RiskGaugeWidget)


# --- 19. Dashboard alert service accessible ---------------------------------
def test_dashboard_alert_service(app: Any) -> None:
    service = AlertService()
    page = DashboardPage(provider=lambda: _snapshot(), alert_service=service)
    assert page.alert_service is service


# --- 20. Dashboard telemetry history accessible -----------------------------
def test_dashboard_telemetry_history(app: Any) -> None:
    history = TelemetryHistory()
    page = DashboardPage(provider=lambda: _snapshot(), telemetry_history=history)
    assert page.telemetry_history is history
    assert page.telemetry_history.count == 0


# --- 21. refresh_live does not crash ----------------------------------------
def test_dashboard_refresh_live(app: Any) -> None:
    page = DashboardPage(provider=lambda: _snapshot())
    page.refresh_live()
    assert page.has_error() is False


# --- 22. LineGraphWidget set_data -------------------------------------------
def test_line_graph_set_data(app: Any) -> None:
    graph = LineGraphWidget(series_configs=(("Packets", "#3B82F6"),))
    graph.set_data({"Packets": [1.0, 2.0, 3.0]})


# --- 23. RiskGaugeWidget set_score ------------------------------------------
def test_risk_gauge_set_score(app: Any) -> None:
    gauge = RiskGaugeWidget()
    gauge.set_score(42, "medium")


# --- 24. Dashboard existing behavior remains intact -------------------------
def test_existing_dashboard_behavior_intact(app: Any) -> None:
    page = DashboardPage(provider=lambda: _snapshot())
    assert page.status_text("runtime") == "NOT RUNNING"
    assert page.status_text("detection") == "NOT RUNNING"
    assert page.status_text("risk") == "NOT RUNNING"
    assert page.status_text("response") == "MONITOR (read-only)"
    assert page.metric_text("events") in ("\u2014", "")


# --- 25. Combined finding + incident detection ------------------------------
def test_combined_finding_incident_alerts() -> None:
    service = AlertService()
    finding = _finding_row(severity="critical")
    incident = _incident_row()
    alerts = service.detect(findings=(finding,), incidents=(incident,))
    assert len(alerts) == 2
    types = {a.alert_type for a in alerts}
    assert "finding" in types
    assert "incident" in types
