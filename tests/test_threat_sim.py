"""Deterministic tests for the Step 39 threat simulation playbooks (demo mode).

The playbooks are synthetic by construction: tests verify that injected data is
tagged and documentation-safe, that it flows through the *existing* alert and
correlation services, and that the console repaints without any packet being
captured.  Qt runs on the offscreen platform and every test cleans the demo
registries so synthetic incidents never leak into other suites.
"""

from __future__ import annotations

import os
from collections.abc import Generator
from datetime import UTC, datetime
from typing import Any

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason="desktop extra not installed")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QFrame, QLabel, QWidget

from aegis_agent.config import AgentSettings
from aegis_agent.inventory import SystemInventory
from aegis_desktop.app import create_application
from aegis_desktop.pages import dashboard as dashboard_module
from aegis_desktop.pages.dashboard import DashboardPage
from aegis_desktop.pages.detections import DetectionsPage
from aegis_desktop.services.alerts import AlertService
from aegis_desktop.services.dashboard import DashboardSnapshot, collect_dashboard_snapshot
from aegis_desktop.services.detections import collect_finding_view
from aegis_desktop.services.incidents import collect_incident_view
from aegis_desktop.services.response_workflow import get_workflow_manager
from aegis_desktop.threat_sim import (
    ATTACKER_IP,
    C2_BEACON_KEY,
    DEMO_HOST_ID,
    PORT_SCAN,
    PORT_SCAN_KEY,
    SCENARIOS,
    SimulationOutcome,
    ThreatSimulationDialog,
    augment_snapshot,
    build_c2_findings,
    build_port_scan_findings,
    clear_simulated,
    run_scenario,
    scenario_for,
    simulated_findings,
    simulated_incidents,
)
from aegis_network_sensor.config import SensorSettings
from aegis_shared.correlation import (
    clear_active_host_network_correlations,
    clear_active_incidents,
    get_active_host_network_correlations,
    get_active_incidents,
    set_active_host_network_correlations,
    set_active_incidents,
)
from aegis_shared.detection import set_active_engine
from aegis_shared.enums import EventCategory, Platform, Severity
from aegis_shared.pipeline import set_active_pipeline

_TS = datetime(2026, 1, 1, tzinfo=UTC)


@pytest.fixture(scope="module")
def app() -> Any:
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or create_application([])


@pytest.fixture(autouse=True)
def _clean_demo_state() -> Generator[None, None, None]:
    """Keep synthetic findings/incidents/requests out of every other module."""

    def _reset() -> None:
        clear_simulated()
        clear_active_incidents()
        clear_active_host_network_correlations()
        get_workflow_manager().clear()

    _reset()
    yield
    _reset()


def _simulate_monitoring_stop() -> None:
    """Mirror exactly what ``runtime.stop()`` clears from the registries."""
    set_active_pipeline(None)
    set_active_engine(None)
    set_active_incidents(None)
    set_active_host_network_correlations(None)


def _inventory() -> SystemInventory:
    return SystemInventory(
        host_id="host-1",
        hostname="ws-01",
        platform=Platform.WINDOWS,
        os_name="Windows",
        os_version="10.0.19045",
        architecture="AMD64",
        python_version="3.14.3",
        agent_version="0.1.0",
        cpu_count=8,
        total_memory_bytes=16 * 1024**3,
        boot_time=_TS,
        collected_at=_TS,
    )


def _snapshot() -> DashboardSnapshot:
    return collect_dashboard_snapshot(
        inventory_collector=_inventory,
        agent_settings=AgentSettings(),
        sensor_settings=SensorSettings(capture_enabled=False, interface=""),
        collected_at=_TS,
        events_view_provider=lambda: None,
        findings_view_provider=lambda: None,
    )


# --- Playbook contract ------------------------------------------------------


def test_playbook_catalog_lists_both_scenarios() -> None:
    assert tuple(s.key for s in SCENARIOS) == (PORT_SCAN_KEY, C2_BEACON_KEY)
    assert PORT_SCAN.domain == "Network only"
    assert PORT_SCAN.severity == "high"
    assert scenario_for(C2_BEACON_KEY) is SCENARIOS[1]
    assert scenario_for("nope") is None


def test_port_scan_builder_is_tagged_synthetic_network_data() -> None:
    (finding,) = build_port_scan_findings(_TS)

    assert finding.rule_id == "AEGIS-NET-002"
    assert finding.severity == Severity.HIGH
    assert finding.category == EventCategory.NETWORK
    assert finding.host_id == DEMO_HOST_ID
    assert finding.finding_id.startswith("AEGIS-NET-002:")
    assert finding.evidence["src_ip"].startswith("185.15.")
    assert finding.evidence["synthetic"] == "true"
    assert "simulated" in finding.tags


def test_c2_builder_pairs_a_host_finding_with_its_network_beacon() -> None:
    host_finding, network_finding = build_c2_findings(_TS)

    assert (host_finding.severity, host_finding.category) == (
        Severity.CRITICAL,
        EventCategory.HOST,
    )
    assert (network_finding.severity, network_finding.category) == (
        Severity.HIGH,
        EventCategory.NETWORK,
    )
    assert host_finding.rule_id == "AEGIS-EXEC-001"
    assert network_finding.evidence["dst_ip"] == ATTACKER_IP
    assert host_finding.host_id == network_finding.host_id == DEMO_HOST_ID
    assert "powershell.exe" in host_finding.evidence["process"]
    assert all("simulated" in item.tags for item in (host_finding, network_finding))


# --- Injection through existing services ------------------------------------


def test_port_scan_run_raises_one_alert_without_an_incident() -> None:
    service = AlertService()

    outcome = run_scenario(PORT_SCAN_KEY, alert_service=service)

    assert isinstance(outcome, SimulationOutcome)
    assert outcome.incident is None
    assert outcome.alerts == service.all_alerts()
    assert [alert.severity for alert in outcome.alerts] == ["high"]
    assert simulated_findings() == outcome.findings
    assert simulated_incidents() == ()
    assert get_active_incidents() == ()


def test_c2_run_correlates_and_publishes_an_open_incident() -> None:
    service = AlertService()

    outcome = run_scenario(C2_BEACON_KEY, alert_service=service)

    incident = outcome.incident
    assert incident is not None
    assert incident.status.value == "open"
    assert incident.host_id == DEMO_HOST_ID
    assert incident.risk_score == 91
    assert incident.risk_level.value == "critical"
    assert len(incident.finding_ids) == 2
    assert incident in get_active_incidents()
    assert simulated_incidents() == (incident,)

    correlations = get_active_host_network_correlations()
    assert len(correlations) == 1
    assert correlations[0].host_id == DEMO_HOST_ID
    assert correlations[0].network_finding_ids


def test_c2_run_raises_finding_and_incident_alerts() -> None:
    service = AlertService()

    outcome = run_scenario(C2_BEACON_KEY, alert_service=service)

    types = sorted(alert.alert_type for alert in outcome.alerts)
    assert types == ["finding", "finding", "incident"]
    assert outcome.alerts[-1].description.startswith("Incident:")
    assert len(service.all_alerts()) == 3


def test_repeated_runs_produce_fresh_ids_and_new_alerts() -> None:
    service = AlertService()

    first = run_scenario(C2_BEACON_KEY, alert_service=service)
    second = run_scenario(C2_BEACON_KEY, alert_service=service)

    assert {f.finding_id for f in first.findings}.isdisjoint(
        f.finding_id for f in second.findings
    )
    assert len(service.all_alerts()) == 6
    assert len(simulated_incidents()) == 2


def test_unknown_scenario_is_rejected() -> None:
    with pytest.raises(KeyError):
        run_scenario("does-not-exist", alert_service=AlertService())


def test_clear_simulated_resets_the_demo_state() -> None:
    run_scenario(C2_BEACON_KEY, alert_service=AlertService())

    clear_simulated()

    assert simulated_findings() == ()
    assert simulated_incidents() == ()


# --- Dashboard snapshot overlay ---------------------------------------------


def test_augment_snapshot_returns_the_same_object_when_idle() -> None:
    snapshot = _snapshot()

    assert augment_snapshot(snapshot) is snapshot


def test_augment_snapshot_feeds_activity_high_risk_and_incident_counts() -> None:
    snapshot = _snapshot()
    run_scenario(C2_BEACON_KEY, alert_service=AlertService())

    enriched = augment_snapshot(snapshot)

    kinds = sorted(item.kind for item in enriched.activity)
    assert kinds == ["finding", "finding", "incident"]
    assert len(enriched.high_risk_findings) == 2
    assert enriched.detection.finding_count == 2
    assert snapshot.activity == ()
    assert snapshot.detection.finding_count == 0


def test_augment_snapshot_never_counts_a_finding_the_view_already_has() -> None:
    """Regression: the detections overlay feeds the dashboard too - no doubles."""
    run_scenario(C2_BEACON_KEY, alert_service=AlertService())

    base = collect_dashboard_snapshot(
        inventory_collector=_inventory,
        agent_settings=AgentSettings(),
        sensor_settings=SensorSettings(capture_enabled=False, interface=""),
        collected_at=_TS,
        events_view_provider=lambda: None,
        findings_view_provider=collect_finding_view,
    )
    enriched = augment_snapshot(base)

    assert len(base.high_risk_findings) == 2
    assert len(enriched.high_risk_findings) == 2
    assert base.detection.finding_count == 2
    assert enriched.detection.finding_count == 2
    assert sum(1 for item in enriched.activity if item.kind == "incident") == 1
    assert sum(1 for item in enriched.activity if item.kind == "finding") == 2


# --- Dialog -----------------------------------------------------------------


def test_dialog_defaults_to_the_first_playbook(app: Any) -> None:
    dialog = ThreatSimulationDialog()

    assert dialog.windowTitle() == "Threat Simulation Playbooks"
    assert dialog.isModal() is True
    assert bool(dialog.windowFlags() & Qt.WindowType.FramelessWindowHint) is True
    assert dialog.scenario_keys() == (PORT_SCAN_KEY, C2_BEACON_KEY)
    assert dialog.selected_key() == PORT_SCAN_KEY
    assert dialog.is_selected(PORT_SCAN_KEY) is True
    dialog.reject()


def test_dialog_select_moves_the_highlight(app: Any) -> None:
    dialog = ThreatSimulationDialog()
    cards = [
        card
        for card in dialog.findChildren(QFrame)
        if card.objectName() == "ScenarioCard"
    ]
    assert len(cards) == 2
    assert cards[0].property("selected") is True
    assert cards[1].property("selected") is False

    dialog.select(C2_BEACON_KEY)

    assert dialog.selected_key() == C2_BEACON_KEY
    assert dialog.is_selected(C2_BEACON_KEY) is True
    assert cards[0].property("selected") is False
    assert cards[1].property("selected") is True
    dialog.reject()


def test_dialog_rejects_an_unknown_playbook(app: Any) -> None:
    dialog = ThreatSimulationDialog()

    with pytest.raises(KeyError):
        dialog.select("unknown")

    dialog.reject()


def test_dialog_run_and_cancel_buttons_set_the_result(app: Any) -> None:
    run_dialog = ThreatSimulationDialog()
    run_dialog.run_button.click()
    assert run_dialog.result() == QDialog.DialogCode.Accepted

    cancel_dialog = ThreatSimulationDialog()
    cancel_dialog.cancel_button.click()
    assert cancel_dialog.result() == QDialog.DialogCode.Rejected


def test_dialog_disclaims_synthetic_data(app: Any) -> None:
    dialog = ThreatSimulationDialog()

    texts = [label.text() for label in dialog.findChildren(QLabel)]
    assert any("No packet is captured" in text for text in texts)
    assert any("never touches the live network" in text for text in texts)
    dialog.reject()


# --- Dashboard integration ---------------------------------------------------


class _FakeSimulationDialog:
    """Dialog double so the page test never runs a real modal loop."""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        result: int = int(QDialog.DialogCode.Rejected),
        key: str = C2_BEACON_KEY,
    ) -> None:
        self._parent = parent
        self._result = result
        self._key = key
        self.tracked_while_open: Any = None

    def exec(self) -> int:
        self.tracked_while_open = getattr(self._parent, "simulation_dialog", None)
        return self._result

    def result(self) -> int:
        return self._result

    def selected_key(self) -> str:
        return self._key


def test_toolbar_exposes_the_simulate_button(app: Any) -> None:
    page = DashboardPage(provider=_snapshot)

    button = page.simulate_button
    assert button.objectName() == "WarningButton"
    assert "Simulate Threat" in button.text()
    assert "demo" in (button.toolTip() or "").lower()
    assert page.simulation_dialog is None


def test_cancelling_the_dialog_leaves_the_console_clean(app: Any) -> None:
    page = DashboardPage(provider=_snapshot)
    monkey_patched = []

    def factory(parent: QWidget | None = None) -> _FakeSimulationDialog:
        dialog = _FakeSimulationDialog(parent, result=int(QDialog.DialogCode.Rejected))
        monkey_patched.append(dialog)
        return dialog

    original = dashboard_module.ThreatSimulationDialog
    dashboard_module.ThreatSimulationDialog = factory
    try:
        outcome = page.open_threat_simulation()
    finally:
        dashboard_module.ThreatSimulationDialog = original

    assert outcome is None
    assert len(monkey_patched) == 1
    assert simulated_findings() == ()
    assert page.alert_service.all_alerts() == ()


def test_accepting_a_playbook_updates_feed_and_posture(app: Any) -> None:
    page = DashboardPage(provider=_snapshot)
    captured: list[Any] = []

    def factory(parent: QWidget | None = None) -> _FakeSimulationDialog:
        dialog = _FakeSimulationDialog(parent, result=int(QDialog.DialogCode.Accepted))
        captured.append(dialog)
        return dialog

    original = dashboard_module.ThreatSimulationDialog
    dashboard_module.ThreatSimulationDialog = factory
    try:
        outcome = page.open_threat_simulation()
    finally:
        dashboard_module.ThreatSimulationDialog = original

    assert isinstance(outcome, SimulationOutcome)
    assert outcome.scenario == C2_BEACON_KEY
    assert captured[0].tracked_while_open is not None
    assert page.simulation_dialog is None

    assert len(page.alert_service.all_alerts()) == 3
    assert len(page.snapshot.high_risk_findings) == 2
    assert len(page.snapshot.activity) == 3

    feed_text = " ".join(label.text() for label in page.findChildren(QLabel))
    assert "AEGIS-EXEC-001" in feed_text
    assert "AEGIS-NET-001" in feed_text

    labels = page.findChildren(QLabel)
    posture = [label.text() for label in labels if "high/critical" in label.text()]
    assert posture, "threat posture summary should report high/critical findings"
    assert "open incident(s)" in posture[0]


# --- Cross-page overlays (Detections / Incidents / persistence) -------------


def _accept_c2_dialog(page: DashboardPage) -> SimulationOutcome:
    """Run the C2 playbook through the dashboard's public dialog path."""

    def factory(parent: QWidget | None = None) -> _FakeSimulationDialog:
        return _FakeSimulationDialog(
            parent, result=int(QDialog.DialogCode.Accepted), key=C2_BEACON_KEY
        )

    original = dashboard_module.ThreatSimulationDialog
    dashboard_module.ThreatSimulationDialog = factory
    try:
        outcome = page.open_threat_simulation()
    finally:
        dashboard_module.ThreatSimulationDialog = original
    assert isinstance(outcome, SimulationOutcome)
    return outcome


def test_detections_view_shows_simulated_findings_with_the_simulated_tag() -> None:
    run_scenario(C2_BEACON_KEY, alert_service=AlertService())

    view = collect_finding_view()
    rows = {row.finding_id: row for row in view.rows}
    sim_ids = {finding.finding_id for finding in simulated_findings()}

    assert view.available is True
    assert sim_ids <= set(rows)
    assert view.posture.findings == len(view.rows)
    assert all("simulated" in rows[fid].tags for fid in sim_ids)
    assert any(rows[fid].title.startswith("Suspicious Process") for fid in sim_ids)


def test_detections_view_survives_stopping_monitoring() -> None:
    run_scenario(C2_BEACON_KEY, alert_service=AlertService())
    _simulate_monitoring_stop()

    view = collect_finding_view()
    sim_ids = {finding.finding_id for finding in simulated_findings()}

    assert view.available is True
    assert sim_ids <= {row.finding_id for row in view.rows}
    assert view.posture.findings == len(view.rows)


def test_detections_page_lists_the_simulated_findings(app: Any) -> None:
    run_scenario(C2_BEACON_KEY, alert_service=AlertService())

    page = DetectionsPage()
    page.refresh()

    assert page.snapshot is not None
    assert page.row_count() >= 2
    tags = [tag for i in range(page.row_count()) for tag in page.row_at(i).tags]
    assert "simulated" in tags
    assert page.detection_count_text().startswith("Detections: ")

    _simulate_monitoring_stop()
    page.refresh()
    assert page.row_count() >= 2


def test_incidents_view_includes_the_simulated_incident_and_its_findings() -> None:
    outcome = run_scenario(C2_BEACON_KEY, alert_service=AlertService())
    assert outcome.incident is not None

    view = collect_incident_view()
    assert outcome.incident.incident_id in {row.incident_id for row in view.rows}
    related = {finding.finding_id for finding in view.findings}
    assert {finding.finding_id for finding in outcome.findings} <= related


def test_incidents_view_survives_stopping_monitoring() -> None:
    outcome = run_scenario(C2_BEACON_KEY, alert_service=AlertService())
    assert outcome.incident is not None
    _simulate_monitoring_stop()

    view = collect_incident_view()
    assert outcome.incident.incident_id in {row.incident_id for row in view.rows}


def test_all_three_pages_stay_populated_after_stopping_monitoring(app: Any) -> None:
    """Presentation guarantee: demo data survives *Stop Monitoring*."""
    page = DashboardPage(provider=_snapshot)
    outcome = _accept_c2_dialog(page)
    assert outcome.incident is not None

    _simulate_monitoring_stop()
    page.refresh()

    assert page.snapshot is not None
    assert len(page.snapshot.high_risk_findings) == 2
    assert any(item.kind == "incident" for item in page.snapshot.activity)
    assert len(page.alert_service.all_alerts()) == 3

    sim_ids = {finding.finding_id for finding in simulated_findings()}
    assert sim_ids <= {row.finding_id for row in collect_finding_view().rows}
    assert outcome.incident.incident_id in {
        row.incident_id for row in collect_incident_view().rows
    }


# --- Response workflow (Action Center -> Response Center) -------------------


def test_c2_run_opens_a_draft_block_ip_request_for_the_attacker() -> None:
    outcome = run_scenario(C2_BEACON_KEY, alert_service=AlertService())
    assert outcome.incident is not None
    rid = outcome.response_request_id
    assert rid is not None

    mgr = get_workflow_manager()
    view = mgr.get(rid)
    assert view is not None
    assert view.action_label == "Block IP"
    assert view.target == ATTACKER_IP
    assert view.status == "draft"
    assert view.incident_id == outcome.incident.incident_id
    assert view.source_finding_ids == tuple(f.finding_id for f in outcome.findings)
    assert view.risk_level == "critical"
    assert view.risk_score == 91
    assert view.policy_decision == "requires_approval"
    assert mgr.actionable_count() == 1


def test_port_scan_run_opens_a_block_ip_request_without_an_incident() -> None:
    outcome = run_scenario(PORT_SCAN_KEY, alert_service=AlertService())
    rid = outcome.response_request_id
    assert rid is not None

    view = get_workflow_manager().get(rid)
    assert view is not None
    assert view.action_label == "Block IP"
    assert view.target == ATTACKER_IP
    assert view.status == "draft"
    assert not view.incident_id
    assert view.risk_level == "high"
    assert outcome.incident is None


def test_opened_request_walks_dry_run_submit_and_approve() -> None:
    """The Response Center pipeline works on the simulated IP - no execution."""
    outcome = run_scenario(C2_BEACON_KEY, alert_service=AlertService())
    mgr = get_workflow_manager()
    rid = outcome.response_request_id
    assert rid is not None
    assert mgr.pending_count() == 0

    dry = mgr.run_dry_run(rid)
    assert dry is not None
    assert dry.status == "dry_run_completed"
    assert dry.dry_run_status == "would_apply"

    submitted = mgr.request_approval(rid)
    assert submitted is not None
    assert submitted.status == "pending_approval"
    assert mgr.pending_count() == 1

    approved = mgr.approve(rid)
    assert approved is not None
    assert approved.status == "approved"
    assert mgr.approved_count() == 1
    # Approval only updates workflow state: nothing was executed.
    assert mgr.executed_count() == 0


def test_clearing_the_workflow_manager_drops_the_simulated_request() -> None:
    outcome = run_scenario(C2_BEACON_KEY, alert_service=AlertService())
    assert outcome.response_request_id is not None
    mgr = get_workflow_manager()
    assert mgr.count == 1

    mgr.clear()

    assert mgr.count == 0
    assert mgr.actionable_count() == 0


def test_action_center_reports_one_pending_action_after_a_scenario(app: Any) -> None:
    page = DashboardPage(provider=_snapshot)
    assert page._pending_response_count() == 0
    page.refresh()

    outcome = _accept_c2_dialog(page)
    assert outcome.response_request_id is not None

    assert page._pending_response_count() == 1
    assert page._posture_action_num.text() == "1"
    assert page._posture_action_sub.text() == "1 response request(s) awaiting action"
    color = dashboard_module._action_color(1)
    assert color != dashboard_module._action_color(0)
    assert f"color: {color}" in page._posture_action_num.styleSheet()


def test_response_center_lists_the_simulated_request(app: Any) -> None:
    from aegis_desktop.pages.response_center import ResponseCenterPage

    outcome = run_scenario(C2_BEACON_KEY, alert_service=AlertService())
    rid = outcome.response_request_id
    assert rid is not None

    page = ResponseCenterPage()
    page.refresh()

    assert page.row_count() == 1
    row = page.source_model.row_at(0)
    assert row.request_id == rid
    assert row.action_label == "Block IP"
    assert row.target == ATTACKER_IP
    assert row.status == "draft"
    assert page.has_error() is False


def test_action_center_still_reports_pending_after_stopping_monitoring(
    app: Any,
) -> None:
    page = DashboardPage(provider=_snapshot)
    _accept_c2_dialog(page)

    _simulate_monitoring_stop()
    page.refresh()

    assert page._pending_response_count() == 1
    assert page._posture_action_num.text() == "1"
