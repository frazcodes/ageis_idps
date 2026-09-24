"""Deterministic tests for the Finding Investigation View (Step 14).

Tests the InvestigationView dataclass, collect_investigation_view() service
function, and the sectioned investigation panel on the Detections page. No real
engines, pipelines or monitors are started; all dependencies are injected.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason="desktop extra not installed")

from PySide6.QtWidgets import QApplication

from aegis_desktop.app import create_application
from aegis_desktop.pages.detections import DetectionsPage
from aegis_desktop.services.detections import (
    DetectionPosture,
    FindingRow,
    FindingSnapshotView,
    InvestigationView,
    ResponsePosture,
    RiskView,
    collect_investigation_view,
    evidence_summary,
)
from aegis_shared.detection import DetectionFinding
from aegis_shared.enums import (
    EventCategory,
    EventType,
    Severity,
)

_TS = datetime(2026, 3, 15, 10, 0, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def app() -> QApplication:
    return create_application([])


def _finding(
    *,
    finding_id: str = "AEGIS-LISTEN-001:evt-1",
    rule_id: str = "AEGIS-LISTEN-001",
    event_id: str = "evt-1",
    severity: Severity = Severity.MEDIUM,
    evidence: dict[str, str] | None = None,
) -> DetectionFinding:
    return DetectionFinding(
        finding_id=finding_id,
        rule_id=rule_id,
        rule_name="Unexpected listening port",
        severity=severity,
        title="Unexpected listening port",
        description="A listening TCP endpoint was observed on a suspicious port.",
        event_id=event_id,
        event_type=EventType.PORT_LISTENING,
        category=EventCategory.HOST,
        timestamp=_TS,
        host_id="host-1",
        evidence=evidence if evidence is not None else {"local_port": "8080", "protocol": "tcp"},
        tags=("host", "port"),
    )


def _mock_rule_lookup(rule_id: str) -> dict[str, str]:
    return {
        "rule_id": rule_id,
        "name": "Unexpected listening port",
        "description": "A listening TCP endpoint was observed on a suspicious port.",
        "tags": "host, port",
    }


def _mock_risk_view() -> RiskView:
    return RiskView(
        risk_score=45,
        risk_level="medium",
        severity="medium",
        reasons=("AEGIS-LISTEN-001 (medium) contributed 45: Unexpected listening port",),
        contributors=("AEGIS-LISTEN-001:evt-1 (medium) +45",),
    )


def _mock_response() -> ResponsePosture:
    return ResponsePosture(mode="monitor", dry_run=True, require_approval=True)


def _mock_event_details(event_id: str = "evt-1") -> dict[str, str]:
    return {
        "event_id": event_id,
        "event_type": "port.listening",
        "category": "host",
        "severity": "medium",
        "timestamp": _TS.isoformat(),
        "source": "agent-test",
    }


# --- Service: InvestigationView construction ---------------------------------


def test_investigation_view_has_all_sections() -> None:
    finding = _finding()
    view = collect_investigation_view(
        finding,
        event_details_lookup=lambda eid: _mock_event_details(eid),
        risk_lookup=lambda ev, f: _mock_risk_view(),
        rule_lookup=_mock_rule_lookup,
    )

    assert "finding_id" in view.finding
    assert "rule_id" in view.finding
    assert "severity" in view.finding
    assert view.rule_info != {}
    assert view.evidence != {}
    assert view.risk is not None
    assert view.response.mode == "monitor"
    assert view.event_details is not None


def test_investigation_view_finding_dict_matches_finding() -> None:
    finding = _finding(finding_id="AEGIS-LISTEN-001:evt-42")
    view = collect_investigation_view(
        finding,
        event_details_lookup=lambda eid: _mock_event_details(eid),
        rule_lookup=_mock_rule_lookup,
    )

    assert view.finding["finding_id"] == "AEGIS-LISTEN-001:evt-42"
    assert view.finding["rule_id"] == "AEGIS-LISTEN-001"
    assert view.finding["severity"] == "medium"


def test_investigation_view_rule_info_has_name_and_tags() -> None:
    finding = _finding()
    view = collect_investigation_view(
        finding,
        event_details_lookup=lambda eid: _mock_event_details(eid),
        rule_lookup=_mock_rule_lookup,
    )

    assert "name" in view.rule_info
    assert "tags" in view.rule_info
    assert "host" in view.rule_info["tags"]


def test_investigation_view_evidence_is_redacted() -> None:
    finding = _finding(evidence={"local_port": "8080"})
    view = collect_investigation_view(
        finding,
        event_details_lookup=lambda eid: _mock_event_details(eid),
        rule_lookup=_mock_rule_lookup,
    )

    assert "local_port" in view.evidence
    assert "8080" in view.evidence["local_port"]


def test_investigation_view_risk_none_when_no_engine() -> None:
    finding = _finding()
    view = collect_investigation_view(
        finding,
        event_details_lookup=lambda eid: _mock_event_details(eid),
        risk_lookup=lambda ev, f: None,
        rule_lookup=_mock_rule_lookup,
    )

    assert view.risk is None


def test_investigation_view_event_none_when_not_available() -> None:
    finding = _finding()
    view = collect_investigation_view(
        finding,
        event_details_lookup=lambda eid: None,
        rule_lookup=_mock_rule_lookup,
    )

    assert view.event_details is None


def test_investigation_view_response_has_safe_defaults() -> None:
    finding = _finding()
    view = collect_investigation_view(
        finding,
        event_details_lookup=lambda eid: _mock_event_details(eid),
        rule_lookup=_mock_rule_lookup,
    )

    assert view.response.dry_run is True
    assert view.response.require_approval is True
    assert view.response.mode in ("monitor", "enforce", "dry_run")


def test_investigation_view_risk_populated() -> None:
    finding = _finding()
    view = collect_investigation_view(
        finding,
        event_details_lookup=lambda eid: _mock_event_details(eid),
        risk_lookup=lambda ev, f: _mock_risk_view(),
        rule_lookup=_mock_rule_lookup,
    )

    assert view.risk is not None
    assert view.risk.risk_score == 45
    assert view.risk.risk_level == "medium"
    assert len(view.risk.reasons) == 1


def test_investigation_view_event_populated() -> None:
    finding = _finding()
    view = collect_investigation_view(
        finding,
        event_details_lookup=lambda eid: _mock_event_details(eid),
        rule_lookup=_mock_rule_lookup,
    )

    assert view.event_details is not None
    assert view.event_details["event_id"] == "evt-1"
    assert view.event_details["event_type"] == "port.listening"


# --- Service: RiskView / ResponsePosture dataclasses --------------------------


def test_risk_view_is_frozen() -> None:
    rv = _mock_risk_view()
    with pytest.raises(AttributeError):
        rv.risk_score = 99  # type: ignore[misc]


def test_response_posture_is_frozen() -> None:
    rp = _mock_response()
    with pytest.raises(AttributeError):
        rp.mode = "enforce"  # type: ignore[misc]


# --- Service: evidence_summary integration -----------------------------------


def test_evidence_summary_used_in_finding_view() -> None:
    finding = _finding(evidence={"local_port": "9090", "protocol": "tcp"})
    summary = evidence_summary(dict(finding.evidence))

    assert "9090" in summary
    assert "tcp" in summary


# --- Page: investigation panel integration -----------------------------------


def _make_page_with_finding(
    finding: DetectionFinding,
    *,
    investigation_provider: object | None = None,
) -> DetectionsPage:
    """Create a DetectionsPage with one finding and an optional investigation mock."""
    view = FindingSnapshotView(
        available=True,
        error=None,
        collected_at=_TS,
        posture=DetectionPosture(running=True, enabled=True, rule_count=6, findings=1),
        rows=(
            FindingRow(
                timestamp=_TS,
                finding_id=finding.finding_id,
                rule_id=finding.rule_id,
                severity="medium",
                title=finding.title,
                event_id=finding.event_id,
                event_type="port.listening",
                category="host",
                host_id="host-1",
                description=finding.description,
                evidence_summary=evidence_summary(dict(finding.evidence)),
                tags=("host", "port"),
            ),
        ),
        findings=(finding,),
    )
    kwargs: dict[str, object] = {"provider": lambda: view}
    if investigation_provider is not None:
        kwargs["investigation_provider"] = investigation_provider
    return DetectionsPage(**kwargs)  # type: ignore[arg-type]


def test_page_selecting_finding_shows_investigation(app: QApplication) -> None:
    finding = _finding()

    def fake_investigation(f: DetectionFinding) -> InvestigationView:
        return InvestigationView(
            finding={"finding_id": f.finding_id, "severity": "medium"},
            rule_info={"name": "Unexpected listening port"},
            evidence={"local_port": "8080"},
            risk=_mock_risk_view(),
            response=_mock_response(),
            event_details={"event_id": f.event_id, "event_type": "port.listening"},
        )

    page = _make_page_with_finding(finding, investigation_provider=fake_investigation)
    page.refresh()

    page.show_detail_for(page.row_at(0))

    keys = page.detail_keys()
    assert "Finding Id" in keys
    assert "Severity" in keys
    assert "Mode" in keys


def test_page_investigation_shows_risk_section(app: QApplication) -> None:
    finding = _finding()

    def fake_investigation(f: DetectionFinding) -> InvestigationView:
        return InvestigationView(
            finding={"finding_id": f.finding_id},
            rule_info={},
            evidence={},
            risk=_mock_risk_view(),
            response=_mock_response(),
            event_details=None,
        )

    page = _make_page_with_finding(finding, investigation_provider=fake_investigation)
    page.refresh()

    page.show_detail_for(page.row_at(0))

    keys = page.detail_keys()
    assert "Risk Score" in keys
    assert "Risk Level" in keys


def test_page_investigation_shows_response_posture(app: QApplication) -> None:
    finding = _finding()

    def fake_investigation(f: DetectionFinding) -> InvestigationView:
        return InvestigationView(
            finding={"finding_id": f.finding_id},
            rule_info={},
            evidence={},
            risk=None,
            response=ResponsePosture(mode="monitor", dry_run=True, require_approval=False),
            event_details=None,
        )

    page = _make_page_with_finding(finding, investigation_provider=fake_investigation)
    page.refresh()

    page.show_detail_for(page.row_at(0))

    values = page.detail_values()
    assert "monitor" in values
    assert "Yes" in values  # dry_run
    assert "No" in values  # require_approval=False


def test_page_investigation_shows_event_section(app: QApplication) -> None:
    finding = _finding()

    def fake_investigation(f: DetectionFinding) -> InvestigationView:
        return InvestigationView(
            finding={"finding_id": f.finding_id},
            rule_info={},
            evidence={},
            risk=None,
            response=_mock_response(),
            event_details={"event_id": "evt-1", "event_type": "port.listening"},
        )

    page = _make_page_with_finding(finding, investigation_provider=fake_investigation)
    page.refresh()

    page.show_detail_for(page.row_at(0))

    keys = page.detail_keys()
    assert "Event Id" in keys
    assert "Event Type" in keys


def test_page_clearing_selection_clears_investigation(app: QApplication) -> None:
    finding = _finding()

    def fake_investigation(f: DetectionFinding) -> InvestigationView:
        return InvestigationView(
            finding={"finding_id": f.finding_id},
            rule_info={},
            evidence={},
            risk=None,
            response=_mock_response(),
            event_details=None,
        )

    page = _make_page_with_finding(finding, investigation_provider=fake_investigation)
    page.refresh()

    page.show_detail_for(page.row_at(0))
    assert len(page.detail_keys()) > 0

    page._clear_detail()
    assert len(page.detail_keys()) == 0


def test_page_no_response_action_buttons(app: QApplication) -> None:
    from PySide6.QtWidgets import QPushButton

    page = DetectionsPage()
    labels = {button.text().lower() for button in page.findChildren(QPushButton)}

    assert labels <= {"refresh"}
    for forbidden in ("ignore", "delete", "quarantine", "kill", "block", "respond"):
        assert not any(forbidden in label for label in labels)


# --- Safety: no forbidden imports --------------------------------------------


def test_application_does_not_load_security_engines() -> None:
    import subprocess
    import sys

    forbidden_prefixes = (
        "aegis_agent.monitors",
        "aegis_network_sensor.capture",
        "aegis_network_sensor.normalization",
        "aegis_network_sensor.sensor",
        "aegis_response_engine",
        "aegis_ml_engine",
        "aegis_shared.risk",
    )
    code = (
        "import sys; import aegis_desktop.app, aegis_desktop.window; "
        f"prefixes = {forbidden_prefixes!r}; "
        "print(sorted(m for m in sys.modules if m.startswith(prefixes)))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "[]"
