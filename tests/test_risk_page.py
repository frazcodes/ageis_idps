"""Deterministic tests for the Risk page integration (GUI-8).

Assessments are produced by the real Step 9 risk engine over locally constructed
events/findings; no test depends on real machine activity and no producer is
started. Qt runs with the offscreen platform and no privileges.
"""

from __future__ import annotations

import os
import subprocess
import sys
from datetime import UTC, datetime

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason="desktop extra not installed")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QPushButton

from aegis_desktop.app import create_application
from aegis_desktop.pages.base import BasePage
from aegis_desktop.pages.risk import RiskPage
from aegis_desktop.services.processes import MISSING
from aegis_desktop.services.risk import (
    RISK_ERROR,
    RiskPosture,
    RiskRow,
    RiskSnapshotView,
    collect_risk_view,
    describe_assessment,
    reasons_summary,
)
from aegis_desktop.window import MainWindow
from aegis_shared.detection import DetectionEngine, DetectionSettings
from aegis_shared.enums import (
    AddressFamily,
    EventType,
    Platform,
    RiskLevel,
    Severity,
    SourceKind,
    TransportProtocol,
)
from aegis_shared.events import HostRef, SecurityEvent, SocketContext, SourceRef
from aegis_shared.risk import (
    AnomalySignal,
    RiskAssessment,
    RiskContributor,
    RiskEngine,
    RiskSettings,
)

_TS = datetime(2026, 1, 1, tzinfo=UTC)
_TS2 = datetime(2026, 1, 2, tzinfo=UTC)

#: Packages the application must not load just by opening it.
_FORBIDDEN_IMPORT_PREFIXES = (
    "aegis_agent.monitors",
    "aegis_network_sensor.capture",
    "aegis_network_sensor.normalization",
    "aegis_network_sensor.sensor",
    "aegis_response_engine",
    "aegis_ml_engine",
)


@pytest.fixture(scope="module")
def app() -> QApplication:
    return create_application([])


def _source() -> SourceRef:
    return SourceRef(kind=SourceKind.AGENT, id="agent-test")


def _host() -> HostRef:
    return HostRef(host_id="host-1", hostname="ws-01", platform=Platform.WINDOWS)


def _port_event(event_id: str, port: int, *, timestamp: datetime = _TS) -> SecurityEvent:
    return SecurityEvent.create(
        event_id=event_id,
        event_type=EventType.PORT_LISTENING,
        source=_source(),
        host=_host(),
        timestamp=timestamp,
        socket=SocketContext(
            local_address="0.0.0.0",
            local_port=port,
            address_family=AddressFamily.IPV4,
            protocol=TransportProtocol.TCP,
            status="LISTEN",
        ),
    )


def _detection_engine(ports: list[int]) -> DetectionEngine:
    return DetectionEngine.from_settings(DetectionSettings(suspicious_listen_ports=ports))


def _risk_engine() -> RiskEngine:
    return RiskEngine()


def _collect(ports: list[int], events: list[SecurityEvent], **kwargs: object) -> RiskSnapshotView:
    return collect_risk_view(
        engine=_risk_engine(),
        events_provider=lambda: events,
        detection_engine_provider=lambda: _detection_engine(ports),
        **kwargs,  # type: ignore[arg-type]
    )


def _assessment(
    *,
    assessment_id: str = "1:evt-1",
    event_id: str = "evt-1",
    risk_score: int = 25,
    risk_level: RiskLevel = RiskLevel.MEDIUM,
    severity: Severity = Severity.MEDIUM,
    timestamp: datetime = _TS,
    reasons: tuple[str, ...] = ("AEGIS-LISTEN-001 (medium) contributed 25: port",),
    finding_ids: tuple[str, ...] = ("AEGIS-LISTEN-001:evt-1",),
    contributors: tuple[RiskContributor, ...] = (),
    anomaly: AnomalySignal | None = None,
    scoring_version: str = "1",
) -> RiskAssessment:
    return RiskAssessment(
        assessment_id=assessment_id,
        event_id=event_id,
        host_id="host-1",
        risk_score=risk_score,
        risk_level=risk_level,
        severity=severity,
        reasons=reasons,
        finding_ids=finding_ids,
        contributors=contributors,
        scoring_version=scoring_version,
        timestamp=timestamp,
        anomaly=anomaly,
    )


def _row(
    *,
    assessment_id: str = "1:evt-1",
    event_id: str = "evt-1",
    risk_score: int = 25,
    risk_level: str = "medium",
    severity: str = "medium",
    timestamp: datetime = _TS,
    reasons_summary: str = "reason",
    finding_ids: tuple[str, ...] = ("AEGIS-LISTEN-001:evt-1",),
    scoring_version: str = "1",
) -> RiskRow:
    return RiskRow(
        timestamp=timestamp,
        assessment_id=assessment_id,
        event_id=event_id,
        host_id="host-1",
        risk_score=risk_score,
        risk_level=risk_level,
        severity=severity,
        reasons_summary=reasons_summary,
        finding_ids=finding_ids,
        scoring_version=scoring_version,
        has_anomaly=False,
    )


def _empty_view() -> RiskSnapshotView:
    return RiskSnapshotView(
        available=True,
        error=None,
        collected_at=None,
        posture=RiskPosture(running=False, assessments=0, scoring_version=None),
        rows=(),
        assessments=(),
    )


# --- Adapter ---------------------------------------------------------------


def test_adapter_converts_assessments() -> None:
    view = _collect([8080], [_port_event("evt-1", 8080)])

    assert view.available is True
    assert view.count == 1
    assert view.assessments[0].event_id == "evt-1"


def test_adapter_preserves_assessment_id() -> None:
    view = _collect([8080], [_port_event("evt-abc", 8080)])

    assert view.rows[0].assessment_id == "1:evt-abc"


def test_adapter_preserves_event_id() -> None:
    view = _collect([8080], [_port_event("evt-xyz", 8080)])

    assert view.rows[0].event_id == "evt-xyz"


def test_adapter_preserves_host_id() -> None:
    view = _collect([8080], [_port_event("e", 8080)])

    assert view.rows[0].host_id == "host-1"


def test_adapter_preserves_score() -> None:
    view = _collect([8080], [_port_event("e", 8080)])

    assert view.rows[0].risk_score == 25


def test_adapter_preserves_risk_level() -> None:
    view = _collect([8080], [_port_event("e", 8080)])

    assert view.rows[0].risk_level == "medium"


def test_adapter_preserves_severity() -> None:
    view = _collect([8080], [_port_event("e", 8080)])

    assert view.rows[0].severity == "medium"


def test_adapter_preserves_timestamp() -> None:
    view = _collect([8080], [_port_event("e", 8080, timestamp=_TS2)])

    assert view.rows[0].timestamp == _TS2


def test_adapter_preserves_reasons() -> None:
    view = _collect([8080], [_port_event("e", 8080)])

    assert "AEGIS-LISTEN-001" in view.rows[0].reasons_summary


def test_adapter_preserves_finding_ids() -> None:
    view = _collect([8080], [_port_event("e", 8080)])

    assert view.rows[0].finding_ids == ("AEGIS-LISTEN-001:e",)


def test_adapter_preserves_scoring_version() -> None:
    view = collect_risk_view(
        engine=RiskEngine(RiskSettings(scoring_version="2")),
        events_provider=lambda: [_port_event("e", 8080)],
        detection_engine_provider=lambda: _detection_engine([8080]),
    )

    assert view.rows[0].scoring_version == "2"
    assert view.posture.scoring_version == "2"


def test_adapter_contributor_conversion() -> None:
    contributor = RiskContributor(
        finding_id="AEGIS-LISTEN-001:evt-1",
        rule_id="AEGIS-LISTEN-001",
        severity=Severity.MEDIUM,
        contribution=25,
        reason="AEGIS-LISTEN-001 (medium) contributed 25: port",
    )
    details = describe_assessment(_assessment(contributors=(contributor,)))

    assert details["contributor.1.finding_id"] == "AEGIS-LISTEN-001:evt-1"
    assert details["contributor.1.rule_id"] == "AEGIS-LISTEN-001"
    assert details["contributor.1.contribution"] == "25"


def test_adapter_anomaly_conversion() -> None:
    signal = AnomalySignal(
        source="isolation_forest",
        score=0.82,
        confidence=0.9,
        model_version="2026-01-01",
        reason="demo",
    )
    details = describe_assessment(_assessment(anomaly=signal))

    assert details["anomaly.source"] == "isolation_forest"
    assert details["anomaly.score"] == "0.82"
    assert details["anomaly.model_version"] == "2026-01-01"


def test_adapter_no_anomaly_is_honest() -> None:
    details = describe_assessment(_assessment(anomaly=None))

    assert details["anomaly"] == "None"


def test_adapter_supports_empty_assessments() -> None:
    view = collect_risk_view(
        engine=_risk_engine(),
        events_provider=lambda: [],
        detection_engine_provider=lambda: _detection_engine([8080]),
    )

    assert view.available is True
    assert view.count == 0
    assert view.rows == ()


def test_adapter_no_engine_is_honest() -> None:
    view = collect_risk_view(engine_provider=lambda: None)

    assert view.available is True
    assert view.count == 0
    assert view.posture.running is False
    assert view.posture.scoring_version is None


def test_adapter_read_failure_is_safe() -> None:
    class _Boom:
        @property
        def settings(self) -> object:
            raise RuntimeError("boom")

        def assess_many(self, items: object) -> object:
            raise RuntimeError("boom")

    view = collect_risk_view(
        engine=_Boom(),  # type: ignore[arg-type]
        events_provider=lambda: [_port_event("e", 8080)],
        detection_engine_provider=lambda: _detection_engine([8080]),
    )

    assert view.available is False
    assert view.error == RISK_ERROR
    assert view.rows == ()


def test_adapter_malformed_optional_data_is_safe() -> None:
    details = describe_assessment(_assessment(reasons=(), finding_ids=(), contributors=()))

    assert details["reasons"] == MISSING
    assert details["finding_ids"] == MISSING
    assert details["anomaly"] == "None"


def test_adapter_reasons_are_redacted() -> None:
    summary = reasons_summary(("app --password=hunter2", "api_key=abc123"))

    assert "hunter2" not in summary
    assert "abc123" not in summary
    assert "***REDACTED***" in summary


# --- Page ------------------------------------------------------------------


def test_page_constructs(app: QApplication) -> None:
    page = RiskPage(provider=_empty_view)

    assert isinstance(page, BasePage)
    assert page.PAGE_KEY == "risk"
    assert page.TITLE == "Risk"
    assert page.column_headers()[0] == "Timestamp"
    assert "Score" in page.column_headers()


def test_no_risk_evaluation_on_startup(app: QApplication) -> None:
    calls: list[int] = []

    def provider() -> RiskSnapshotView:
        calls.append(1)
        return _empty_view()

    page = RiskPage(provider=provider)

    assert calls == []
    assert page.row_count() == 0
    assert page.risk_count_text() == "Risk: No data"
    assert page.engine_status_text() == "Risk Engine: Not running"


def test_no_engine_honest_state(app: QApplication) -> None:
    page = RiskPage(provider=lambda: collect_risk_view(engine_provider=lambda: None))
    page.refresh()

    assert page.engine_status_text() == "Risk Engine: Not running"
    assert page.assessments_text() == "Assessments: No data"
    assert page.scoring_version_text() == "Scoring Version: —"
    assert page.risk_count_text() == "Risk: No data"
    assert page.has_error() is False


def test_assessments_populate_table(app: QApplication) -> None:
    view = _collect([8080], [_port_event("a", 8080), _port_event("b", 8080)])
    page = RiskPage(provider=lambda: view)

    page.refresh()

    assert page.row_count() == 2
    assert page.source_model.columnCount() == len(page.column_headers())


def test_assessment_count(app: QApplication) -> None:
    view = _collect([8080], [_port_event("a", 8080), _port_event("b", 8080)])
    page = RiskPage(provider=lambda: view)

    page.refresh()

    assert page.risk_count_text() == "Risk: 2"


def test_score_display(app: QApplication) -> None:
    view = _collect([8080], [_port_event("e", 8080)])
    page = RiskPage(provider=lambda: view)
    page.refresh()

    assert page.source_model.data(page.source_model.index(0, 4)) == "25"


def test_risk_level_display(app: QApplication) -> None:
    view = _collect([8080], [_port_event("e", 8080)])
    page = RiskPage(provider=lambda: view)
    page.refresh()

    assert page.source_model.data(page.source_model.index(0, 5)) == "medium"


def test_timestamp_sorting(app: QApplication) -> None:
    view = _collect(
        [8080],
        [_port_event("newer", 8080, timestamp=_TS2), _port_event("older", 8080, timestamp=_TS)],
    )
    page = RiskPage(provider=lambda: view)
    page.refresh()

    page.proxy_model.sort(0, Qt.SortOrder.AscendingOrder)
    assert page.proxy_model.index(0, 2).data() == "older"
    page.proxy_model.sort(0, Qt.SortOrder.DescendingOrder)
    assert page.proxy_model.index(0, 2).data() == "newer"


def test_score_sorting(app: QApplication) -> None:
    page = RiskPage(provider=_empty_view)
    page._snapshot = RiskSnapshotView(
        available=True,
        error=None,
        collected_at=_TS,
        posture=RiskPosture(True, 3, "1"),
        rows=(
            _row(assessment_id="a", risk_score=10),
            _row(assessment_id="b", risk_score=90),
            _row(assessment_id="c", risk_score=50),
        ),
        assessments=(),
    )
    page._model.set_rows(page._snapshot.rows)

    page.proxy_model.sort(4, Qt.SortOrder.AscendingOrder)
    order = [page.proxy_model.index(i, 4).data() for i in range(3)]
    assert order == ["10", "50", "90"]


def test_assessment_id_sorting(app: QApplication) -> None:
    view = _collect([8080], [_port_event("bbb", 8080), _port_event("aaa", 8080)])
    page = RiskPage(provider=lambda: view)
    page.refresh()

    page.proxy_model.sort(1, Qt.SortOrder.AscendingOrder)
    assert page.proxy_model.index(0, 1).data() == "1:aaa"


def test_selected_assessment_detail(app: QApplication) -> None:
    view = _collect([8080], [_port_event("evt-detail", 8080)])
    page = RiskPage(provider=lambda: view)
    page.refresh()

    page.show_detail_for(page.row_at(0))

    keys = page.detail_keys()
    assert "assessment_id" in keys
    assert "risk_score" in keys
    assert "risk_level" in keys
    assert "1:evt-detail" in page.detail_values()


def test_contributor_detail(app: QApplication) -> None:
    contributor = RiskContributor(
        finding_id="AEGIS-LISTEN-001:evt-1",
        rule_id="AEGIS-LISTEN-001",
        severity=Severity.MEDIUM,
        contribution=25,
        reason="contributed",
    )
    assessment = _assessment(contributors=(contributor,))
    page = RiskPage(provider=_empty_view)
    page._snapshot = RiskSnapshotView(
        available=True,
        error=None,
        collected_at=_TS,
        posture=RiskPosture(True, 1, "1"),
        rows=(_row(assessment_id=assessment.assessment_id),),
        assessments=(assessment,),
    )
    page._model.set_rows(page._snapshot.rows)

    page.show_detail_for(page.row_at(0))

    keys = page.detail_keys()
    assert "contributor.1.finding_id" in keys
    assert "contributor.1.rule_id" in keys
    assert "contributor.1.contribution" in keys


def test_anomaly_detail(app: QApplication) -> None:
    signal = AnomalySignal(
        source="isolation_forest", score=0.82, confidence=0.9, model_version="v1", reason="demo"
    )
    assessment = _assessment(anomaly=signal)
    page = RiskPage(provider=_empty_view)
    page._snapshot = RiskSnapshotView(
        available=True,
        error=None,
        collected_at=_TS,
        posture=RiskPosture(True, 1, "1"),
        rows=(_row(assessment_id=assessment.assessment_id),),
        assessments=(assessment,),
    )
    page._model.set_rows(page._snapshot.rows)

    page.show_detail_for(page.row_at(0))

    assert "anomaly.source" in page.detail_keys()
    assert "isolation_forest" in page.detail_values()


def test_refresh_behavior(app: QApplication) -> None:
    calls: list[int] = []

    def provider() -> RiskSnapshotView:
        calls.append(1)
        return _collect([8080], [_port_event("e", 8080)])

    page = RiskPage(provider=provider)

    page.refresh()
    assert len(calls) == 1
    assert page.row_count() == 1
    page.refresh()
    assert len(calls) == 2


def test_refresh_does_not_start_producers(app: QApplication) -> None:
    events = [_port_event("e", 8080)]
    page = RiskPage(
        provider=lambda: collect_risk_view(
            engine=_risk_engine(),
            events_provider=lambda: events,
            detection_engine_provider=lambda: _detection_engine([8080]),
        )
    )

    page.refresh()

    # The engines are stateless; refresh evaluates but starts nothing.
    assert len(events) == 1
    assert page.row_count() == 1


def test_safe_error_state(app: QApplication) -> None:
    def boom() -> RiskSnapshotView:
        raise RuntimeError("unexpected failure")

    page = RiskPage(provider=boom)

    assert page.refresh() is None
    assert page.has_error() is True
    assert page.error_text() == RISK_ERROR


def test_read_failure_view_shows_error(app: QApplication) -> None:
    page = RiskPage(
        provider=lambda: RiskSnapshotView(
            available=False,
            error=RISK_ERROR,
            collected_at=None,
            posture=RiskPosture(False, 0, None),
            rows=(),
        )
    )

    page.refresh()

    assert page.has_error() is True
    assert page.row_count() == 0


def test_no_destructive_controls(app: QApplication) -> None:
    page = RiskPage(provider=_empty_view)

    labels = {button.text().lower() for button in page.findChildren(QPushButton)}

    assert labels <= {"refresh"}
    for forbidden in (
        "block",
        "kill",
        "quarantine",
        "ignore",
        "dismiss",
        "remediate",
        "respond",
        "approve",
        "reject",
    ):
        assert not any(forbidden in label for label in labels)


def test_missing_host_displays_placeholder(app: QApplication) -> None:
    page = RiskPage(provider=_empty_view)
    page._snapshot = RiskSnapshotView(
        available=True,
        error=None,
        collected_at=_TS,
        posture=RiskPosture(True, 1, "1"),
        rows=(
            RiskRow(
                timestamp=_TS,
                assessment_id="1:evt-1",
                event_id="evt-1",
                host_id=None,
                risk_score=0,
                risk_level="informational",
                severity="info",
                reasons_summary=MISSING,
                finding_ids=(),
                scoring_version="1",
                has_anomaly=False,
            ),
        ),
        assessments=(_assessment(),),
    )
    page._model.set_rows(page._snapshot.rows)

    assert page.source_model.data(page.source_model.index(0, 3)) == MISSING


def test_navigation_regression(app: QApplication) -> None:
    window = MainWindow()
    try:
        window.navigate_to("risk")
        assert window.current_page_key == "risk"
        assert window.current_page is window.page("risk")

        window.navigate_to("dashboard")
        assert window.current_page_key == "dashboard"
    finally:
        window.close()


# --- Safety ----------------------------------------------------------------


def test_application_does_not_load_security_runtime() -> None:
    code = (
        "import sys; import aegis_desktop.app, aegis_desktop.window; "
        f"prefixes = {_FORBIDDEN_IMPORT_PREFIXES!r}; "
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
