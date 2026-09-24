"""Deterministic tests for the Detections page integration (GUI-7).

Findings are produced by the real Step 8 engine over locally constructed events;
no test depends on real machine activity and no producer is started. Qt runs with
the offscreen platform and no privileges.
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
from aegis_desktop.pages.detections import DetectionsPage
from aegis_desktop.services.detections import (
    DETECTION_ERROR,
    DetectionPosture,
    FindingRow,
    FindingSnapshotView,
    collect_finding_view,
    describe_finding,
    evidence_summary,
)
from aegis_desktop.services.processes import MISSING
from aegis_desktop.window import MainWindow
from aegis_shared.detection import (
    ALL_RULE_IDS,
    DetectionEngine,
    DetectionFinding,
    DetectionSettings,
)
from aegis_shared.enums import (
    AddressFamily,
    EventCategory,
    EventType,
    Platform,
    Severity,
    SourceKind,
    TransportProtocol,
)
from aegis_shared.events import HostRef, ProcessContext, SecurityEvent, SocketContext, SourceRef

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
    "aegis_shared.risk",
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


def _process_event(event_id: str, path: str, *, timestamp: datetime = _TS) -> SecurityEvent:
    return SecurityEvent.create(
        event_id=event_id,
        event_type=EventType.PROCESS_STARTED,
        source=_source(),
        host=_host(),
        timestamp=timestamp,
        process=ProcessContext(pid=10, name="p", executable_path=path),
    )


def _engine(
    *, ports: list[int] | None = None, proc_patterns: list[str] | None = None
) -> DetectionEngine:
    settings = DetectionSettings(
        suspicious_listen_ports=ports or [],
        suspicious_process_path_patterns=proc_patterns or [],
    )
    return DetectionEngine.from_settings(settings)


def _finding(
    *,
    finding_id: str = "AEGIS-LISTEN-001:evt-1",
    rule_id: str = "AEGIS-LISTEN-001",
    severity: Severity = Severity.MEDIUM,
    title: str = "Unexpected listening port",
    event_id: str = "evt-1",
    timestamp: datetime = _TS,
    evidence: dict[str, str] | None = None,
    tags: tuple[str, ...] = ("host", "port"),
) -> DetectionFinding:
    return DetectionFinding(
        finding_id=finding_id,
        rule_id=rule_id,
        rule_name=title,
        severity=severity,
        title=title,
        description="Demo finding.",
        event_id=event_id,
        event_type=EventType.PORT_LISTENING,
        category=EventCategory.HOST,
        timestamp=timestamp,
        host_id="host-1",
        evidence=evidence if evidence is not None else {"local_port": "8080"},
        tags=tags,
    )


def _empty_view() -> FindingSnapshotView:
    return FindingSnapshotView(
        available=True,
        error=None,
        collected_at=None,
        posture=DetectionPosture(running=False, enabled=False, rule_count=0, findings=0),
        rows=(),
        findings=(),
    )


def _row(
    *,
    finding_id: str = "AEGIS-LISTEN-001:evt-1",
    rule_id: str = "AEGIS-LISTEN-001",
    severity: str = "medium",
    event_id: str = "evt-1",
    evidence_summary: str = "local_port=8080",
    tags: tuple[str, ...] = ("host", "port"),
) -> FindingRow:
    return FindingRow(
        timestamp=_TS,
        finding_id=finding_id,
        rule_id=rule_id,
        severity=severity,
        title="Title",
        event_id=event_id,
        event_type="host.port.listening",
        category="host",
        host_id="host-1",
        description="Description",
        evidence_summary=evidence_summary,
        tags=tags,
    )


# --- Adapter ---------------------------------------------------------------


def test_adapter_converts_findings() -> None:
    view = collect_finding_view(
        engine=_engine(ports=[8080]),
        events_provider=lambda: [_port_event("evt-1", 8080)],
    )

    assert view.available is True
    assert view.count == 1
    assert view.findings[0].event_id == "evt-1"


def test_adapter_preserves_finding_id() -> None:
    view = collect_finding_view(
        engine=_engine(ports=[8080]),
        events_provider=lambda: [_port_event("evt-9", 8080)],
    )

    assert view.rows[0].finding_id == "AEGIS-LISTEN-001:evt-9"


def test_adapter_preserves_rule_id() -> None:
    view = collect_finding_view(
        engine=_engine(proc_patterns=["*public*"]),
        events_provider=lambda: [_process_event("e", "C:\\Users\\public\\x.exe")],
    )

    assert view.rows[0].rule_id == "AEGIS-PROC-001"


def test_adapter_preserves_severity() -> None:
    view = collect_finding_view(
        engine=_engine(proc_patterns=["*public*"]),
        events_provider=lambda: [_process_event("e", "C:\\Users\\public\\x.exe")],
    )

    assert view.rows[0].severity == "high"


def test_adapter_preserves_title() -> None:
    view = collect_finding_view(
        engine=_engine(ports=[8080]),
        events_provider=lambda: [_port_event("e", 8080)],
    )

    assert view.rows[0].title == "Unexpected listening port"


def test_adapter_preserves_description() -> None:
    view = collect_finding_view(
        engine=_engine(ports=[8080]),
        events_provider=lambda: [_port_event("e", 8080)],
    )

    assert view.rows[0].description


def test_adapter_preserves_event_id() -> None:
    view = collect_finding_view(
        engine=_engine(ports=[8080]),
        events_provider=lambda: [_port_event("evt-abc", 8080)],
    )

    assert view.rows[0].event_id == "evt-abc"


def test_adapter_timestamp_comes_from_event() -> None:
    view = collect_finding_view(
        engine=_engine(ports=[8080]),
        events_provider=lambda: [_port_event("e", 8080, timestamp=_TS2)],
    )

    assert view.rows[0].timestamp == _TS2


def test_adapter_evidence_summary() -> None:
    assert evidence_summary({"local_port": "8080", "protocol": "tcp"}) == (
        "local_port=8080 protocol=tcp"
    )
    assert evidence_summary({}) == MISSING


def test_adapter_preserves_tags() -> None:
    view = collect_finding_view(
        engine=_engine(ports=[8080]),
        events_provider=lambda: [_port_event("e", 8080)],
    )

    assert "host" in view.rows[0].tags
    assert "port" in view.rows[0].tags


def test_adapter_redacts_sensitive_evidence() -> None:
    finding = _finding(evidence={"command_line": "app --password=hunter2", "api_key": "topsecret"})
    summary = evidence_summary(dict(finding.evidence))

    assert "hunter2" not in summary
    assert "topsecret" not in summary
    assert "***REDACTED***" in summary


def test_adapter_supports_empty_findings() -> None:
    view = collect_finding_view(engine=_engine(ports=[8080]), events_provider=lambda: [])

    assert view.available is True
    assert view.count == 0
    assert view.rows == ()


def test_adapter_no_engine_is_honest() -> None:
    view = collect_finding_view(engine_provider=lambda: None)

    assert view.available is True
    assert view.count == 0
    assert view.posture.running is False
    assert view.posture.rule_count == 0


def test_adapter_read_failure_is_safe() -> None:
    class _Boom:
        @property
        def enabled(self) -> bool:
            raise RuntimeError("boom")

        @property
        def rules(self) -> object:
            raise RuntimeError("boom")

        def evaluate_many(self, events: object) -> object:
            raise RuntimeError("boom")

    view = collect_finding_view(engine=_Boom(), events_provider=lambda: [])  # type: ignore[arg-type]

    assert view.available is False
    assert view.error == DETECTION_ERROR
    assert view.rows == ()


def test_adapter_rule_count_from_engine() -> None:
    view = collect_finding_view(engine=_engine(ports=[8080]), events_provider=lambda: [])

    assert view.posture.running is True
    assert view.posture.rule_count == len(ALL_RULE_IDS)


def test_describe_finding_is_structured_and_safe() -> None:
    finding = _finding(evidence={"local_port": "8080", "command_line": "app --password=hunter2"})
    details = describe_finding(finding)

    assert details["finding_id"] == finding.finding_id
    assert details["rule_id"] == finding.rule_id
    assert details["severity"] == "medium"
    assert details["event_id"] == "evt-1"
    assert details["tags"] == "host, port"
    assert "8080" in details["evidence.local_port"]
    assert "hunter2" not in details["evidence.command_line"]


# --- Page ------------------------------------------------------------------


def test_page_constructs(app: QApplication) -> None:
    page = DetectionsPage(provider=_empty_view)

    assert isinstance(page, BasePage)
    assert page.PAGE_KEY == "detections"
    assert page.TITLE == "Detections"
    assert page.column_headers()[0] == "Timestamp"


def test_initial_page_does_not_start_detection(app: QApplication) -> None:
    calls: list[int] = []

    def provider() -> FindingSnapshotView:
        calls.append(1)
        return _empty_view()

    page = DetectionsPage(provider=provider)

    assert calls == []
    assert page.row_count() == 0
    assert page.detection_count_text() == "Detections: No data"
    assert page.engine_status_text() == "Detection Engine: Not running"


def test_no_engine_state_is_honest(app: QApplication) -> None:
    page = DetectionsPage(provider=lambda: collect_finding_view(engine_provider=lambda: None))
    page.refresh()

    assert page.engine_status_text() == "Detection Engine: Not running"
    assert page.rules_text() == "Rules: —"
    assert page.detection_count_text() == "Detections: No data"
    assert page.has_error() is False


def test_findings_populate_table(app: QApplication) -> None:
    view = collect_finding_view(
        engine=_engine(ports=[8080]),
        events_provider=lambda: [_port_event("a", 8080), _port_event("b", 8080)],
    )
    page = DetectionsPage(provider=lambda: view)

    page.refresh()

    assert page.row_count() == 2
    assert page.source_model.columnCount() == len(page.column_headers())


def test_finding_count_is_correct(app: QApplication) -> None:
    view = collect_finding_view(
        engine=_engine(ports=[8080]),
        events_provider=lambda: [_port_event("a", 8080), _port_event("b", 8080)],
    )
    page = DetectionsPage(provider=lambda: view)

    page.refresh()

    assert page.detection_count_text() == "Detections: 2"


def test_refresh_reads_existing_state(app: QApplication) -> None:
    calls: list[int] = []

    def provider() -> FindingSnapshotView:
        calls.append(1)
        return collect_finding_view(
            engine=_engine(ports=[8080]), events_provider=lambda: [_port_event("a", 8080)]
        )

    page = DetectionsPage(provider=provider)

    page.refresh()
    assert len(calls) == 1
    assert page.row_count() == 1
    page.refresh()
    assert len(calls) == 2


def test_refresh_does_not_start_producers(app: QApplication) -> None:
    events = [_port_event("a", 8080)]
    page = DetectionsPage(
        provider=lambda: collect_finding_view(
            engine=_engine(ports=[8080]), events_provider=lambda: events
        )
    )

    page.refresh()

    # The engine is stateless; refresh evaluates but starts nothing.
    assert len(events) == 1
    assert page.row_count() == 1


def test_timestamp_sorting_works(app: QApplication) -> None:
    view = collect_finding_view(
        engine=_engine(ports=[8080]),
        events_provider=lambda: [
            _port_event("newer", 8080, timestamp=_TS2),
            _port_event("older", 8080, timestamp=_TS),
        ],
    )
    page = DetectionsPage(provider=lambda: view)
    page.refresh()

    page.proxy_model.sort(0, Qt.SortOrder.AscendingOrder)
    assert page.proxy_model.index(0, 5).data() == "older"
    page.proxy_model.sort(0, Qt.SortOrder.DescendingOrder)
    assert page.proxy_model.index(0, 5).data() == "newer"


def test_severity_sorting_works(app: QApplication) -> None:
    page = DetectionsPage(provider=_empty_view)
    page._snapshot = FindingSnapshotView(
        available=True,
        error=None,
        collected_at=_TS,
        posture=DetectionPosture(True, True, 5, 3),
        rows=(
            _row(severity="high", finding_id="f-high"),
            _row(severity="low", finding_id="f-low"),
            _row(severity="critical", finding_id="f-crit"),
        ),
        findings=(),
    )
    page._model.set_rows(page._snapshot.rows)

    page.proxy_model.sort(3, Qt.SortOrder.AscendingOrder)
    order = [page.proxy_model.index(i, 3).data() for i in range(3)]
    assert order == ["low", "high", "critical"]


def test_finding_and_rule_id_sorting_works(app: QApplication) -> None:
    view = collect_finding_view(
        engine=_engine(ports=[8080], proc_patterns=["*public*"]),
        events_provider=lambda: [
            _port_event("bbb", 8080),
            _process_event("aaa", "C:\\Users\\public\\x.exe"),
        ],
    )
    page = DetectionsPage(provider=lambda: view)
    page.refresh()

    page.proxy_model.sort(2, Qt.SortOrder.AscendingOrder)
    assert page.proxy_model.index(0, 2).data() == "AEGIS-LISTEN-001"
    page.proxy_model.sort(2, Qt.SortOrder.DescendingOrder)
    assert page.proxy_model.index(0, 2).data() == "AEGIS-PROC-001"


def test_selected_finding_detail_works(app: QApplication) -> None:
    view = collect_finding_view(
        engine=_engine(ports=[8080]), events_provider=lambda: [_port_event("evt-detail", 8080)]
    )
    page = DetectionsPage(provider=lambda: view)
    page.refresh()

    page.show_detail_for(page.row_at(0))

    keys = page.detail_keys()
    assert "Finding Id" in keys
    assert "Rule Id" in keys
    assert "Severity" in keys


def test_sensitive_evidence_is_not_exposed(app: QApplication) -> None:
    finding = _finding(evidence={"command_line": "app --password=hunter2"})
    page = DetectionsPage(provider=_empty_view)
    page._snapshot = FindingSnapshotView(
        available=True,
        error=None,
        collected_at=_TS,
        posture=DetectionPosture(True, True, 5, 1),
        rows=(
            _row(
                finding_id=finding.finding_id,
                evidence_summary=evidence_summary(dict(finding.evidence)),
            ),
        ),
        findings=(finding,),
    )
    page._model.set_rows(page._snapshot.rows)

    model = page.source_model
    cells = [
        str(model.data(model.index(r, c), Qt.ItemDataRole.DisplayRole))
        for r in range(model.rowCount())
        for c in range(model.columnCount())
    ]
    assert not any("hunter2" in cell for cell in cells)

    page.show_detail_for(page.row_at(0))
    assert not any("hunter2" in value for value in page.detail_values())


def test_malformed_missing_data_does_not_crash(app: QApplication) -> None:
    finding = _finding(evidence={}, tags=())
    page = DetectionsPage(provider=_empty_view)
    page._snapshot = FindingSnapshotView(
        available=True,
        error=None,
        collected_at=_TS,
        posture=DetectionPosture(True, True, 5, 1),
        rows=(_row(finding_id=finding.finding_id, tags=()),),
        findings=(finding,),
    )
    page._model.set_rows(page._snapshot.rows)

    page.show_detail_for(page.row_at(0))

    assert page.row_count() == 1
    assert page.has_error() is False
    assert page.source_model.data(page.source_model.index(0, 8)) == MISSING


def test_read_failure_produces_safe_error(app: QApplication) -> None:
    page = DetectionsPage(
        provider=lambda: FindingSnapshotView(
            available=False,
            error=DETECTION_ERROR,
            collected_at=None,
            posture=DetectionPosture(False, False, 0, 0),
            rows=(),
        )
    )

    page.refresh()

    assert page.has_error() is True
    assert page.error_text() == DETECTION_ERROR
    assert page.row_count() == 0


def test_provider_exception_produces_safe_error(app: QApplication) -> None:
    def boom() -> FindingSnapshotView:
        raise RuntimeError("unexpected failure")

    page = DetectionsPage(provider=boom)

    assert page.refresh() is None
    assert page.has_error() is True
    assert page.error_text() == DETECTION_ERROR


def test_no_response_or_destructive_control_exists(app: QApplication) -> None:
    page = DetectionsPage(provider=_empty_view)

    labels = {button.text().lower() for button in page.findChildren(QPushButton)}

    assert labels <= {"refresh"}
    for forbidden in (
        "ignore",
        "delete",
        "quarantine",
        "kill",
        "block",
        "isolate",
        "respond",
        "remediate",
        "execute",
    ):
        assert not any(forbidden in label for label in labels)


def test_existing_navigation_still_works(app: QApplication) -> None:
    window = MainWindow()
    try:
        window.navigate_to("detections")
        assert window.current_page_key == "detections"
        assert window.current_page is window.page("detections")

        window.navigate_to("dashboard")
        assert window.current_page_key == "dashboard"
    finally:
        window.close()


# --- Safety / import -------------------------------------------------------


def test_application_does_not_load_security_engines() -> None:
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
