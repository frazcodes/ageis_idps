"""Deterministic tests for the Events page integration (GUI-6).

Events are constructed locally and submitted to a real in-memory
:class:`EventPipeline`; no test depends on real machine events or starts any
producer. Qt runs with the offscreen platform and no privileges.
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
from aegis_desktop.pages.events import EventsPage
from aegis_desktop.services.events import (
    EVENT_ERROR,
    EventSnapshotView,
    PipelinePosture,
    collect_event_view,
    describe_event,
)
from aegis_desktop.services.processes import MISSING
from aegis_desktop.window import MainWindow
from aegis_shared.enums import (
    AddressFamily,
    EventType,
    FileType,
    HashStatus,
    NetworkDirection,
    Platform,
    Severity,
    SourceKind,
    TransportProtocol,
)
from aegis_shared.events import (
    FileContext,
    HostRef,
    NetworkContext,
    ProcessContext,
    SecurityEvent,
    SocketContext,
    SourceRef,
)
from aegis_shared.pipeline import EventPipeline

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
    "aegis_shared.detection",
    "aegis_shared.risk",
)


@pytest.fixture(scope="module")
def app() -> QApplication:
    return create_application([])


def _source() -> SourceRef:
    return SourceRef(kind=SourceKind.AGENT, id="agent-test", version="0.1.0")


def _host() -> HostRef:
    return HostRef(host_id="host-1", hostname="ws-01", platform=Platform.WINDOWS)


def _process_event(
    event_id: str = "evt-1",
    *,
    timestamp: datetime = _TS,
    command_line: str | None = None,
) -> SecurityEvent:
    return SecurityEvent.create(
        event_id=event_id,
        event_type=EventType.PROCESS_STARTED,
        severity=Severity.INFO,
        source=_source(),
        host=_host(),
        timestamp=timestamp,
        process=ProcessContext(pid=1234, name="python.exe", command_line=command_line),
    )


def _socket_event(event_id: str = "evt-2", *, timestamp: datetime = _TS) -> SecurityEvent:
    return SecurityEvent.create(
        event_id=event_id,
        event_type=EventType.PORT_LISTENING,
        source=_source(),
        host=_host(),
        timestamp=timestamp,
        socket=SocketContext(
            local_address="0.0.0.0",
            local_port=8080,
            address_family=AddressFamily.IPV4,
            protocol=TransportProtocol.TCP,
            status="LISTEN",
        ),
    )


def _file_event(event_id: str = "evt-3", *, timestamp: datetime = _TS) -> SecurityEvent:
    return SecurityEvent.create(
        event_id=event_id,
        event_type=EventType.FILE_MODIFIED,
        source=_source(),
        host=_host(),
        timestamp=timestamp,
        file=FileContext(
            path="C:\\demo\\a.txt",
            operation="modified",
            file_type=FileType.REGULAR,
            hash_status=HashStatus.HASHED,
        ),
    )


def _network_event(event_id: str = "evt-4", *, timestamp: datetime = _TS) -> SecurityEvent:
    return SecurityEvent.create(
        event_id=event_id,
        event_type=EventType.NETWORK_PACKET_OBSERVED,
        source=SourceRef(kind=SourceKind.SENSOR, id="sensor-test"),
        timestamp=timestamp,
        network=NetworkContext(
            src_ip="10.0.0.1",
            dst_ip="203.0.113.9",
            dst_port=4444,
            protocol=TransportProtocol.TCP,
            direction=NetworkDirection.OUTBOUND,
            ip_version=AddressFamily.IPV4,
            flow_id="flow-1",
        ),
    )


def _pipeline_with(*events: SecurityEvent) -> EventPipeline:
    pipeline = EventPipeline()
    pipeline.submit_all(events)
    return pipeline


def _empty_view() -> EventSnapshotView:
    return EventSnapshotView(
        available=True,
        error=None,
        collected_at=None,
        posture=PipelinePosture(
            running=False,
            buffered=0,
            capacity=0,
            dedup_window=0,
            accepted=0,
            rejected=0,
            dropped=0,
            duplicates=0,
        ),
        rows=(),
        events=(),
    )


# --- Adapter ---------------------------------------------------------------


def test_adapter_converts_events() -> None:
    view = collect_event_view(pipeline=_pipeline_with(_process_event(), _socket_event()))

    assert view.available is True
    assert view.count == 2
    assert view.events[0].event_id == "evt-1"


def test_adapter_preserves_event_id() -> None:
    view = collect_event_view(pipeline=_pipeline_with(_process_event("evt-xyz")))

    assert view.rows[0].event_id == "evt-xyz"


def test_adapter_preserves_event_type() -> None:
    view = collect_event_view(pipeline=_pipeline_with(_socket_event()))

    assert view.rows[0].event_type == "host.port.listening"


def test_adapter_preserves_category() -> None:
    view = collect_event_view(pipeline=_pipeline_with(_network_event()))

    assert view.rows[0].category == "network"


def test_adapter_preserves_timestamp() -> None:
    view = collect_event_view(pipeline=_pipeline_with(_process_event(timestamp=_TS)))

    assert view.rows[0].timestamp == _TS


def test_adapter_preserves_host_id() -> None:
    view = collect_event_view(pipeline=_pipeline_with(_process_event()))

    assert view.rows[0].host_id == "host-1"


def test_adapter_context_summary_generic() -> None:
    view = collect_event_view(pipeline=_pipeline_with(_process_event()))

    assert view.rows[0].summary.startswith("Process:")


def test_adapter_process_context_summary() -> None:
    view = collect_event_view(pipeline=_pipeline_with(_process_event()))

    assert view.rows[0].summary == "Process: python.exe (PID 1234)"


def test_adapter_socket_context_summary() -> None:
    view = collect_event_view(pipeline=_pipeline_with(_socket_event()))

    assert view.rows[0].summary == "Socket: TCP 0.0.0.0:8080"


def test_adapter_file_context_summary() -> None:
    view = collect_event_view(pipeline=_pipeline_with(_file_event()))

    assert view.rows[0].summary == "File (modified): C:\\demo\\a.txt"


def test_adapter_handles_missing_context() -> None:
    event = SecurityEvent.create(
        event_id="evt-bare",
        event_type=EventType.PROCESS_STARTED,
        source=_source(),
        host=_host(),
        timestamp=_TS,
        process=ProcessContext(),
    )
    view = collect_event_view(pipeline=_pipeline_with(event))

    assert view.rows[0].summary == "Process: process"


def test_adapter_supports_empty_buffer() -> None:
    view = collect_event_view(pipeline=EventPipeline())

    assert view.available is True
    assert view.count == 0
    assert view.rows == ()


def test_adapter_redacts_sensitive_command_line() -> None:
    event = _process_event(command_line="app --password=hunter2 --token=abc123")
    view = collect_event_view(pipeline=_pipeline_with(event))

    assert "hunter2" not in view.rows[0].summary
    assert "abc123" not in view.rows[0].summary
    assert "***REDACTED***" in view.rows[0].summary


def test_adapter_pipeline_posture() -> None:
    pipeline = EventPipeline(max_events=10, dedup_window=7)
    pipeline.submit_all([_process_event("a"), _socket_event("b")])
    pipeline.submit(_process_event("a"))  # duplicate

    view = collect_event_view(pipeline=pipeline)

    assert view.posture.running is True
    assert view.posture.capacity == 10
    assert view.posture.buffered == 2
    assert view.posture.dedup_window == 7
    assert view.posture.accepted == 2
    assert view.posture.rejected == 1
    assert view.posture.duplicates == 1


def test_adapter_no_pipeline_reports_not_running() -> None:
    view = collect_event_view(pipeline_provider=lambda: None)

    assert view.available is True
    assert view.count == 0
    assert view.posture.running is False


def test_adapter_read_failure_is_safe() -> None:
    class _Boom:
        @property
        def stats(self) -> object:
            raise RuntimeError("boom")

        @property
        def dedup_window(self) -> int:
            raise RuntimeError("boom")

        def peek(self) -> object:
            raise RuntimeError("boom")

    view = collect_event_view(pipeline=_Boom())  # type: ignore[arg-type]

    assert view.available is False
    assert view.error == EVENT_ERROR
    assert view.rows == ()


# --- Detail ----------------------------------------------------------------


def test_describe_event_is_structured_and_safe() -> None:
    event = _process_event(command_line="app --password=hunter2")
    details = describe_event(event)

    assert details["event_id"] == "evt-1"
    assert details["event_type"] == "host.process.started"
    assert details["category"] == "host"
    assert details["host.host_id"] == "host-1"
    assert details["process.pid"] == "1234"
    assert "hunter2" not in details["process.command_line"]
    assert "repr" not in details["event_id"]


def test_describe_event_redacts_raw_secrets() -> None:
    event = _process_event().model_copy(update={"raw": {"api_key": "topsecret", "note": "ok"}})
    details = describe_event(event)

    assert details["raw.api_key"] == "***REDACTED***"
    assert details["raw.note"] == "ok"


# --- Page ------------------------------------------------------------------


def test_page_constructs(app: QApplication) -> None:
    page = EventsPage(provider=_empty_view)

    assert isinstance(page, BasePage)
    assert page.PAGE_KEY == "events"
    assert page.TITLE == "Events"
    assert page.column_headers()[0] == "Timestamp"


def test_initial_page_does_not_read_or_start(app: QApplication) -> None:
    calls: list[int] = []

    def provider() -> EventSnapshotView:
        calls.append(1)
        return _empty_view()

    page = EventsPage(provider=provider)

    assert calls == []
    assert page.row_count() == 0
    assert page.event_count_text() == "Events: No data"
    assert page.pipeline_status_text() == "Pipeline: Not running"


def test_empty_buffer_shows_no_data(app: QApplication) -> None:
    page = EventsPage(provider=_empty_view)
    page.refresh()

    assert page.row_count() == 0
    assert page.event_count_text() == "Events: No data"
    assert page.last_updated_text() == "Last updated: —"
    assert page.has_error() is False


def test_buffered_events_populate_table(app: QApplication) -> None:
    view = collect_event_view(pipeline=_pipeline_with(_process_event(), _socket_event()))
    page = EventsPage(provider=lambda: view)

    page.refresh()

    assert page.row_count() == 2
    assert page.source_model.columnCount() == len(page.column_headers())


def test_event_count_is_correct(app: QApplication) -> None:
    view = collect_event_view(
        pipeline=_pipeline_with(_process_event("a"), _socket_event("b"), _file_event("c"))
    )
    page = EventsPage(provider=lambda: view)

    page.refresh()

    assert page.event_count_text() == "Events: 3"


def test_refresh_reads_existing_events(app: QApplication) -> None:
    calls: list[int] = []

    def provider() -> EventSnapshotView:
        calls.append(1)
        return collect_event_view(pipeline=_pipeline_with(_process_event()))

    page = EventsPage(provider=provider)

    page.refresh()
    assert len(calls) == 1
    assert page.row_count() == 1
    page.refresh()
    assert len(calls) == 2


def test_refresh_does_not_start_producers(app: QApplication) -> None:
    pipeline = _pipeline_with(_process_event())
    page = EventsPage(provider=lambda: collect_event_view(pipeline=pipeline))

    page.refresh()

    # Reading never mutates the buffer (peek, not drain) and starts nothing.
    assert len(pipeline.peek()) == 1
    assert pipeline.stats.buffered == 1


def test_timestamp_sorting_works(app: QApplication) -> None:
    pipeline = _pipeline_with(
        _process_event("newer", timestamp=_TS2),
        _socket_event("older", timestamp=_TS),
    )
    page = EventsPage(provider=lambda: collect_event_view(pipeline=pipeline))
    page.refresh()

    page.proxy_model.sort(0, Qt.SortOrder.AscendingOrder)
    first = page.proxy_model.index(0, 1).data()
    assert first == "older"

    page.proxy_model.sort(0, Qt.SortOrder.DescendingOrder)
    assert page.proxy_model.index(0, 1).data() == "newer"


def test_event_id_and_type_sorting_works(app: QApplication) -> None:
    pipeline = _pipeline_with(
        _process_event("bbb"),
        _socket_event("aaa"),
    )
    page = EventsPage(provider=lambda: collect_event_view(pipeline=pipeline))
    page.refresh()

    page.proxy_model.sort(1, Qt.SortOrder.AscendingOrder)
    assert page.proxy_model.index(0, 1).data() == "aaa"

    page.proxy_model.sort(2, Qt.SortOrder.AscendingOrder)
    assert page.proxy_model.index(0, 2).data() == "host.port.listening"


def test_selected_event_detail_view_works(app: QApplication) -> None:
    pipeline = _pipeline_with(_process_event("evt-detail"))
    page = EventsPage(provider=lambda: collect_event_view(pipeline=pipeline))
    page.refresh()

    page.show_detail_for(page.row_at(0))

    keys = page.detail_keys()
    assert "event_id" in keys
    assert "event_type" in keys
    assert "host.host_id" in keys
    assert "evt-detail" in page.detail_values()


def test_sensitive_values_are_not_displayed(app: QApplication) -> None:
    pipeline = _pipeline_with(_process_event(command_line="app --password=hunter2"))
    page = EventsPage(provider=lambda: collect_event_view(pipeline=pipeline))
    page.refresh()

    model = page.source_model
    cells = [
        str(model.data(model.index(row, column), Qt.ItemDataRole.DisplayRole))
        for row in range(model.rowCount())
        for column in range(model.columnCount())
    ]
    assert not any("hunter2" in cell for cell in cells)

    page.show_detail_for(page.row_at(0))
    assert not any("hunter2" in value for value in page.detail_values())


def test_malformed_or_missing_context_does_not_crash(app: QApplication) -> None:
    bare = SecurityEvent.create(
        event_id="evt-bare",
        event_type=EventType.PROCESS_STARTED,
        source=_source(),
        host=None,
        timestamp=_TS,
        process=ProcessContext(),
    )
    pipeline = _pipeline_with(bare)
    page = EventsPage(provider=lambda: collect_event_view(pipeline=pipeline))

    page.refresh()
    page.show_detail_for(page.row_at(0))

    assert page.row_count() == 1
    assert page.row_at(0).host_id is None
    assert page.has_error() is False


def test_read_failure_produces_safe_error(app: QApplication) -> None:
    page = EventsPage(
        provider=lambda: EventSnapshotView(
            available=False,
            error=EVENT_ERROR,
            collected_at=None,
            posture=PipelinePosture(False, 0, 0, 0, 0, 0, 0, 0),
            rows=(),
        )
    )

    page.refresh()

    assert page.has_error() is True
    assert page.error_text() == EVENT_ERROR
    assert page.row_count() == 0


def test_provider_exception_produces_safe_error(app: QApplication) -> None:
    def boom() -> EventSnapshotView:
        raise RuntimeError("unexpected failure")

    page = EventsPage(provider=boom)

    assert page.refresh() is None
    assert page.has_error() is True
    assert page.error_text() == EVENT_ERROR


def test_pipeline_posture_is_displayed(app: QApplication) -> None:
    pipeline = EventPipeline(max_events=10, dedup_window=7)
    pipeline.submit_all([_process_event("a")])
    page = EventsPage(provider=lambda: collect_event_view(pipeline=pipeline))
    page.refresh()

    assert page.pipeline_status_text() == "Pipeline: Running"
    assert page.buffer_text() == "Buffer: 1/10"
    assert page.dedup_text() == "Dedup window: 7"


def test_no_destructive_or_response_control_exists(app: QApplication) -> None:
    page = EventsPage(provider=_empty_view)

    labels = {button.text().lower() for button in page.findChildren(QPushButton)}

    assert labels <= {"refresh"}
    for forbidden in (
        "block",
        "kill",
        "quarantine",
        "delete",
        "respond",
        "isolate",
        "remediate",
        "submit",
    ):
        assert not any(forbidden in label for label in labels)


def test_existing_navigation_still_works(app: QApplication) -> None:
    window = MainWindow()
    try:
        window.navigate_to("events")
        assert window.current_page_key == "events"
        assert window.current_page is window.page("events")

        window.navigate_to("dashboard")
        assert window.current_page_key == "dashboard"
    finally:
        window.close()


def test_missing_host_displays_placeholder(app: QApplication) -> None:
    event = SecurityEvent.create(
        event_id="evt-nohost",
        event_type=EventType.PROCESS_STARTED,
        source=_source(),
        host=None,
        timestamp=_TS,
        process=ProcessContext(pid=1, name="p"),
    )
    pipeline = _pipeline_with(event)
    page = EventsPage(provider=lambda: collect_event_view(pipeline=pipeline))
    page.refresh()

    assert page.source_model.data(page.source_model.index(0, 5)) == MISSING


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
