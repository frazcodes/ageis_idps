"""Deterministic tests for the host event pipeline.

Events are constructed locally with fixed IDs and timestamps; no test depends on
the real process table, sockets or filesystem. A fixed clock makes envelopes
byte-for-byte reproducible.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from aegis_agent.__main__ import main
from aegis_agent.config import AgentSettings
from aegis_agent.monitors.file_integrity import FileChanges, FileRecord
from aegis_agent.monitors.port import PortChanges, PortRecord
from aegis_agent.monitors.process import ProcessChanges, ProcessRecord
from aegis_agent.pipeline import (
    EventBuffer,
    EventEnvelope,
    HostEventPipeline,
    collect_monitor_events,
    is_valid,
    validate_event,
)
from aegis_shared.enums import (
    AddressFamily,
    EventCategory,
    EventType,
    FileType,
    HashStatus,
    Platform,
    Severity,
    SourceKind,
    TransportProtocol,
)
from aegis_shared.events import (
    FileContext,
    HostRef,
    ProcessContext,
    SecurityEvent,
    SocketContext,
    SourceRef,
)

_TS = datetime(2026, 1, 1, tzinfo=UTC)


def _clock() -> datetime:
    return _TS


def _source() -> SourceRef:
    return SourceRef(kind=SourceKind.AGENT, id="agent-test")


def _host() -> HostRef:
    return HostRef(host_id="host-1", hostname="ws-01", platform=Platform.WINDOWS)


def _process_event(event_id: str = "proc-1", timestamp: datetime = _TS) -> SecurityEvent:
    return SecurityEvent.create(
        event_id=event_id,
        event_type=EventType.PROCESS_STARTED,
        severity=Severity.INFO,
        source=_source(),
        host=_host(),
        timestamp=timestamp,
        process=ProcessContext(pid=10, name="demo"),
    )


def _port_event(event_id: str = "port-1", timestamp: datetime = _TS) -> SecurityEvent:
    return SecurityEvent.create(
        event_id=event_id,
        event_type=EventType.PORT_LISTENING,
        source=_source(),
        host=_host(),
        timestamp=timestamp,
        socket=SocketContext(
            protocol=TransportProtocol.TCP,
            address_family=AddressFamily.IPV4,
            local_port=8080,
            status="LISTEN",
        ),
    )


def _file_event(event_id: str = "file-1", timestamp: datetime = _TS) -> SecurityEvent:
    return SecurityEvent.create(
        event_id=event_id,
        event_type=EventType.FILE_MODIFIED,
        source=_source(),
        host=_host(),
        timestamp=timestamp,
        file=FileContext(
            path="C:\\demo\\a.txt",
            file_type=FileType.REGULAR,
            hash_status=HashStatus.HASHED,
        ),
    )


# --- Validation ------------------------------------------------------------


def test_valid_event_accepted() -> None:
    pipeline = HostEventPipeline(clock=_clock)

    result = pipeline.submit(_process_event())

    assert result.accepted is True
    assert result.sequence == 0
    assert len(pipeline) == 1
    assert pipeline.stats.accepted == 1


def test_malformed_event_rejected() -> None:
    pipeline = HostEventPipeline(clock=_clock)
    invalid = _process_event().model_copy(update={"event_id": ""})

    result = pipeline.submit(invalid)

    assert result.accepted is False
    assert "event_id" in (result.reason or "")
    assert pipeline.stats.rejected == 1
    assert len(pipeline) == 0


def test_missing_required_fields_rejected() -> None:
    assert validate_event(_process_event().model_copy(update={"event_id": None})).valid is False
    assert validate_event(_process_event().model_copy(update={"event_type": None})).valid is False


def test_validation_rejects_bad_schema_version() -> None:
    event = _process_event().model_copy(update={"schema_version": "2.0.0"})

    result = validate_event(event)

    assert result.valid is False
    assert any(issue.field == "schema_version" for issue in result.issues)


def test_validation_rejects_malformed_schema_version() -> None:
    event = _process_event().model_copy(update={"schema_version": "not-a-version"})
    assert is_valid(event) is False


def test_validation_rejects_naive_timestamp() -> None:
    event = _process_event().model_copy(update={"timestamp": datetime(2026, 1, 1)})
    assert is_valid(event) is False


def test_validation_rejects_category_mismatch() -> None:
    event = _process_event().model_copy(update={"category": EventCategory.NETWORK})
    assert is_valid(event) is False


def test_validation_requires_context_per_event_type() -> None:
    assert is_valid(_process_event().model_copy(update={"process": None})) is False
    assert is_valid(_port_event().model_copy(update={"socket": None})) is False
    assert is_valid(_file_event().model_copy(update={"file": None})) is False


def test_validation_result_summary_is_deterministic() -> None:
    event = _process_event().model_copy(update={"event_id": "", "timestamp": datetime(2026, 1, 1)})
    first = validate_event(event).summary()
    second = validate_event(event).summary()
    assert first == second
    assert first is not None and "event_id" in first


# --- Buffer behavior -------------------------------------------------------


def test_fifo_order_preserved() -> None:
    pipeline = HostEventPipeline(clock=_clock)
    pipeline.submit_all([_process_event("a"), _process_event("b"), _process_event("c")])

    drained = pipeline.drain()

    assert [envelope.event.event_id for envelope in drained] == ["a", "b", "c"]


def test_buffer_capacity_enforced() -> None:
    pipeline = HostEventPipeline(max_events=2, clock=_clock)
    pipeline.submit_all([_process_event("a"), _process_event("b"), _process_event("c")])

    assert len(pipeline) == 2
    assert pipeline.stats.buffered == 2


def test_overflow_drops_oldest() -> None:
    pipeline = HostEventPipeline(max_events=2, clock=_clock)
    pipeline.submit_all([_process_event("a"), _process_event("b"), _process_event("c")])

    drained = pipeline.drain()

    assert [envelope.event.event_id for envelope in drained] == ["b", "c"]
    assert pipeline.stats.dropped == 1


def test_empty_buffer_behavior() -> None:
    pipeline = HostEventPipeline(clock=_clock)

    assert pipeline.is_empty
    assert len(pipeline) == 0
    assert pipeline.drain() == []
    assert pipeline.peek() == []
    assert pipeline.stats.buffered == 0


def test_peek_does_not_remove_and_keeps_order() -> None:
    pipeline = HostEventPipeline(clock=_clock)
    pipeline.submit_all([_process_event(f"e{index}") for index in range(5)])

    peeked = pipeline.peek()

    assert [envelope.event.event_id for envelope in peeked] == [f"e{index}" for index in range(5)]
    assert len(pipeline) == 5


def test_same_timestamp_preserves_insertion_order() -> None:
    pipeline = HostEventPipeline(clock=_clock)
    pipeline.submit_all(
        [
            _process_event("a", timestamp=_TS),
            _process_event("b", timestamp=_TS),
            _process_event("c", timestamp=_TS),
        ]
    )

    assert [envelope.event.event_id for envelope in pipeline.drain()] == ["a", "b", "c"]


def test_event_buffer_extend_reports_drops() -> None:
    buffer = EventBuffer(max_events=2)
    envelopes = [
        EventEnvelope(sequence=index, event=_process_event(f"e{index}")) for index in range(4)
    ]

    dropped = buffer.extend(envelopes)

    assert dropped == 2
    assert buffer.dropped == 2
    assert buffer.appended == 4
    assert [envelope.event.event_id for envelope in buffer.drain()] == ["e2", "e3"]


# --- Counters --------------------------------------------------------------


def test_counters_track_accepted_rejected_dropped_duplicates() -> None:
    pipeline = HostEventPipeline(max_events=1, clock=_clock)
    good = _process_event("a")
    pipeline.submit(good)
    pipeline.submit(good)  # duplicate -> rejected
    pipeline.submit(_process_event().model_copy(update={"event_id": ""}))  # invalid -> rejected
    pipeline.submit(_process_event("b"))  # overflow -> drops "a"

    stats = pipeline.stats

    assert stats.accepted == 2
    assert stats.duplicates == 1
    assert stats.rejected == 2
    assert stats.dropped == 1
    assert stats.buffered == 1
    assert stats.capacity == 1


def test_batch_insertion_returns_results() -> None:
    pipeline = HostEventPipeline(clock=_clock)

    results = pipeline.submit_all([_process_event("a"), _process_event("b")])

    assert [result.accepted for result in results] == [True, True]
    assert [result.sequence for result in results] == [0, 1]


def test_drain_returns_all_and_empties_buffer() -> None:
    pipeline = HostEventPipeline(clock=_clock)
    pipeline.submit_all([_process_event("a"), _process_event("b")])

    drained = pipeline.drain()

    assert len(drained) == 2
    assert pipeline.is_empty
    assert pipeline.drain() == []


# --- Deduplication ---------------------------------------------------------


def test_duplicate_event_id_rejected() -> None:
    pipeline = HostEventPipeline(clock=_clock)
    event = _process_event("dup")
    assert pipeline.submit(event).accepted is True

    second = pipeline.submit(event)

    assert second.accepted is False
    assert second.reason == "duplicate_event_id"
    assert pipeline.stats.duplicates == 1
    assert len(pipeline) == 1


def test_dedup_window_is_bounded() -> None:
    pipeline = HostEventPipeline(dedup_window=2, clock=_clock)
    first = _process_event("a")
    pipeline.submit(first)
    pipeline.submit(_process_event("b"))
    pipeline.submit(_process_event("c"))  # evicts "a" from the dedup window

    assert pipeline.submit(first).accepted is True


# --- Monitor integration ---------------------------------------------------


def test_process_event_enters_pipeline() -> None:
    pipeline = HostEventPipeline(clock=_clock)
    changes = ProcessChanges(started=(ProcessRecord(pid=1, name="p", create_time=_TS),))

    results = pipeline.submit_monitor_changes(
        source=_source(), host=_host(), process_changes=changes
    )

    assert results and all(result.accepted for result in results)
    assert pipeline.stats.accepted == 1


def test_port_event_enters_pipeline() -> None:
    pipeline = HostEventPipeline(clock=_clock)
    changes = PortChanges(
        started=(
            PortRecord(
                protocol=TransportProtocol.TCP,
                address_family=AddressFamily.IPV4,
                local_port=8000,
                status="LISTEN",
            ),
        )
    )

    pipeline.submit_monitor_changes(source=_source(), host=_host(), port_changes=changes)

    drained = pipeline.drain()
    assert [envelope.event.event_type for envelope in drained] == [EventType.PORT_LISTENING]


def test_file_event_enters_pipeline() -> None:
    pipeline = HostEventPipeline(clock=_clock)
    changes = FileChanges(
        created=(
            FileRecord(
                path="C:\\x.txt",
                file_type=FileType.REGULAR,
                hash_status=HashStatus.HASHED,
            ),
        )
    )

    pipeline.submit_monitor_changes(source=_source(), host=_host(), file_changes=changes)

    drained = pipeline.drain()
    assert [envelope.event.event_type for envelope in drained] == [EventType.FILE_CREATED]


def test_monitor_events_are_not_mutated_by_the_pipeline() -> None:
    changes = ProcessChanges(started=(ProcessRecord(pid=7, name="p", create_time=_TS),))
    events = collect_monitor_events(
        source=_source(), host=_host(), process_changes=changes, timestamp=_TS
    )
    assert len(events) == 1
    assert events[0].event_type is EventType.PROCESS_STARTED

    pipeline = HostEventPipeline(clock=_clock)
    pipeline.submit_all(events)
    drained = pipeline.drain()

    assert drained[0].event == events[0]


# --- Serialization ---------------------------------------------------------


def test_json_serialization_is_deterministic() -> None:
    pipeline = HostEventPipeline(clock=_clock)
    pipeline.submit(_file_event("fixed"))
    envelope = pipeline.drain()[0]

    first = json.dumps(envelope.to_json_dict(), sort_keys=True)
    second = json.dumps(envelope.to_json_dict(), sort_keys=True)

    assert first == second
    payload = envelope.to_json_dict()
    assert payload["event"]["event_id"] == "fixed"
    assert payload["sequence"] == 0
    assert payload["enqueued_at"].endswith("Z")


# --- Configuration & bounds ------------------------------------------------


def test_configuration_validation() -> None:
    assert AgentSettings().event_buffer_max_events == 1000
    with pytest.raises(ValueError):
        AgentSettings(event_buffer_max_events=0)
    with pytest.raises(ValueError):
        AgentSettings(event_buffer_max_events=1_000_001)
    with pytest.raises(ValueError):
        HostEventPipeline(max_events=0)
    with pytest.raises(ValueError):
        HostEventPipeline(dedup_window=0)


def test_buffer_never_exceeds_capacity() -> None:
    pipeline = HostEventPipeline(max_events=10, clock=_clock)

    for index in range(1000):
        pipeline.submit(_process_event(f"e{index}"))

    assert len(pipeline) == 10
    assert pipeline.stats.dropped == 990
    assert pipeline.stats.accepted == 1000


# --- CLI -------------------------------------------------------------------


def test_cli_events_text(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["events"])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "Aegis host event pipeline" in out
    assert "host.process.started" in out
    assert "host.port.listening" in out
    assert "host.file.modified" in out
    assert "duplicates=1" in out


def test_cli_events_json(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["events", "--json"])
    out = capsys.readouterr().out

    assert exit_code == 0
    payload = json.loads(out)
    assert payload["stats"]["accepted"] == 3
    assert payload["stats"]["duplicates"] == 1
    assert len(payload["events"]) == 3
    assert {entry["event"]["event_type"] for entry in payload["events"]} == {
        "host.process.started",
        "host.port.listening",
        "host.file.modified",
    }
