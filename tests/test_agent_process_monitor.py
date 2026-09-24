"""Deterministic tests for the read-only process monitor.

psutil is mocked so tests never depend on the processes running on the developer
machine. Skipped automatically when the agent extra (psutil) is not installed.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest

pytest.importorskip("psutil", reason="agent extra not installed")

import psutil

from aegis_agent.__main__ import main
from aegis_agent.monitors.process import (
    ProcessChanges,
    ProcessIdentity,
    ProcessMonitor,
    ProcessRecord,
    ProcessSnapshot,
    changes_to_events,
    collect_process_snapshot,
    sanitize_command_line,
)
from aegis_agent.monitors.process import collector as process_collector
from aegis_shared.enums import EventCategory, EventType, Platform, SourceKind
from aegis_shared.events import HostRef, SourceRef
from aegis_shared.logging import REDACTED

_T0 = 1_700_000_000.0
_T1 = _T0 + 3600.0


class _NamedProcess:
    """Minimal stand-in for a parent process handle."""

    def __init__(self, name: str | None, error: Exception | None = None) -> None:
        self._name = name
        self._error = error

    def name(self) -> str | None:
        if self._error is not None:
            raise self._error
        return self._name


class FakeProcess:
    """Fake psutil.Process with per-field error injection."""

    def __init__(
        self,
        pid: int,
        *,
        ppid: int | None = None,
        name: str | None = None,
        parent_name: str | None = None,
        exe: str | None = None,
        username: str | None = None,
        cmdline: list[str] | None = None,
        create_time: float | None = None,
        errors: dict[str, Exception] | None = None,
    ) -> None:
        self.pid = pid
        self._values: dict[str, object] = {
            "ppid": ppid,
            "name": name,
            "exe": exe,
            "username": username,
            "cmdline": cmdline,
            "create_time": create_time,
        }
        self._errors = errors or {}
        self._parent = _NamedProcess(parent_name) if parent_name is not None else None

    def _value(self, field: str) -> Any:
        error = self._errors.get(field)
        if error is not None:
            raise error
        return self._values[field]

    def ppid(self) -> int | None:
        return self._value("ppid")

    def name(self) -> str | None:
        return self._value("name")

    def exe(self) -> str | None:
        return self._value("exe")

    def username(self) -> str | None:
        return self._value("username")

    def cmdline(self) -> list[str] | None:
        return self._value("cmdline")

    def create_time(self) -> float | None:
        return self._value("create_time")

    def parent(self) -> _NamedProcess | None:
        error = self._errors.get("parent")
        if error is not None:
            raise error
        return self._parent


def _patch(monkeypatch: pytest.MonkeyPatch, processes: list[FakeProcess]) -> None:
    """Make the collector enumerate exactly ``processes`` (live list)."""
    monkeypatch.setattr(
        process_collector.psutil, "process_iter", lambda *args, **kwargs: iter(processes)
    )


def _record(
    pid: int = 100,
    *,
    name: str | None = "app",
    username: str | None = None,
    create_time: datetime | None = None,
) -> ProcessRecord:
    return ProcessRecord(
        pid=pid,
        name=name,
        username=username,
        create_time=create_time if create_time is not None else datetime.fromtimestamp(_T0, tz=UTC),
    )


def _source() -> SourceRef:
    return SourceRef(kind=SourceKind.AGENT, id="agent-test")


def _host() -> HostRef:
    return HostRef(host_id="host-1", hostname="ws-01", platform=Platform.WINDOWS)


# --- Collection ------------------------------------------------------------


def test_collect_enumerates_processes_sorted_by_pid(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(
        monkeypatch,
        [
            FakeProcess(200, name="second", create_time=_T0),
            FakeProcess(100, name="first", create_time=_T0),
        ],
    )

    snapshot = collect_process_snapshot()

    assert [record.pid for record in snapshot.processes] == [100, 200]
    assert snapshot.processes[0].name == "first"


def test_missing_metadata_degrades_to_none(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, [FakeProcess(10)])

    record = collect_process_snapshot().processes[0]

    assert record.ppid is None
    assert record.name is None
    assert record.parent_name is None
    assert record.executable_path is None
    assert record.username is None
    assert record.command_line is None
    assert record.create_time is None


def test_blank_string_fields_normalize_to_none(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, [FakeProcess(10, name="", exe="", username="")])

    record = collect_process_snapshot().processes[0]

    assert record.name is None
    assert record.executable_path is None
    assert record.username is None


def test_parent_name_is_collected(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(
        monkeypatch,
        [FakeProcess(20, name="child", parent_name="explorer.exe", create_time=_T0)],
    )

    record = collect_process_snapshot().processes[0]

    assert record.parent_name == "explorer.exe"


def test_empty_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, [])

    snapshot = collect_process_snapshot()

    assert snapshot.processes == ()
    assert snapshot.by_identity() == {}


# --- Error handling --------------------------------------------------------


def test_no_such_process_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(
        monkeypatch,
        [
            FakeProcess(1, name="ok", create_time=_T0),
            FakeProcess(2, errors={"name": psutil.NoSuchProcess(2)}),
        ],
    )

    snapshot = collect_process_snapshot()

    assert [record.pid for record in snapshot.processes] == [1]


def test_zombie_process_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, [FakeProcess(3, errors={"name": psutil.ZombieProcess(3)})])

    assert collect_process_snapshot().processes == ()


def test_access_denied_keeps_process_with_none_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(
        monkeypatch,
        [
            FakeProcess(
                5,
                name="svc",
                create_time=_T0,
                errors={"exe": psutil.AccessDenied(5), "cmdline": psutil.AccessDenied(5)},
            )
        ],
    )

    record = collect_process_snapshot().processes[0]

    assert record.pid == 5
    assert record.name == "svc"
    assert record.executable_path is None
    assert record.command_line is None


def test_parent_access_denied_does_not_skip_process(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(
        monkeypatch,
        [
            FakeProcess(
                20, name="child", errors={"parent": psutil.AccessDenied(20)}, create_time=_T0
            )
        ],
    )

    record = collect_process_snapshot().processes[0]

    assert record.pid == 20
    assert record.parent_name is None


# --- Models & serialization ------------------------------------------------


def test_process_record_rejects_negative_pid() -> None:
    with pytest.raises(ValueError):
        ProcessRecord(pid=-1)


def test_process_record_rejects_naive_create_time() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        ProcessRecord(pid=1, create_time=datetime(2026, 1, 1))


def test_snapshot_json_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(
        monkeypatch,
        [FakeProcess(10, name="app", username="alice", cmdline=["app", "--x"], create_time=_T0)],
    )
    snapshot = collect_process_snapshot()

    payload = snapshot.to_json_dict()
    restored = ProcessSnapshot.model_validate(json.loads(json.dumps(payload)))

    assert restored == snapshot
    assert payload["processes"][0]["create_time"].endswith("Z")


# --- Identity --------------------------------------------------------------


def test_identity_is_stable_and_reliable() -> None:
    first = _record(pid=42)
    second = _record(pid=42)

    assert isinstance(first.identity, ProcessIdentity)
    assert first.identity.key == second.identity.key
    assert first.identity.is_reliable is True


def test_identity_without_create_time_is_unreliable() -> None:
    record = ProcessRecord(pid=7)

    assert record.identity.key == "7:unknown"
    assert record.identity.is_reliable is False


# --- Snapshot diffing ------------------------------------------------------


def test_process_start_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    processes = [FakeProcess(1, name="init", create_time=_T0)]
    _patch(monkeypatch, processes)
    monitor = ProcessMonitor()
    monitor.start()

    processes.append(FakeProcess(2, name="new", create_time=_T1))
    changes = monitor.poll()

    assert [record.pid for record in changes.started] == [2]
    assert changes.stopped == ()
    assert changes.is_empty is False


def test_process_stop_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    processes = [
        FakeProcess(1, name="a", create_time=_T0),
        FakeProcess(2, name="b", create_time=_T0),
    ]
    _patch(monkeypatch, processes)
    monitor = ProcessMonitor()
    monitor.start()

    processes.pop(0)
    changes = monitor.poll()

    assert changes.started == ()
    assert [record.pid for record in changes.stopped] == [1]


def test_pid_reuse_reports_stop_and_start(monkeypatch: pytest.MonkeyPatch) -> None:
    processes = [FakeProcess(1234, name="old", create_time=_T0)]
    _patch(monkeypatch, processes)
    monitor = ProcessMonitor()
    monitor.start()

    processes[0] = FakeProcess(1234, name="new", create_time=_T1)
    changes = monitor.poll()

    assert [record.name for record in changes.stopped] == ["old"]
    assert [record.name for record in changes.started] == ["new"]


def test_monitor_stop_clears_baseline(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, [FakeProcess(1, name="a", create_time=_T0)])
    monitor = ProcessMonitor()
    monitor.start()
    assert monitor.has_baseline is True

    monitor.stop()
    assert monitor.has_baseline is False

    changes = monitor.poll()
    assert [record.pid for record in changes.started] == [1]


# --- Event mapping ---------------------------------------------------------


def test_changes_to_events_maps_to_canonical_event() -> None:
    started = _record(pid=9, name="calc.exe", username="alice")
    stopped = _record(pid=10, name="old")
    changes = ProcessChanges(started=(started,), stopped=(stopped,))

    events = changes_to_events(changes, source=_source(), host=_host())

    assert [event.event_type for event in events] == [
        EventType.PROCESS_STARTED,
        EventType.PROCESS_STOPPED,
    ]
    first = events[0]
    assert first.category is EventCategory.HOST
    assert first.host is not None and first.host.host_id == "host-1"
    assert first.process is not None and first.process.pid == 9
    assert first.actor is not None and first.actor.user == "alice"
    assert first.timestamp.tzinfo is not None
    assert first.schema_version


# --- Command-line sanitization ---------------------------------------------


@pytest.mark.parametrize(
    ("raw", "secret"),
    [
        ("mysql -u root --password=hunter2", "hunter2"),
        ("app --token abc123", "abc123"),
        ("run PASSWORD=topsecret", "topsecret"),
        ("psql postgresql://user:s3cret@localhost/db", "s3cret"),
        ("curl -H Authorization: Bearer tok.en", "tok.en"),
    ],
)
def test_sanitize_command_line_redacts_secrets(raw: str, secret: str) -> None:
    result = sanitize_command_line(raw)

    assert result is not None
    assert secret not in result
    assert REDACTED in result


def test_sanitize_command_line_keeps_benign_command() -> None:
    assert sanitize_command_line("notepad.exe C:\\notes.txt") == "notepad.exe C:\\notes.txt"


def test_sanitize_command_line_none_and_empty() -> None:
    assert sanitize_command_line(None) is None
    assert sanitize_command_line("") is None


def test_sanitize_command_line_truncates() -> None:
    result = sanitize_command_line("x" * 5000)

    assert result is not None
    assert result.endswith("[truncated]")
    assert len(result) == 4096 + len("...[truncated]")


def test_collector_sanitizes_command_line(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(
        monkeypatch,
        [FakeProcess(11, name="app", cmdline=["app", "--password=hunter2"], create_time=_T0)],
    )

    record = collect_process_snapshot().processes[0]

    assert record.command_line is not None
    assert "hunter2" not in record.command_line
    assert REDACTED in record.command_line


# --- CLI -------------------------------------------------------------------


def test_cli_processes_text(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch(monkeypatch, [FakeProcess(4321, name="demo", username="alice", create_time=_T0)])

    exit_code = main(["processes"])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "Aegis process snapshot (1 processes)" in out
    assert "demo" in out
    assert "4321" in out


def test_cli_processes_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch(monkeypatch, [FakeProcess(4321, name="demo", create_time=_T0)])

    exit_code = main(["processes", "--json"])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert json.loads(out)["processes"][0]["pid"] == 4321


def test_cli_status_still_works(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["status"])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "inventory" in out
