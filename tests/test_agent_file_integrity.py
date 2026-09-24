"""Deterministic tests for read-only file-integrity monitoring.

All tests use pytest's ``tmp_path``; none depend on the real machine's
filesystem layout and none require elevated privileges (symlink tests skip when
the platform refuses to create symlinks).
"""

from __future__ import annotations

import builtins
import hashlib
import json
import os
import stat as stat_module
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from aegis_agent.__main__ import main
from aegis_agent.config import SymlinkPolicy
from aegis_agent.monitors.file_integrity import (
    FileCollector,
    FileIntegrityMonitor,
    FileRecord,
    FileSnapshot,
    changes_to_events,
    collect_file_snapshot,
)
from aegis_shared.enums import (
    EventCategory,
    EventType,
    FileType,
    HashStatus,
    Platform,
    SourceKind,
)
from aegis_shared.events import HostRef, SourceRef
from aegis_shared.version import EVENT_SCHEMA_VERSION


def _write(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def _collector(*paths: Path, **kwargs: object) -> FileCollector:
    return FileCollector(paths=[str(path) for path in paths], **kwargs)  # type: ignore[arg-type]


def _key(path: Path) -> str:
    return os.path.normcase(os.path.normpath(os.path.abspath(str(path))))


def _record_for(snapshot: FileSnapshot, path: Path) -> FileRecord:
    matches = [record for record in snapshot.files if record.identity.key == _key(path)]
    assert matches, f"no record for {path}"
    return matches[0]


def _names(records: tuple[FileRecord, ...]) -> set[str]:
    return {Path(record.path).name for record in records}


def _make_symlink(link: Path, target: Path) -> None:
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not supported in this environment")


def _fake_stat_result(
    mode: int, *, size: int = 0, mtime: float = 1_700_000_000.0
) -> os.stat_result:
    return os.stat_result((mode, 0, 0, 1, 0, 0, size, mtime, mtime, mtime))


def _source() -> SourceRef:
    return SourceRef(kind=SourceKind.AGENT, id="agent-test")


def _host() -> HostRef:
    return HostRef(host_id="host-1", hostname="ws-01", platform=Platform.WINDOWS)


# --- Baseline & basic change detection ------------------------------------


def test_baseline_creation(tmp_path: Path) -> None:
    _write(tmp_path / "a.txt", "alpha")

    snapshot = collect_file_snapshot([str(tmp_path)])

    names = _names(snapshot.files)
    assert "a.txt" in names
    assert tmp_path.name in names  # the configured directory itself is recorded


def test_unchanged_file_produces_no_event(tmp_path: Path) -> None:
    _write(tmp_path / "a.txt", "alpha")
    monitor = FileIntegrityMonitor(collector=_collector(tmp_path))
    monitor.start()

    changes = monitor.poll()

    assert changes.is_empty
    assert changes.created == ()
    assert changes.modified == ()
    assert changes.deleted == ()


def test_new_file_created(tmp_path: Path) -> None:
    _write(tmp_path / "a.txt", "alpha")
    monitor = FileIntegrityMonitor(collector=_collector(tmp_path))
    monitor.start()

    _write(tmp_path / "b.txt", "beta")
    changes = monitor.poll()

    assert "b.txt" in _names(changes.created)
    assert "b.txt" not in {Path(m.current.path).name for m in changes.modified}
    assert changes.deleted == ()


def test_modified_file_detected(tmp_path: Path) -> None:
    target = _write(tmp_path / "a.txt", "alpha")
    monitor = FileIntegrityMonitor(collector=_collector(tmp_path))
    monitor.start()

    _write(target, "alpha-changed-content")
    changes = monitor.poll()

    regular = [m for m in changes.modified if m.current.file_type is FileType.REGULAR]
    assert len(regular) == 1
    assert Path(regular[0].current.path).name == "a.txt"
    assert regular[0].previous.sha256 != regular[0].current.sha256


def test_deleted_file_detected(tmp_path: Path) -> None:
    target = _write(tmp_path / "a.txt", "alpha")
    monitor = FileIntegrityMonitor(collector=_collector(tmp_path))
    monitor.start()

    target.unlink()
    changes = monitor.poll()

    assert "a.txt" in _names(changes.deleted)


def test_repeated_unchanged_snapshots_do_not_duplicate_events(tmp_path: Path) -> None:
    _write(tmp_path / "a.txt", "alpha")
    monitor = FileIntegrityMonitor(collector=_collector(tmp_path))
    monitor.start()

    assert monitor.poll().is_empty
    assert monitor.poll().is_empty
    assert monitor.poll().is_empty


def test_type_change_is_reported_as_modification(tmp_path: Path) -> None:
    target = tmp_path / "thing"
    _write(target, "data")
    monitor = FileIntegrityMonitor(collector=_collector(tmp_path))
    monitor.start()

    target.unlink()
    target.mkdir()
    changes = monitor.poll()

    modified = [m for m in changes.modified if m.current.identity.key == _key(target)]
    assert len(modified) == 1
    assert modified[0].current.file_type is FileType.DIRECTORY
    assert "thing" not in _names(changes.created)
    assert "thing" not in _names(changes.deleted)


# --- Hashing ---------------------------------------------------------------


def test_sha256_correctness(tmp_path: Path) -> None:
    target = _write(tmp_path / "a.txt", "hello")

    record = _record_for(_collector(target).collect(), target)

    assert record.sha256 == hashlib.sha256(b"hello").hexdigest()
    assert record.hash_status is HashStatus.HASHED


def test_file_over_max_size_is_not_hashed(tmp_path: Path) -> None:
    target = _write(tmp_path / "big.bin", "x" * 100)

    record = _record_for(_collector(target, max_hash_bytes=10).collect(), target)

    assert record.sha256 is None
    assert record.hash_status is HashStatus.SKIPPED_SIZE


def test_file_under_max_size_is_hashed(tmp_path: Path) -> None:
    target = _write(tmp_path / "small.bin", "x" * 10)

    record = _record_for(_collector(target, max_hash_bytes=1024).collect(), target)

    assert record.hash_status is HashStatus.HASHED


def test_zero_max_hash_disables_hashing(tmp_path: Path) -> None:
    target = _write(tmp_path / "a.txt", "data")

    record = _record_for(_collector(target, max_hash_bytes=0).collect(), target)

    assert record.sha256 is None
    assert record.hash_status is HashStatus.SKIPPED_SIZE


def test_directory_hash_status_is_not_applicable(tmp_path: Path) -> None:
    sub = tmp_path / "sub"
    sub.mkdir()

    record = _record_for(_collector(sub).collect(), sub)

    assert record.file_type is FileType.DIRECTORY
    assert record.hash_status is HashStatus.NOT_APPLICABLE


def test_hash_status_is_part_of_change_signature() -> None:
    hashed = FileRecord(
        path="p",
        file_type=FileType.REGULAR,
        size_bytes=10,
        sha256="a" * 64,
        hash_status=HashStatus.HASHED,
    )
    unavailable = FileRecord(
        path="p",
        file_type=FileType.REGULAR,
        size_bytes=10,
        sha256=None,
        hash_status=HashStatus.SKIPPED_SIZE,
    )

    assert hashed.differs_from(unavailable)


# --- Error handling --------------------------------------------------------


def test_missing_configured_path_is_skipped(tmp_path: Path) -> None:
    snapshot = _collector(tmp_path / "does-not-exist").collect()

    assert snapshot.files == ()


def test_hash_permission_denied_is_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _write(tmp_path / "a.txt", "alpha")
    real_open = builtins.open

    def fake_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        try:
            is_target = os.path.abspath(str(file)) == os.path.abspath(str(target))
        except (TypeError, ValueError):
            is_target = False
        if is_target and "b" in mode:
            raise PermissionError("denied")
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fake_open)

    record = _record_for(_collector(target).collect(), target)

    assert record.sha256 is None
    assert record.hash_status is HashStatus.PERMISSION_DENIED


def test_directory_listing_permission_denied_is_graceful(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sub = tmp_path / "sub"
    sub.mkdir()
    _write(sub / "child.txt", "x")
    real_scandir = os.scandir

    def fake_scandir(path: Any = ".", *args: Any, **kwargs: Any) -> Any:
        if os.path.abspath(os.fspath(path)) == os.path.abspath(str(sub)):
            raise PermissionError("denied")
        return real_scandir(path, *args, **kwargs)

    monkeypatch.setattr(os, "scandir", fake_scandir)

    snapshot = _collector(sub).collect()

    names = _names(snapshot.files)
    assert "sub" in names  # the directory itself is still recorded
    assert "child.txt" not in names


# --- Symlink policy (mocked, platform-independent) -------------------------


def test_symlink_skip_policy_mocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    link = tmp_path / "link"
    monkeypatch.setattr(os, "lstat", lambda path: _fake_stat_result(stat_module.S_IFLNK, size=4))

    snapshot = _collector(link, symlink_policy=SymlinkPolicy.SKIP).collect()

    assert snapshot.files == ()


def test_symlink_report_policy_mocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    link = tmp_path / "link"
    monkeypatch.setattr(os, "lstat", lambda path: _fake_stat_result(stat_module.S_IFLNK, size=4))
    monkeypatch.setattr(os, "readlink", lambda path: "target")

    record = _collector(link, symlink_policy=SymlinkPolicy.REPORT).collect().files[0]

    assert record.file_type is FileType.SYMLINK
    assert record.is_symlink is True
    assert record.link_target == "target"
    assert record.sha256 is None
    assert record.hash_status is HashStatus.NOT_APPLICABLE


def test_symlink_follow_to_directory_mocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    link = tmp_path / "link"
    monkeypatch.setattr(os, "lstat", lambda path: _fake_stat_result(stat_module.S_IFLNK, size=4))
    monkeypatch.setattr(os, "readlink", lambda path: "somedir")
    monkeypatch.setattr(os, "stat", lambda path: _fake_stat_result(stat_module.S_IFDIR))

    record = _collector(link, symlink_policy=SymlinkPolicy.FOLLOW).collect().files[0]

    assert record.file_type is FileType.DIRECTORY
    assert record.is_symlink is True
    assert record.link_target == "somedir"
    assert record.hash_status is HashStatus.NOT_APPLICABLE


# --- Symlink policy (real filesystem, skipped where unsupported) -----------


def test_symlink_skip_policy_excludes_links(tmp_path: Path) -> None:
    target = _write(tmp_path / "real.txt", "alpha")
    _make_symlink(tmp_path / "link.txt", target)

    snapshot = _collector(tmp_path, symlink_policy=SymlinkPolicy.SKIP).collect()

    names = _names(snapshot.files)
    assert "link.txt" not in names
    assert "real.txt" in names


def test_symlink_report_policy_records_link(tmp_path: Path) -> None:
    target = _write(tmp_path / "real.txt", "alpha")
    link = tmp_path / "link.txt"
    _make_symlink(link, target)

    record = _record_for(_collector(tmp_path, symlink_policy=SymlinkPolicy.REPORT).collect(), link)

    assert record.file_type is FileType.SYMLINK
    assert record.is_symlink is True
    assert record.sha256 is None
    assert record.hash_status is HashStatus.NOT_APPLICABLE
    assert record.link_target is not None


def test_symlink_follow_policy_hashes_target(tmp_path: Path) -> None:
    target = _write(tmp_path / "real.txt", "alpha")
    link = tmp_path / "link.txt"
    _make_symlink(link, target)

    record = _record_for(_collector(tmp_path, symlink_policy=SymlinkPolicy.FOLLOW).collect(), link)

    assert record.file_type is FileType.REGULAR
    assert record.is_symlink is True
    assert record.sha256 == hashlib.sha256(b"alpha").hexdigest()


def test_symlinked_directory_is_not_traversed(tmp_path: Path) -> None:
    real_dir = tmp_path / "realdir"
    real_dir.mkdir()
    _write(real_dir / "inside.txt", "x")
    _make_symlink(tmp_path / "linkdir", real_dir)

    snapshot = _collector(tmp_path, symlink_policy=SymlinkPolicy.FOLLOW).collect()

    inside = [record for record in snapshot.files if Path(record.path).name == "inside.txt"]
    assert len(inside) == 1


# --- Scope -----------------------------------------------------------------


def test_nested_directory_is_traversed_recursively(tmp_path: Path) -> None:
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    _write(nested / "deep.txt", "x")

    snapshot = _collector(tmp_path).collect()

    assert "deep.txt" in _names(snapshot.files)


def test_multiple_configured_paths(tmp_path: Path) -> None:
    first = tmp_path / "d1"
    first.mkdir()
    _write(first / "one.txt", "1")
    second = tmp_path / "d2"
    second.mkdir()
    _write(second / "two.txt", "2")

    snapshot = _collector(first, second).collect()

    names = _names(snapshot.files)
    assert {"one.txt", "two.txt"} <= names


def test_file_identity_is_normalized_path(tmp_path: Path) -> None:
    target = _write(tmp_path / "a.txt", "alpha")

    record = _record_for(_collector(target).collect(), target)

    assert record.identity.key == _key(target)


# --- Events ----------------------------------------------------------------


def test_changes_to_events_maps_file_context(tmp_path: Path) -> None:
    target = _write(tmp_path / "a.txt", "alpha")
    monitor = FileIntegrityMonitor(collector=_collector(tmp_path))
    monitor.start()
    _write(target, "beta")
    changes = monitor.poll()

    events = changes_to_events(changes, source=_source(), host=_host())

    assert [event.event_type for event in events] == [EventType.FILE_MODIFIED]
    event = events[0]
    assert event.category is EventCategory.HOST
    assert event.host is not None and event.host.host_id == "host-1"
    assert event.file is not None
    assert event.file.path == str(target)
    assert event.file.operation == "modified"
    assert event.file.file_type is FileType.REGULAR
    assert event.file.hash_status is HashStatus.HASHED
    assert event.file.hashes["sha256"] == hashlib.sha256(b"beta").hexdigest()
    assert event.file.modified_at is not None
    assert event.timestamp.tzinfo is not None


def test_changes_to_events_orders_created_modified_deleted(tmp_path: Path) -> None:
    modified_target = _write(tmp_path / "modify.txt", "a")
    deleted_target = _write(tmp_path / "delete.txt", "b")
    monitor = FileIntegrityMonitor(collector=_collector(tmp_path))
    monitor.start()
    _write(modified_target, "a-changed")
    deleted_target.unlink()
    _write(tmp_path / "create.txt", "c")
    changes = monitor.poll()

    events = changes_to_events(changes, source=_source(), host=_host())
    types = [event.event_type for event in events]

    assert types[0] is EventType.FILE_CREATED
    assert types[-1] is EventType.FILE_DELETED
    assert EventType.FILE_MODIFIED in types


def test_event_serialization_is_deterministic(tmp_path: Path) -> None:
    target = _write(tmp_path / "a.txt", "alpha")
    monitor = FileIntegrityMonitor(collector=_collector(tmp_path))
    monitor.start()
    _write(target, "beta")
    events = changes_to_events(monitor.poll(), source=_source(), host=_host())

    payload = events[0].model_dump(mode="json")
    first = json.dumps(payload, sort_keys=True)
    second = json.dumps(events[0].model_dump(mode="json"), sort_keys=True)

    assert first == second
    assert payload["schema_version"] == EVENT_SCHEMA_VERSION


# --- CLI -------------------------------------------------------------------


def test_cli_files_text(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _write(tmp_path / "hello.txt", "hello")

    exit_code = main(["files", "--path", str(tmp_path)])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "Aegis file-integrity snapshot" in out
    assert "hello.txt" in out
    assert "hashed" in out


def test_cli_files_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _write(tmp_path / "hello.txt", "hello")

    exit_code = main(["files", "--path", str(tmp_path), "--json"])
    out = capsys.readouterr().out

    assert exit_code == 0
    payload = json.loads(out)
    assert any(Path(entry["path"]).name == "hello.txt" for entry in payload["files"])


def test_cli_files_without_paths_prints_hint(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "aegis_agent.__main__.get_agent_settings",
        lambda: SimpleNamespace(file_integrity_paths=[]),
    )

    exit_code = main(["files"])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "no paths are configured" in out
