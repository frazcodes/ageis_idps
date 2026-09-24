"""Deterministic tests for host behavioral feature extraction (Step 19).

Exercises :func:`extract_host_features` using locally constructed host monitor
snapshot/change models. No process table, sockets, filesystem, capture or ML
model is touched; all inputs are built in memory.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from aegis_agent.monitors.file_integrity.models import (
    FileChanges,
    FileModification,
    FileRecord,
)
from aegis_agent.monitors.port.models import PortChanges, PortRecord, PortSnapshot
from aegis_agent.monitors.process.models import (
    ProcessChanges,
    ProcessRecord,
    ProcessSnapshot,
)
from aegis_ml_engine.features import HostBehaviorFeatures, extract_host_features
from aegis_ml_engine.features.host_features import _FEATURE_VERSION
from aegis_shared.enums import AddressFamily, FileType, HashStatus, TransportProtocol

_TS = datetime(2026, 6, 1, tzinfo=UTC)


def _process(pid: int = 1) -> ProcessRecord:
    return ProcessRecord(pid=pid, create_time=_TS)


def _port(port: int = 8080) -> PortRecord:
    return PortRecord(
        protocol=TransportProtocol.TCP,
        address_family=AddressFamily.IPV4,
        local_address="127.0.0.1",
        local_port=port,
        status="LISTEN",
    )


def _file(path: str = "C:\\tmp\\a.txt") -> FileRecord:
    return FileRecord(
        path=path, file_type=FileType.REGULAR, hash_status=HashStatus.NOT_APPLICABLE
    )


def _mod(path: str = "C:\\tmp\\a.txt") -> FileModification:
    return FileModification(previous=_file(path), current=_file(path))


# --- 1. Normal host feature extraction -------------------------------------


def test_normal_host_feature_extraction() -> None:
    features = extract_host_features(
        host_id="host-1",
        process_snapshot=ProcessSnapshot(processes=(_process(1), _process(2), _process(3))),
        port_snapshot=PortSnapshot(ports=(_port(80), _port(443))),
        process_changes=ProcessChanges(started=(_process(4),), stopped=(_process(5),)),
        port_changes=PortChanges(started=(_port(8080),), stopped=(_port(9090),)),
        file_changes=FileChanges(
            created=(_file("C:\\tmp\\new.txt"),),
            modified=(_mod("C:\\tmp\\mod.txt"),),
            deleted=(_file("C:\\tmp\\old.txt"),),
        ),
    )

    assert isinstance(features, HostBehaviorFeatures)
    assert features.host_id == "host-1"
    assert features.feature_version == _FEATURE_VERSION


# --- 2. Process / port / file counts are correct ---------------------------


def test_process_port_file_counts_are_correct() -> None:
    features = extract_host_features(
        host_id="host-1",
        process_snapshot=ProcessSnapshot(processes=(_process(1), _process(2), _process(3))),
        port_snapshot=PortSnapshot(ports=(_port(80), _port(443))),
        process_changes=ProcessChanges(started=(_process(4), _process(5)), stopped=(_process(6),)),
        port_changes=PortChanges(
            started=(_port(8080), _port(8443)), stopped=(_port(9090),)
        ),
        file_changes=FileChanges(
            created=(_file("C:\\tmp\\a"), _file("C:\\tmp\\b")),
            modified=(_mod("C:\\tmp\\c"),),
            deleted=(_file("C:\\tmp\\d"), _file("C:\\tmp\\e")),
        ),
    )

    assert features.process_count == 3
    assert features.listening_port_count == 2
    assert features.new_process_count == 2
    assert features.terminated_process_count == 1
    assert features.new_listening_port_count == 2
    assert features.removed_listening_port_count == 1
    assert features.file_created_count == 2
    assert features.file_modified_count == 1
    assert features.file_deleted_count == 2
    assert features.file_change_count == 5


# --- 3. Empty telemetry is handled safely ----------------------------------


def test_empty_telemetry_is_handled() -> None:
    features = extract_host_features()

    assert features.host_id is None
    assert features.process_count == 0
    assert features.listening_port_count == 0
    assert features.file_change_count == 0
    assert features.new_process_count == 0
    assert features.terminated_process_count == 0
    assert features.new_listening_port_count == 0
    assert features.removed_listening_port_count == 0
    assert features.file_created_count == 0
    assert features.file_modified_count == 0
    assert features.file_deleted_count == 0


def test_empty_collections_are_handled() -> None:
    features = extract_host_features(
        process_snapshot=ProcessSnapshot(),
        port_snapshot=PortSnapshot(),
        process_changes=ProcessChanges(),
        port_changes=PortChanges(),
        file_changes=FileChanges(),
    )

    assert features.process_count == 0
    assert features.listening_port_count == 0
    assert features.file_change_count == 0


# --- 4. Deterministic repeated extraction ----------------------------------


def test_deterministic_repeated_extraction() -> None:
    kwargs = {
        "host_id": "host-1",
        "process_snapshot": ProcessSnapshot(processes=(_process(1),)),
        "file_changes": FileChanges(created=(_file(),)),
    }

    assert extract_host_features(**kwargs) == extract_host_features(**kwargs)


# --- 5. No negative / invalid numeric output -------------------------------


def test_all_numeric_features_are_non_negative_ints() -> None:
    features = extract_host_features(
        process_snapshot=ProcessSnapshot(processes=(_process(1),)),
        file_changes=FileChanges(deleted=(_file(),)),
    )

    for name in (
        "process_count",
        "listening_port_count",
        "file_change_count",
        "new_process_count",
        "terminated_process_count",
        "new_listening_port_count",
        "removed_listening_port_count",
        "file_created_count",
        "file_modified_count",
        "file_deleted_count",
    ):
        value = getattr(features, name)
        assert isinstance(value, int)
        assert value >= 0


# --- 6. Input objects are not mutated --------------------------------------


def test_input_objects_are_not_mutated() -> None:
    process_snapshot = ProcessSnapshot(processes=(_process(1), _process(2)))
    file_changes = FileChanges(created=(_file(),))

    before_processes = process_snapshot.processes
    before_created = file_changes.created

    extract_host_features(process_snapshot=process_snapshot, file_changes=file_changes)

    assert process_snapshot.processes == before_processes
    assert file_changes.created == before_created
    assert len(process_snapshot.processes) == 2
    assert len(file_changes.created) == 1


def test_features_are_frozen() -> None:
    features = extract_host_features(host_id="host-1")

    with pytest.raises(AttributeError):
        features.process_count = 99  # type: ignore[misc]
