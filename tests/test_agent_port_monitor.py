"""Deterministic tests for the read-only listening-port monitor.

psutil is mocked so tests never depend on the ports actually open on the
developer machine and never require elevated privileges. Skipped automatically
when the agent extra (psutil) is not installed.
"""

from __future__ import annotations

import json
import socket
from datetime import UTC, datetime
from pathlib import Path

import pytest

pytest.importorskip("psutil", reason="agent extra not installed")

import psutil

from aegis_agent.__main__ import main
from aegis_agent.config import get_agent_settings
from aegis_agent.monitors.port import (
    PortChanges,
    PortIdentity,
    PortMonitor,
    PortRecord,
    PortSnapshot,
    changes_to_events,
    collect_port_snapshot,
    format_endpoint,
)
from aegis_agent.monitors.port import collector as port_collector
from aegis_agent.monitors.process import collector as process_collector
from aegis_shared.enums import (
    AddressFamily,
    EventCategory,
    EventType,
    Platform,
    SourceKind,
    TransportProtocol,
)
from aegis_shared.events import HostRef, SourceRef

_T0 = 1_700_000_000.0
_T1 = _T0 + 3600.0


class FakeConnection:
    """Stand-in for a psutil ``sconn`` namedtuple."""

    def __init__(
        self,
        *,
        family: int = socket.AF_INET,
        socket_type: int = socket.SOCK_STREAM,
        laddr: object = (),
        raddr: object = (),
        status: str = "LISTEN",
        pid: int | None = None,
    ) -> None:
        self.fd = -1
        self.family = family
        self.type = socket_type
        self.laddr = laddr
        self.raddr = raddr
        self.status = status
        self.pid = pid


class FakePsutilProcess:
    """Stand-in for ``psutil.Process`` with optional error injection."""

    def __init__(
        self,
        name: str | None = None,
        create_time: float | None = None,
        error: Exception | None = None,
    ) -> None:
        self._name = name
        self._create_time = create_time
        self._error = error

    def name(self) -> str | None:
        if self._error is not None:
            raise self._error
        return self._name

    def create_time(self) -> float | None:
        if self._error is not None:
            raise self._error
        return self._create_time


def _patch_connections(monkeypatch: pytest.MonkeyPatch, connections: list[FakeConnection]) -> None:
    """Make the collector enumerate exactly ``connections`` (live list)."""
    monkeypatch.setattr(
        port_collector.psutil, "net_connections", lambda *args, **kwargs: list(connections)
    )


def _patch_processes(
    monkeypatch: pytest.MonkeyPatch, mapping: dict[int, FakePsutilProcess]
) -> None:
    """Make ``psutil.Process(pid)`` resolve via ``mapping`` (else NoSuchProcess)."""

    def fake_process(pid: int) -> FakePsutilProcess:
        if pid not in mapping:
            raise psutil.NoSuchProcess(pid)
        return mapping[pid]

    monkeypatch.setattr(port_collector.psutil, "Process", fake_process)


def _source() -> SourceRef:
    return SourceRef(kind=SourceKind.AGENT, id="agent-test")


def _host() -> HostRef:
    return HostRef(host_id="host-1", hostname="ws-01", platform=Platform.WINDOWS)


# --- Collection ------------------------------------------------------------


def test_tcp_listening_socket_collected(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_connections(
        monkeypatch, [FakeConnection(laddr=("0.0.0.0", 8000), status="LISTEN", pid=100)]
    )
    _patch_processes(monkeypatch, {100: FakePsutilProcess("python", _T0)})

    snapshot = collect_port_snapshot()

    assert len(snapshot.ports) == 1
    record = snapshot.ports[0]
    assert record.protocol is TransportProtocol.TCP
    assert record.address_family is AddressFamily.IPV4
    assert record.local_address == "0.0.0.0"
    assert record.local_port == 8000
    assert record.status == "LISTEN"
    assert record.pid == 100
    assert record.process_name == "python"


def test_udp_bound_socket_collected_without_status(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_connections(
        monkeypatch,
        [
            FakeConnection(
                socket_type=socket.SOCK_DGRAM,
                laddr=("0.0.0.0", 5353),
                status="NONE",
                pid=101,
            )
        ],
    )
    _patch_processes(monkeypatch, {101: FakePsutilProcess("mdns", _T0)})

    record = collect_port_snapshot().ports[0]

    assert record.protocol is TransportProtocol.UDP
    assert record.status is None
    assert record.local_port == 5353


def test_udp_unbound_socket_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_connections(
        monkeypatch,
        [FakeConnection(socket_type=socket.SOCK_DGRAM, laddr=("0.0.0.0", 0), status="NONE", pid=1)],
    )

    assert collect_port_snapshot().ports == ()


def test_ipv6_listening_socket_endpoint_formatting(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_connections(
        monkeypatch,
        [FakeConnection(family=socket.AF_INET6, laddr=("::1", 8000, 0, 0), pid=1)],
    )
    _patch_processes(monkeypatch, {1: FakePsutilProcess("svc", _T0)})

    record = collect_port_snapshot().ports[0]

    assert record.address_family is AddressFamily.IPV6
    assert record.local_address == "::1"
    assert record.endpoint == "[::1]:8000"


def test_ipv6_brackets_are_stripped(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_connections(
        monkeypatch,
        [FakeConnection(family=socket.AF_INET6, laddr=("[::]", 8080, 0, 0), pid=1)],
    )

    assert collect_port_snapshot().ports[0].local_address == "::"


def test_established_tcp_connection_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_connections(
        monkeypatch,
        [
            FakeConnection(
                laddr=("10.0.0.1", 12345),
                raddr=("10.0.0.2", 443),
                status="ESTABLISHED",
                pid=1,
            )
        ],
    )

    assert collect_port_snapshot().ports == ()


def test_duplicate_identity_is_deduplicated(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_connections(
        monkeypatch,
        [
            FakeConnection(laddr=("0.0.0.0", 8000), pid=1),
            FakeConnection(laddr=("0.0.0.0", 8000), pid=1),
        ],
    )
    _patch_processes(monkeypatch, {1: FakePsutilProcess("svc", _T0)})

    assert len(collect_port_snapshot().ports) == 1


def test_empty_socket_list(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_connections(monkeypatch, [])

    snapshot = collect_port_snapshot()

    assert snapshot.ports == ()
    assert snapshot.by_identity() == {}


# --- Ownership -------------------------------------------------------------


def test_owning_process_identity_is_correlated(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_connections(monkeypatch, [FakeConnection(laddr=("0.0.0.0", 8000), pid=200)])
    _patch_processes(monkeypatch, {200: FakePsutilProcess("svc", _T0)})

    record = collect_port_snapshot().ports[0]
    expected = datetime.fromtimestamp(_T0, tz=UTC)

    assert record.process_create_time == expected
    assert record.identity.owner_key == f"200:{expected.isoformat()}"


def test_missing_owning_pid(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_connections(monkeypatch, [FakeConnection(laddr=("0.0.0.0", 9000), pid=None)])

    record = collect_port_snapshot().ports[0]

    assert record.pid is None
    assert record.process_name is None
    assert record.identity.owner_key == "unowned"


def test_process_access_denied_leaves_owner_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_connections(monkeypatch, [FakeConnection(laddr=("0.0.0.0", 9001), pid=300)])
    _patch_processes(monkeypatch, {300: FakePsutilProcess(error=psutil.AccessDenied(300))})

    record = collect_port_snapshot().ports[0]

    assert record.pid == 300
    assert record.process_name is None
    assert record.process_create_time is None


def test_no_such_process_leaves_owner_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_connections(monkeypatch, [FakeConnection(laddr=("0.0.0.0", 9002), pid=999)])
    _patch_processes(monkeypatch, {})

    record = collect_port_snapshot().ports[0]

    assert record.pid == 999
    assert record.process_name is None


def test_zombie_process_leaves_owner_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_connections(monkeypatch, [FakeConnection(laddr=("0.0.0.0", 9003), pid=400)])
    _patch_processes(monkeypatch, {400: FakePsutilProcess(error=psutil.ZombieProcess(400))})

    record = collect_port_snapshot().ports[0]

    assert record.pid == 400
    assert record.process_name is None


def test_net_connections_access_denied_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_denied(*args: object, **kwargs: object) -> None:
        raise psutil.AccessDenied()

    monkeypatch.setattr(port_collector.psutil, "net_connections", raise_denied)

    assert collect_port_snapshot().ports == ()


def test_net_connections_oserror_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_oserror(*args: object, **kwargs: object) -> None:
        raise OSError("enumeration failed")

    monkeypatch.setattr(port_collector.psutil, "net_connections", raise_oserror)

    assert collect_port_snapshot().ports == ()


# --- Models & serialization ------------------------------------------------


def test_port_record_rejects_invalid_port() -> None:
    with pytest.raises(ValueError):
        PortRecord(
            protocol=TransportProtocol.TCP,
            address_family=AddressFamily.IPV4,
            local_port=70000,
        )


def test_port_record_rejects_naive_process_create_time() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        PortRecord(
            protocol=TransportProtocol.TCP,
            address_family=AddressFamily.IPV4,
            local_port=80,
            process_create_time=datetime(2026, 1, 1),
        )


def test_snapshot_json_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_connections(monkeypatch, [FakeConnection(laddr=("0.0.0.0", 8000), pid=1)])
    _patch_processes(monkeypatch, {1: FakePsutilProcess("svc", _T0)})
    snapshot = collect_port_snapshot()

    payload = snapshot.to_json_dict()
    restored = PortSnapshot.model_validate(json.loads(json.dumps(payload)))

    assert restored == snapshot
    assert payload["ports"][0]["process_create_time"].endswith("Z")


def test_port_identity_is_stable_and_ownership_sensitive() -> None:
    created = datetime.fromtimestamp(_T0, tz=UTC)

    def identity(pid: int) -> PortIdentity:
        return PortIdentity(
            protocol=TransportProtocol.TCP,
            address_family=AddressFamily.IPV4,
            local_address="0.0.0.0",
            local_port=8000,
            pid=pid,
            process_create_time=created,
        )

    assert identity(1).key == identity(1).key
    assert identity(1).key != identity(2).key


@pytest.mark.parametrize(
    ("address", "port", "family", "expected"),
    [
        pytest.param("0.0.0.0", 8000, AddressFamily.IPV4, "0.0.0.0:8000", id="ipv4-wildcard"),
        pytest.param("127.0.0.1", 8000, AddressFamily.IPV4, "127.0.0.1:8000", id="ipv4-loopback"),
        pytest.param("192.168.1.10", 443, AddressFamily.IPV4, "192.168.1.10:443", id="ipv4-lan"),
        pytest.param("0.0.0.0", 0, AddressFamily.IPV4, "0.0.0.0:0", id="ipv4-port-zero"),
        pytest.param("::1", 8000, AddressFamily.IPV6, "[::1]:8000", id="ipv6-loopback"),
        pytest.param("::", 8080, AddressFamily.IPV6, "[::]:8080", id="ipv6-wildcard"),
        pytest.param("fe80::1", 123, AddressFamily.IPV6, "[fe80::1]:123", id="ipv6-link-local"),
        pytest.param(
            "fe80::7a6c:b308:6054:6d83",
            123,
            AddressFamily.IPV6,
            "[fe80::7a6c:b308:6054:6d83]:123",
            id="ipv6-long-link-local",
        ),
        pytest.param("::", 0, AddressFamily.IPV6, "[::]:0", id="ipv6-port-zero"),
        pytest.param(None, 8000, AddressFamily.IPV4, "*:8000", id="ipv4-unknown-host"),
        pytest.param(None, None, AddressFamily.IPV4, "?", id="no-port"),
    ],
)
def test_format_endpoint(
    address: str | None, port: int | None, family: AddressFamily, expected: str
) -> None:
    assert format_endpoint(address, port, family) == expected


def test_link_local_record_preserves_structured_fields() -> None:
    record = PortRecord(
        protocol=TransportProtocol.UDP,
        address_family=AddressFamily.IPV6,
        local_address="fe80::7a6c:b308:6054:6d83",
        local_port=123,
    )

    assert record.local_address == "fe80::7a6c:b308:6054:6d83"
    assert record.local_port == 123
    assert record.endpoint == "[fe80::7a6c:b308:6054:6d83]:123"


# --- Snapshot diffing ------------------------------------------------------


def test_port_start_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    connections = [FakeConnection(laddr=("0.0.0.0", 8000), pid=1)]
    _patch_connections(monkeypatch, connections)
    _patch_processes(monkeypatch, {1: FakePsutilProcess("svc", _T0)})
    monitor = PortMonitor()
    monitor.start()

    connections.append(FakeConnection(laddr=("0.0.0.0", 8080), pid=1))
    changes = monitor.poll()

    assert [record.local_port for record in changes.started] == [8080]
    assert changes.stopped == ()
    assert changes.is_empty is False


def test_port_stop_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    connections = [
        FakeConnection(laddr=("0.0.0.0", 8000), pid=1),
        FakeConnection(laddr=("0.0.0.0", 8080), pid=1),
    ]
    _patch_connections(monkeypatch, connections)
    _patch_processes(monkeypatch, {1: FakePsutilProcess("svc", _T0)})
    monitor = PortMonitor()
    monitor.start()

    connections.pop(0)
    changes = monitor.poll()

    assert changes.started == ()
    assert [record.local_port for record in changes.stopped] == [8000]


def test_ownership_change_reports_stop_and_start(monkeypatch: pytest.MonkeyPatch) -> None:
    connections = [FakeConnection(laddr=("0.0.0.0", 8000), pid=1)]
    _patch_connections(monkeypatch, connections)
    _patch_processes(
        monkeypatch,
        {1: FakePsutilProcess("old", _T0), 2: FakePsutilProcess("new", _T1)},
    )
    monitor = PortMonitor()
    monitor.start()

    connections[0] = FakeConnection(laddr=("0.0.0.0", 8000), pid=2)
    changes = monitor.poll()

    assert [record.process_name for record in changes.stopped] == ["old"]
    assert [record.process_name for record in changes.started] == ["new"]


def test_owner_pid_reuse_is_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    connections = [FakeConnection(laddr=("0.0.0.0", 8000), pid=1)]
    _patch_connections(monkeypatch, connections)
    _patch_processes(monkeypatch, {1: FakePsutilProcess("first", _T0)})
    monitor = PortMonitor()
    monitor.start()

    _patch_processes(monkeypatch, {1: FakePsutilProcess("second", _T1)})
    changes = monitor.poll()

    assert len(changes.stopped) == 1
    assert len(changes.started) == 1


def test_monitor_stop_clears_baseline(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_connections(monkeypatch, [FakeConnection(laddr=("0.0.0.0", 8000), pid=1)])
    monitor = PortMonitor()
    monitor.start()
    assert monitor.has_baseline is True

    monitor.stop()
    assert monitor.has_baseline is False

    changes = monitor.poll()
    assert [record.local_port for record in changes.started] == [8000]


# --- Event mapping ---------------------------------------------------------


def test_changes_to_events_maps_to_canonical_event() -> None:
    opened = PortRecord(
        protocol=TransportProtocol.TCP,
        address_family=AddressFamily.IPV4,
        local_address="0.0.0.0",
        local_port=8000,
        status="LISTEN",
        pid=5,
        process_name="svc",
    )
    closed = PortRecord(
        protocol=TransportProtocol.TCP,
        address_family=AddressFamily.IPV4,
        local_address="0.0.0.0",
        local_port=8080,
        status="LISTEN",
    )
    changes = PortChanges(started=(opened,), stopped=(closed,))

    events = changes_to_events(changes, source=_source(), host=_host())

    assert [event.event_type for event in events] == [
        EventType.PORT_LISTENING,
        EventType.PORT_CLOSED,
    ]
    first = events[0]
    assert first.category is EventCategory.HOST
    assert first.host is not None and first.host.host_id == "host-1"
    assert first.socket is not None
    assert first.socket.local_port == 8000
    assert first.socket.address_family is AddressFamily.IPV4
    assert first.process is not None and first.process.pid == 5
    assert first.timestamp.tzinfo is not None


# --- CLI -------------------------------------------------------------------


def test_cli_ports_text(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch_connections(monkeypatch, [FakeConnection(laddr=("0.0.0.0", 8000), pid=1)])
    _patch_processes(monkeypatch, {1: FakePsutilProcess("python", _T0)})

    exit_code = main(["ports"])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "Aegis listening-port snapshot (1 endpoints)" in out
    assert "0.0.0.0:8000" in out
    assert "python" in out


def test_cli_ports_text_preserves_ipv6_port(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Regression: the LOCAL column used to truncate long IPv6 endpoints, chopping
    # off the port digits (e.g. "[fe80::...]:" instead of "[fe80::...]:123").
    _patch_connections(
        monkeypatch,
        [
            FakeConnection(
                family=socket.AF_INET6,
                socket_type=socket.SOCK_DGRAM,
                laddr=("fe80::7a6c:b308:6054:6d83", 123, 0, 6),
                status="NONE",
                pid=8788,
            )
        ],
    )
    _patch_processes(monkeypatch, {8788: FakePsutilProcess("svchost.exe", _T0)})

    exit_code = main(["ports"])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "[fe80::7a6c:b308:6054:6d83]:123" in out
    assert "svchost.exe" in out


def test_cli_ports_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch_connections(monkeypatch, [FakeConnection(laddr=("0.0.0.0", 8000), pid=1)])
    _patch_processes(monkeypatch, {1: FakePsutilProcess("python", _T0)})

    exit_code = main(["ports", "--json"])
    out = capsys.readouterr().out

    assert exit_code == 0
    payload = json.loads(out)
    assert payload["ports"][0]["local_port"] == 8000


def test_cli_inventory_still_works(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    monkeypatch.setenv("AEGIS_AGENT_STATE_DIR", str(tmp_path / "state"))
    get_agent_settings.cache_clear()
    try:
        exit_code = main(["inventory"])
        out = capsys.readouterr().out
        assert exit_code == 0
        assert "Aegis endpoint system inventory" in out
    finally:
        get_agent_settings.cache_clear()


def test_cli_processes_still_works(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(process_collector.psutil, "process_iter", lambda *args, **kwargs: iter([]))

    exit_code = main(["processes"])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "Aegis process snapshot (0 processes)" in out
