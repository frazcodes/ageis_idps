"""Read-only listening-port collection via psutil.

What counts as "listening"
--------------------------
* **TCP**: only sockets in the ``LISTEN`` state. Established connections are not
  local listening endpoints and are ignored.
* **UDP**: UDP has no TCP-style ``LISTEN`` state, so a bound socket with a
  non-zero local port is treated as an endpoint. This can include unconnected
  client sockets; that limitation is inherent to the platform APIs.

Permission handling
-------------------
Enumerating sockets or resolving owning PIDs may require elevated privileges.
``psutil.AccessDenied`` / ``OSError`` degrade gracefully (empty snapshot, or a
``None`` owner for the affected socket) rather than crashing the monitor.
Unexpected exceptions are not caught here - programming errors must surface.

Nothing in this module binds, closes or otherwise modifies a socket, and no
firewall or shell command is ever invoked.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import psutil

from aegis_agent.monitors.port.addressing import (
    address_family_for,
    normalize_address,
    protocol_for_socket_type,
    split_local_address,
)
from aegis_agent.monitors.port.models import PortRecord, PortSnapshot
from aegis_shared.enums import TransportProtocol
from aegis_shared.logging import get_logger

logger = get_logger(__name__)

#: Errors that mean "socket enumeration is unavailable" -> empty snapshot.
_ENUMERATION_EXCEPTIONS: tuple[type[BaseException], ...] = (psutil.AccessDenied, OSError)

#: Errors tolerated while resolving an owning process -> owner left unknown.
_PROCESS_EXCEPTIONS: tuple[type[BaseException], ...] = (
    psutil.NoSuchProcess,
    psutil.ZombieProcess,
    psutil.AccessDenied,
    OSError,
)


class ProcessLookup:
    """Per-collection cache mapping PID to ``(name, create_time)``.

    One snapshot commonly references the same PID many times. Looking the process
    up once per PID avoids repeatedly constructing ``psutil.Process`` while
    keeping the cache trivial and scoped to a single collection.
    """

    def __init__(self) -> None:
        self._cache: dict[int, tuple[str | None, datetime | None]] = {}

    def lookup(self, pid: int) -> tuple[str | None, datetime | None]:
        """Return cached ``(name, create_time)`` for ``pid``."""
        if pid not in self._cache:
            self._cache[pid] = self._query(pid)
        return self._cache[pid]

    def _query(self, pid: int) -> tuple[str | None, datetime | None]:
        try:
            proc = psutil.Process(pid)
            raw_name = proc.name()
            raw_create_time = proc.create_time()
        except _PROCESS_EXCEPTIONS:
            return None, None

        name = raw_name.strip() if isinstance(raw_name, str) and raw_name.strip() else None
        return name, _to_datetime(raw_create_time)


def _to_datetime(raw: Any) -> datetime | None:
    try:
        return datetime.fromtimestamp(float(raw), tz=UTC)
    except (TypeError, ValueError, OSError, OverflowError):
        return None


class PortCollector:
    """Enumerate local listening endpoints and build :class:`PortRecord` objects."""

    def __init__(self, *, process_lookup: ProcessLookup | None = None) -> None:
        self._process_lookup = process_lookup

    def collect(self) -> PortSnapshot:
        """Return a snapshot of local listening endpoints, ordered deterministically."""
        try:
            connections = psutil.net_connections(kind="inet")
        except _ENUMERATION_EXCEPTIONS as exc:
            logger.warning("Socket enumeration unavailable (%s); returning empty snapshot", exc)
            return PortSnapshot(ports=())

        lookup = self._process_lookup or ProcessLookup()
        records: dict[str, PortRecord] = {}
        for connection in connections:
            if not self._is_listening(connection):
                continue
            record = self._build_record(connection, lookup)
            if record is not None:
                records.setdefault(record.identity.key, record)

        return PortSnapshot(ports=tuple(sorted(records.values(), key=_sort_key)))

    @staticmethod
    def _is_listening(connection: Any) -> bool:
        """Whether a psutil connection is a local listening endpoint."""
        protocol = protocol_for_socket_type(getattr(connection, "type", None))
        if protocol is TransportProtocol.TCP:
            status = getattr(connection, "status", None)
            return isinstance(status, str) and status.upper() == "LISTEN"
        if protocol is TransportProtocol.UDP:
            _, port = split_local_address(getattr(connection, "laddr", None))
            return port is not None and port > 0
        return False

    def _build_record(self, connection: Any, lookup: ProcessLookup) -> PortRecord | None:
        raw_address, port = split_local_address(getattr(connection, "laddr", None))
        if port is None:
            return None

        protocol = protocol_for_socket_type(getattr(connection, "type", None))
        family = address_family_for(getattr(connection, "family", None))

        pid = _extract_pid(connection)
        process_name: str | None = None
        process_create_time: datetime | None = None
        if pid is not None:
            process_name, process_create_time = lookup.lookup(pid)

        return PortRecord(
            protocol=protocol,
            address_family=family,
            local_address=normalize_address(raw_address, family),
            local_port=port,
            status=_extract_status(protocol, getattr(connection, "status", None)),
            pid=pid,
            process_name=process_name,
            process_create_time=process_create_time,
        )


def _extract_pid(connection: Any) -> int | None:
    """Return a usable owning PID, or ``None`` when absent/invalid."""
    pid = getattr(connection, "pid", None)
    # bool is a subclass of int; a boolean is never a valid PID.
    if isinstance(pid, bool):
        return None
    if isinstance(pid, int) and pid >= 0:
        return pid
    return None


def _extract_status(protocol: TransportProtocol, raw_status: Any) -> str | None:
    """Return the OS socket state for TCP; UDP has no meaningful state."""
    if protocol is not TransportProtocol.TCP:
        return None
    if isinstance(raw_status, str) and raw_status.strip():
        return raw_status.strip()
    return None


def _sort_key(record: PortRecord) -> tuple[int, str, str, str, int]:
    return (
        record.local_port,
        record.protocol.value,
        record.address_family.value,
        record.local_address or "",
        record.pid if record.pid is not None else -1,
    )


def collect_port_snapshot() -> PortSnapshot:
    """Convenience wrapper for a single read-only listening-port snapshot."""
    return PortCollector().collect()


__all__ = ["PortCollector", "ProcessLookup", "collect_port_snapshot"]
