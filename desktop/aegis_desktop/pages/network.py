"""Network page: read-only network monitoring, endpoints, flows and events.

The page is presentation only. It shows two kinds of real data:

* **Listening endpoints** - one-shot collection through the existing Step 4 port
  collector (the original local HIDS/NIDS view: what ports are open and which
  process owns them).
* **Live network monitoring** - the capture status, traffic counters, aggregated
  flows and recent network events produced by the single running
  :class:`~aegis_runtime.AegisRuntime` through
  :mod:`aegis_desktop.services.network`.

It never captures packets itself, never starts a runtime loop, never changes
network configuration and fabricates no telemetry. When monitoring is stopped the
page honestly shows "No network activity observed".
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QPersistentModelIndex,
    QSortFilterProxyModel,
    Qt,
)
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableView,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from aegis_desktop.pages.base import BasePage
from aegis_desktop.services.arp_radar import ArpDeviceRow, ArpRadarService
from aegis_desktop.services.dashboard import format_bytes, format_timestamp
from aegis_desktop.services.live_network import analyze_packet_threat
from aegis_desktop.services.monitoring import (
    CAPTURE_ACTIVE,
    CAPTURE_ERROR,
    MonitoringStatus,
)
from aegis_desktop.services.network import (
    MISSING,
    PORT_ERROR,
    FlowRow,
    NetworkEventRow,
    NetworkMonitoringView,
    PortRow,
    PortSnapshotView,
    collect_network_monitoring_view,
    collect_port_view,
)
from aegis_desktop.theme import set_state
from aegis_shared.logging import get_logger

logger = get_logger(__name__)

_PORT_COLUMNS = (
    "Protocol",
    "Family",
    "Local Address",
    "Local Port",
    "PID",
    "Process Name",
    "Status",
    "Endpoint",
    "Identity",
)
_PORT_WIDTHS = (90, 80, 200, 100, 80, 200, 90, 260, 340)

_FLOW_COLUMNS = (
    "Flow ID",
    "Protocol",
    "Source",
    "Destination",
    "Packets",
    "Bytes",
    "Duration (ms)",
    "Direction",
)
_FLOW_WIDTHS = (340, 90, 240, 240, 90, 110, 110, 100)

_EVENT_COLUMNS = (
    "Time",
    "Event Type",
    "Protocol",
    "Source",
    "Destination",
    "Packets",
    "Bytes",
)
_EVENT_WIDTHS = (170, 200, 90, 240, 240, 90, 110)

_INITIAL_HINT = (
    "Select Refresh to discover local listening endpoints, or use Start Monitoring "
    "to observe live network telemetry. No packet capture runs until you start it."
)

_NO_DATA_TEXT = "Endpoints: No data"
_UNAVAILABLE = "Unavailable"

_NO_INDEX = QModelIndex()


_AUDIT_COLUMNS = (
    "Port",
    "Protocol",
    "Service Banner",
    "State",
    "Exposure Scope",
    "Process (PID)",
    "Security Assessment",
)
_AUDIT_WIDTHS = (85, 85, 175, 100, 175, 190, 360)

_WELL_KNOWN_SERVICES: tuple[tuple[int, str, str, str], ...] = (
    (21, "tcp", "ftp (File Transfer)", "Cleartext file transfer protocol"),
    (22, "tcp", "ssh (Secure Shell)", "Remote administration shell"),
    (23, "tcp", "telnet", "Critical: Unencrypted remote shell"),
    (25, "tcp", "smtp (Mail Transfer)", "Mail relay / transport service"),
    (53, "udp", "domain (DNS)", "Domain Name System resolver/server"),
    (80, "tcp", "http (Web Server)", "Unencrypted HTTP web traffic"),
    (135, "tcp", "msrpc (Windows RPC)", "Windows DCE/RPC endpoint mapper"),
    (139, "tcp", "netbios-ssn", "Legacy NetBIOS session service"),
    (443, "tcp", "https (TLS Web)", "Encrypted TLS/SSL web service"),
    (445, "tcp", "microsoft-ds (SMB)", "High-value lateral movement target (SMB)"),
    (1433, "tcp", "ms-sql-s (MSSQL)", "Microsoft SQL Server database listener"),
    (3306, "tcp", "mysql (MySQL DB)", "MySQL database listener"),
    (3389, "tcp", "ms-wbt-server (RDP)", "Windows Remote Desktop Protocol"),
    (5432, "tcp", "postgresql (Postgres)", "PostgreSQL database listener"),
    (5985, "tcp", "wsman (WinRM HTTP)", "Windows Remote Management service"),
    (6379, "tcp", "redis (Key-Value)", "Redis in-memory datastore"),
    (8000, "tcp", "http-alt (Dev/API)", "Alternative HTTP / application server"),
    (8080, "tcp", "http-proxy (Web/API)", "HTTP proxy or admin console port"),
)

_HIGH_RISK_PORTS = frozenset({21, 23, 135, 139, 445, 3389, 5985, 6379})
_WILDCARD_ADDRS = frozenset({"0.0.0.0", "::", "*"})  # noqa: S104


class PortAuditRow:
    """Single row in the Nmap-style Port Security Audit table."""

    __slots__ = (
        "assessment",
        "exposure",
        "port",
        "process_info",
        "protocol",
        "service",
        "state",
    )

    def __init__(
        self,
        *,
        port: int,
        protocol: str,
        service: str,
        state: str,
        exposure: str,
        process_info: str,
        assessment: str,
    ) -> None:
        self.port = port
        self.protocol = protocol
        self.service = service
        self.state = state
        self.exposure = exposure
        self.process_info = process_info
        self.assessment = assessment


def build_port_audit_rows(rows: tuple[PortRow, ...]) -> tuple[PortAuditRow, ...]:
    """Synthesize an Nmap-style OPEN/CLOSED port security audit from live PortRows."""
    by_port: dict[int, PortRow] = {}
    for r in rows:
        if r.local_port not in by_port or r.local_address in _WILDCARD_ADDRS:
            by_port[r.local_port] = r

    audit: list[PortAuditRow] = []
    seen_ports: set[int] = set()

    for port, default_proto, service_name, desc in _WELL_KNOWN_SERVICES:
        seen_ports.add(port)
        matched = by_port.get(port)
        if matched is not None:
            addr = matched.local_address or ""
            if addr in _WILDCARD_ADDRS:
                exposure = f"PUBLIC / ALL IFACES ({addr})"
                risk_prefix = (
                    "HIGH RISK: Exposed on all interfaces"
                    if port in _HIGH_RISK_PORTS
                    else "OPEN: Listening on all network interfaces"
                )
            elif addr in ("127.0.0.1", "::1", "localhost"):
                exposure = f"LOOPBACK ONLY ({addr})"
                risk_prefix = "SAFE: Bound to local loopback only"
            else:
                exposure = f"INTERFACE BOUND ({addr})"
                risk_prefix = (
                    "ELEVATED: Network-reachable sensitive port"
                    if port in _HIGH_RISK_PORTS
                    else "OPEN: Bound to specific host interface"
                )
            proc_name = matched.process_name or "System/Kernel"
            pid_str = f"PID {matched.pid}" if matched.pid is not None else "unowned"
            audit.append(
                PortAuditRow(
                    port=port,
                    protocol=matched.protocol.upper(),
                    service=service_name,
                    state="OPEN",
                    exposure=exposure,
                    process_info=f"{proc_name} ({pid_str})",
                    assessment=f"{risk_prefix} — {desc}",
                )
            )
        else:
            audit.append(
                PortAuditRow(
                    port=port,
                    protocol=default_proto.upper(),
                    service=service_name,
                    state="CLOSED",
                    exposure="—",
                    process_info="—",
                    assessment=f"Verified closed — {desc}",
                )
            )

    # Also include any non-standard open ports discovered on the host
    for port in sorted(by_port):
        if port in seen_ports:
            continue
        matched = by_port[port]
        addr = matched.local_address or ""
        if addr in _WILDCARD_ADDRS:
            exposure = f"PUBLIC / ALL IFACES ({addr})"
            assessment = "OPEN: Custom/ephemeral port listening on all interfaces"
        elif addr in ("127.0.0.1", "::1", "localhost"):
            exposure = f"LOOPBACK ONLY ({addr})"
            assessment = "SAFE: Custom port restricted to localhost"
        else:
            exposure = f"INTERFACE BOUND ({addr})"
            assessment = "OPEN: Custom port bound to specific interface"
        proc_name = matched.process_name or "System/Kernel"
        pid_str = f"PID {matched.pid}" if matched.pid is not None else "unowned"
        audit.append(
            PortAuditRow(
                port=port,
                protocol=matched.protocol.upper(),
                service=f"custom-{port}",
                state="OPEN",
                exposure=exposure,
                process_info=f"{proc_name} ({pid_str})",
                assessment=assessment,
            )
        )

    # Sort OPEN ports first, then by port number
    audit.sort(key=lambda item: (0 if item.state == "OPEN" else 1, item.port))
    return tuple(audit)


class PortAuditTableModel(QAbstractTableModel):
    """Qt table model for the Nmap-style OPEN vs CLOSED Port Security Audit."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._rows: list[PortAuditRow] = []

    def set_rows(self, rows: tuple[PortAuditRow, ...]) -> None:
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def rowCount(  # noqa: N802
        self, parent: QModelIndex | QPersistentModelIndex = _NO_INDEX
    ) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(  # noqa: N802
        self, parent: QModelIndex | QPersistentModelIndex = _NO_INDEX
    ) -> int:
        return len(_AUDIT_COLUMNS)

    def headerData(  # noqa: N802
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object:
        if role != Qt.ItemDataRole.DisplayRole or orientation != Qt.Orientation.Horizontal:
            return None
        return _AUDIT_COLUMNS[section]

    def data(
        self,
        index: QModelIndex | QPersistentModelIndex,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object:
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        col = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0:
                return str(row.port)
            if col == 1:
                return row.protocol
            if col == 2:
                return row.service
            if col == 3:
                return row.state
            if col == 4:
                return row.exposure
            if col == 5:
                return row.process_info
            if col == 6:
                return row.assessment
        if role == Qt.ItemDataRole.ForegroundRole:
            from PySide6.QtGui import QColor

            if row.state == "CLOSED":
                return QColor("#64748B")
            if col == 0:
                return QColor("#38BDF8")
            if col == 3:
                return (
                    QColor("#F59E0B")
                    if "HIGH RISK" in row.assessment
                    else QColor("#10B981")
                )
            if col == 4 and "PUBLIC" in row.exposure:
                return QColor("#F97316")
            if col == 6 and "HIGH RISK" in row.assessment:
                return QColor("#F87171")
            return QColor("#E2E8F0")
        if role == Qt.ItemDataRole.TextAlignmentRole:
            if col in (0, 1, 3):
                return int(Qt.AlignmentFlag.AlignCenter)
            return int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        if role == Qt.ItemDataRole.UserRole:
            if col == 0:
                return row.port
            return str(self.data(index, Qt.ItemDataRole.DisplayRole) or "").lower()
        return None


class PortTableModel(QAbstractTableModel):
    """Qt table model over a tuple of :class:`PortRow`."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._rows: list[PortRow] = []

    def set_rows(self, rows: tuple[PortRow, ...]) -> None:
        """Replace the displayed rows."""
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def rows(self) -> tuple[PortRow, ...]:
        """Return the current rows."""
        return tuple(self._rows)

    def row_at(self, row: int) -> PortRow:
        """Return the row at ``row``."""
        return self._rows[row]

    def rowCount(  # noqa: N802
        self, parent: QModelIndex | QPersistentModelIndex = _NO_INDEX
    ) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(  # noqa: N802
        self, parent: QModelIndex | QPersistentModelIndex = _NO_INDEX
    ) -> int:
        return len(_PORT_COLUMNS)

    def headerData(  # noqa: N802
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object:
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation != Qt.Orientation.Horizontal:
            return None
        return _PORT_COLUMNS[section]

    def data(
        self,
        index: QModelIndex | QPersistentModelIndex,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object:
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        column = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            return self._display(row, column)
        if role == Qt.ItemDataRole.ToolTipRole:
            return self._tooltip(row, column)
        if role == Qt.ItemDataRole.UserRole:
            return self._sort_key(row, column)
        if role == Qt.ItemDataRole.ForegroundRole:
            from PySide6.QtGui import QColor

            if column == 3:
                return QColor("#06B6D4")
            if column == 6:
                return QColor("#10B981") if row.status == "LISTEN" else QColor("#94A3B8")
        if role == Qt.ItemDataRole.TextAlignmentRole:
            if column in (0, 1, 3, 4, 6):
                return int(Qt.AlignmentFlag.AlignCenter)
            return int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        return None

    @staticmethod
    def _display(row: PortRow, column: int) -> str:
        if column == 0:
            return row.protocol
        if column == 1:
            return row.address_family
        if column == 2:
            return row.local_address or MISSING
        if column == 3:
            return str(row.local_port)
        if column == 4:
            return MISSING if row.pid is None else str(row.pid)
        if column == 5:
            return row.process_name or MISSING
        if column == 6:
            return row.status or MISSING
        if column == 7:
            return row.endpoint
        if column == 8:
            return row.identity or MISSING
        return MISSING

    @staticmethod
    def _tooltip(row: PortRow, column: int) -> str | None:
        if column == 7:
            return row.endpoint
        return None

    @staticmethod
    def _sort_key(row: PortRow, column: int) -> object:
        if column == 3:
            return row.local_port
        if column == 4:
            return row.pid if row.pid is not None else -1
        return PortTableModel._display(row, column).lower()


class FlowTableModel(QAbstractTableModel):
    """Qt table model over a tuple of :class:`FlowRow`."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._rows: list[FlowRow] = []

    def set_rows(self, rows: tuple[FlowRow, ...]) -> None:
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def row_at(self, row: int) -> FlowRow:
        return self._rows[row]

    def rowCount(  # noqa: N802
        self, parent: QModelIndex | QPersistentModelIndex = _NO_INDEX
    ) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(  # noqa: N802
        self, parent: QModelIndex | QPersistentModelIndex = _NO_INDEX
    ) -> int:
        return len(_FLOW_COLUMNS)

    def headerData(  # noqa: N802
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object:
        if role != Qt.ItemDataRole.DisplayRole or orientation != Qt.Orientation.Horizontal:
            return None
        return _FLOW_COLUMNS[section]

    def data(
        self,
        index: QModelIndex | QPersistentModelIndex,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object:
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        column = index.column()

        is_suspicious, threat_tag, threat_detail = analyze_packet_threat(
            source=row.source,
            destination=row.destination,
            protocol=row.protocol,
            packets=row.packets,
            bytes_transferred=row.bytes,
        )

        if role == Qt.ItemDataRole.BackgroundRole:
            if is_suspicious:
                return QColor(248, 81, 73, 40)
            return None

        if role == Qt.ItemDataRole.ToolTipRole:
            if is_suspicious:
                return (
                    f"[\U0001f6a8 SUSPICIOUS NETWORK FLOW - {threat_tag}]\n"
                    f"{threat_detail}\n"
                    f"Flow ID: {row.flow_id}"
                )
            if column == 0:
                return row.flow_id
            return None

        if role == Qt.ItemDataRole.ForegroundRole:
            if is_suspicious:
                if column in (2, 3):
                    return QColor("#FFA198")
                if column == 1:
                    return QColor("#FF7B72")
                return QColor("#FF7B72")
            return None

        if role == Qt.ItemDataRole.DisplayRole:
            return self._display(row, column)
        if role == Qt.ItemDataRole.UserRole:
            return self._sort_key(row, column)
        return None

    @staticmethod
    def _display(row: FlowRow, column: int) -> str:
        if column == 0:
            return row.flow_id
        if column == 1:
            return row.protocol
        if column == 2:
            return row.source
        if column == 3:
            return row.destination
        if column == 4:
            return str(row.packets)
        if column == 5:
            return str(row.bytes)
        if column == 6:
            return str(row.duration_ms)
        if column == 7:
            return row.direction
        return MISSING

    @staticmethod
    def _sort_key(row: FlowRow, column: int) -> object:
        if column == 4:
            return row.packets
        if column == 5:
            return row.bytes
        if column == 6:
            return row.duration_ms
        return FlowTableModel._display(row, column).lower()


class NetworkEventTableModel(QAbstractTableModel):
    """Qt table model over a tuple of :class:`NetworkEventRow`."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._rows: list[NetworkEventRow] = []

    def set_rows(self, rows: tuple[NetworkEventRow, ...]) -> None:
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def row_at(self, row: int) -> NetworkEventRow:
        return self._rows[row]

    def rowCount(  # noqa: N802
        self, parent: QModelIndex | QPersistentModelIndex = _NO_INDEX
    ) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(  # noqa: N802
        self, parent: QModelIndex | QPersistentModelIndex = _NO_INDEX
    ) -> int:
        return len(_EVENT_COLUMNS)

    def headerData(  # noqa: N802
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object:
        if role != Qt.ItemDataRole.DisplayRole or orientation != Qt.Orientation.Horizontal:
            return None
        return _EVENT_COLUMNS[section]

    def data(
        self,
        index: QModelIndex | QPersistentModelIndex,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object:
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        column = index.column()

        is_suspicious, threat_tag, threat_detail = analyze_packet_threat(
            source=row.source,
            destination=row.destination,
            protocol=row.protocol,
            packets=row.packets or 0,
            bytes_transferred=row.bytes or 0,
            state=row.event_type or "",
        )

        if role == Qt.ItemDataRole.BackgroundRole:
            if is_suspicious:
                return QColor(248, 81, 73, 40)
            return None

        if role == Qt.ItemDataRole.ToolTipRole:
            if is_suspicious:
                return (
                    f"[\U0001f6a8 SUSPICIOUS NETWORK EVENT - {threat_tag}]\n"
                    f"{threat_detail}\n"
                    f"Event Type: {row.event_type}"
                )
            return None

        if role == Qt.ItemDataRole.ForegroundRole:
            if is_suspicious:
                if column in (3, 4):
                    return QColor("#FFA198")
                if column == 1:
                    return QColor("#FF4444")
                return QColor("#FF7B72")
            return None

        if role == Qt.ItemDataRole.DisplayRole:
            return self._display(row, column)
        if role == Qt.ItemDataRole.UserRole:
            return self._sort_key(row, column)
        return None

    @staticmethod
    def _display(row: NetworkEventRow, column: int) -> str:
        if column == 0:
            return format_timestamp(row.timestamp)
        if column == 1:
            return row.event_type
        if column == 2:
            return row.protocol
        if column == 3:
            return row.source
        if column == 4:
            return row.destination
        if column == 5:
            return MISSING if row.packets is None else str(row.packets)
        if column == 6:
            return MISSING if row.bytes is None else str(row.bytes)
        return MISSING

    @staticmethod
    def _sort_key(row: NetworkEventRow, column: int) -> object:
        if column == 0:
            return row.timestamp.timestamp()
        return NetworkEventTableModel._display(row, column).lower()


_ARP_COLUMNS = (
    "IP Address",
    "MAC Address",
    "Vendor / Brand",
    "Device Role",
    "Status",
    "First Seen",
    "Last Seen",
    "Packets",
)
_ARP_WIDTHS = (140, 160, 200, 180, 120, 100, 100, 80)


class ArpRadarTableModel(QAbstractTableModel):
    """Qt table model over a tuple of :class:`ArpDeviceRow`."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._rows: list[ArpDeviceRow] = []

    def set_rows(self, rows: tuple[ArpDeviceRow, ...]) -> None:
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def row_at(self, row: int) -> ArpDeviceRow:
        return self._rows[row]

    def rowCount(  # noqa: N802
        self, parent: QModelIndex | QPersistentModelIndex = _NO_INDEX
    ) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(  # noqa: N802
        self, parent: QModelIndex | QPersistentModelIndex = _NO_INDEX
    ) -> int:
        return len(_ARP_COLUMNS)

    def headerData(  # noqa: N802
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object:
        if role != Qt.ItemDataRole.DisplayRole or orientation != Qt.Orientation.Horizontal:
            return None
        return _ARP_COLUMNS[section]

    def data(
        self,
        index: QModelIndex | QPersistentModelIndex,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> object:
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.BackgroundRole:
            if row.is_suspicious:
                return QColor(248, 81, 73, 40)
            return None

        if role == Qt.ItemDataRole.ToolTipRole:
            if row.is_suspicious:
                return (
                    f"[⚠️ SUSPICIOUS ARP ACTIVITY / SPOOFER DETECTED]\n"
                    f"IP: {row.ip}\n"
                    f"MAC: {row.mac}\n"
                    f"Vendor: {row.vendor}\n"
                    f"Threat: Active ARP cache poisoning or unauthorized IP conflict."
                )
            return (
                f"Host: {row.ip}\n"
                f"MAC: {row.mac}\n"
                f"Hardware Brand: {row.vendor}\n"
                f"Network Role: {row.role}\n"
                f"Packets Observed: {row.packets}"
            )

        if role == Qt.ItemDataRole.ForegroundRole:
            if row.is_suspicious:
                return QColor("#FF4444")
            if col == 0:  # IP
                return QColor("#38BDF8")
            if col == 1:  # MAC
                return QColor("#94A3B8")
            if col == 2:  # Vendor
                return QColor("#34D399")
            if col == 3:  # Role
                if "GATEWAY" in row.role:
                    return QColor("#F59E0B")
                if "THIS COMPUTER" in row.role:
                    return QColor("#60A5FA")
                return QColor("#E2E8F0")
            if col == 4:  # Status
                return (
                    QColor("#10B981")
                    if row.status in ("ACTIVE", "ONLINE")
                    else QColor("#94A3B8")
                )
            return None

        if role == Qt.ItemDataRole.DisplayRole:
            return self._display(row, col)

        if role == Qt.ItemDataRole.UserRole:
            return self._sort_key(row, col)

        return None

    @staticmethod
    def _display(row: ArpDeviceRow, col: int) -> str:
        if col == 0:
            return row.ip
        if col == 1:
            return row.mac
        if col == 2:
            return row.vendor
        if col == 3:
            return row.role
        if col == 4:
            return row.status
        if col == 5:
            return row.first_seen
        if col == 6:
            return row.last_seen
        if col == 7:
            return str(row.packets)
        return ""

    @staticmethod
    def _sort_key(row: ArpDeviceRow, col: int) -> object:
        if col == 0:
            try:
                return tuple(int(x) for x in row.ip.split("."))
            except Exception:
                return (999, 999, 999, 999)
        if col == 7:
            return row.packets
        return ArpRadarTableModel._display(row, col).lower()


def _make_table(model: QAbstractTableModel, widths: tuple[int, ...]) -> QTableView:
    proxy = QSortFilterProxyModel()
    proxy.setSourceModel(model)
    proxy.setSortRole(Qt.ItemDataRole.UserRole)
    table = QTableView()
    table.setModel(proxy)
    table.setSortingEnabled(True)
    table.setAlternatingRowColors(True)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setTextElideMode(Qt.TextElideMode.ElideMiddle)
    table.setWordWrap(False)
    table.verticalHeader().setVisible(False)
    table.horizontalHeader().setStretchLastSection(False)
    table.horizontalHeader().setSectionsMovable(True)
    for index, width in enumerate(widths):
        table.setColumnWidth(index, width)
    table.setProperty("proxy", proxy)
    return table


class NetworkPage(BasePage):
    """Read-only network monitoring, endpoints, flows and events."""

    PAGE_KEY  = "network"
    ICON       = "◎"
    ICON_COLOR = "#06B6D4"
    TITLE     = "Network"
    SUBTITLE = "Read-only network monitoring: capture status, endpoints, flows and events."
    EMPTY_STATE = ""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        provider: Callable[[], PortSnapshotView] | None = None,
        monitoring_provider: Callable[[], NetworkMonitoringView] | None = None,
        arp_service: ArpRadarService | None = None,
    ) -> None:
        self._provider: Callable[[], PortSnapshotView] = provider or collect_port_view
        self._monitoring_provider: Callable[[], NetworkMonitoringView] = (
            monitoring_provider or collect_network_monitoring_view
        )
        self._arp_service: ArpRadarService = arp_service or ArpRadarService()
        self._snapshot: PortSnapshotView | None = None
        self._monitoring: NetworkMonitoringView | None = None
        self._error_active = False

        super().__init__(parent)
        # Deliberately no automatic collection or capture on open.
        self._show_initial_state()

    # -- Construction ------------------------------------------------------

    def build_content(self) -> QWidget:
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        layout.addLayout(self._build_toolbar())
        layout.addWidget(self._build_status_card())

        self._error_label = QLabel("")
        self._error_label.setObjectName("ErrorBanner")
        self._error_label.setWordWrap(True)
        self._error_label.setVisible(False)
        layout.addWidget(self._error_label)

        self._hint_label = QLabel(_INITIAL_HINT)
        self._hint_label.setObjectName("EmptyState")
        self._hint_label.setWordWrap(True)
        layout.addWidget(self._hint_label)

        self._port_model = PortTableModel(self)
        self._port_table = _make_table(self._port_model, _PORT_WIDTHS)
        self._proxy = self._port_table.property("proxy")

        self._audit_model = PortAuditTableModel(self)
        self._audit_table = _make_table(self._audit_model, _AUDIT_WIDTHS)

        self._flow_model = FlowTableModel(self)
        self._flow_table = _make_table(self._flow_model, _FLOW_WIDTHS)

        self._event_model = NetworkEventTableModel(self)
        self._event_table = _make_table(self._event_model, _EVENT_WIDTHS)

        self._arp_model = ArpRadarTableModel(self)
        self._arp_table = _make_table(self._arp_model, _ARP_WIDTHS)

        self._tabs = QTabWidget()
        self._tabs.addTab(self._port_table, "Listening Ports")
        self._tabs.addTab(self._audit_table, "Port Security Audit (Open / Closed)")
        self._tabs.addTab(self._flow_table, "Flows")
        self._tabs.addTab(self._event_table, "Network Events")
        self._tabs.addTab(self._build_arp_tab(), "ARP Radar (Subnet Devices)")
        self._tabs.currentChanged.connect(self._on_tab_changed)
        layout.addWidget(self._tabs, 1)
        return content

    def _build_toolbar(self) -> QHBoxLayout:
        toolbar = QHBoxLayout()
        toolbar.setSpacing(12)

        self._refresh_button = QPushButton("Refresh")
        self._refresh_button.setObjectName("PrimaryButton")
        self._refresh_button.clicked.connect(self._on_refresh_clicked)

        self._count_label = QLabel(_NO_DATA_TEXT)
        self._count_label.setObjectName("FieldValue")
        self._last_updated_label = QLabel("Last updated: —")
        self._last_updated_label.setObjectName("CardHint")

        toolbar.addWidget(self._refresh_button)
        toolbar.addWidget(self._count_label)
        toolbar.addWidget(self._last_updated_label)
        toolbar.addStretch(1)
        return toolbar

    def _build_status_card(self) -> QWidget:
        card = QFrame()
        card.setObjectName("Card")
        outer = QVBoxLayout(card)
        outer.setContentsMargins(16, 10, 16, 10)
        outer.setSpacing(6)

        row1 = QHBoxLayout()
        row1.setSpacing(18)
        self._monitoring_label = QLabel("Network Monitoring: STOPPED")
        self._monitoring_label.setObjectName("FieldValue")
        self._capture_label = QLabel("Capture: INACTIVE")
        self._capture_label.setObjectName("CardHint")
        self._interface_label = QLabel("Interface: —")
        self._interface_label.setObjectName("CardHint")
        row1.addWidget(self._monitoring_label)
        row1.addWidget(self._capture_label)
        row1.addWidget(self._interface_label)
        row1.addStretch(1)

        row2 = QHBoxLayout()
        row2.setSpacing(18)
        self._packets_label = QLabel("Packets: Unavailable")
        self._packets_label.setObjectName("FieldValue")
        self._bytes_label = QLabel("Bytes: Unavailable")
        self._bytes_label.setObjectName("CardHint")
        self._flows_label = QLabel("Flows: Unavailable")
        self._flows_label.setObjectName("CardHint")
        self._active_flows_label = QLabel("Active Flows: Unavailable")
        self._active_flows_label.setObjectName("CardHint")
        row2.addWidget(self._packets_label)
        row2.addWidget(self._bytes_label)
        row2.addWidget(self._flows_label)
        row2.addWidget(self._active_flows_label)
        row2.addStretch(1)

        outer.addLayout(row1)
        outer.addLayout(row2)

        self._capture_error_label = QLabel("")
        self._capture_error_label.setObjectName("ErrorBanner")
        self._capture_error_label.setWordWrap(True)
        self._capture_error_label.setVisible(False)
        outer.addWidget(self._capture_error_label)
        return card

    # -- Refresh -----------------------------------------------------------

    def _on_tab_changed(self, index: int) -> None:
        if index == 4:
            self.refresh_arp(live_sync=True)

    def _on_refresh_clicked(self) -> None:
        self.refresh()
        self.refresh_live()
        if self._tabs.currentIndex() == 4:
            self.scan_arp_subnet()
        else:
            self.refresh_arp()

    def refresh(self) -> PortSnapshotView | None:
        """One one-shot listening-endpoint collection (never captures packets)."""
        try:
            view = self._provider()
        except Exception as exc:
            logger.warning("Network refresh failed: %s", exc)
            self._show_error(PORT_ERROR)
            return None

        self._apply(view)
        return view

    def refresh_live(self) -> NetworkMonitoringView | None:
        """Read live network monitoring state from the running runtime.

        Read-only: it never captures, never polls the runtime (the window's
        single timer does that) and never fabricates telemetry.
        """
        try:
            view = self._monitoring_provider()
        except Exception as exc:
            logger.warning("Network monitoring refresh failed: %s", exc)
            return None

        self._monitoring = view
        self._apply_monitoring(view)
        # Real-time ARP radar sync when viewing the ARP Radar tab
        if self._tabs.currentIndex() == 4:
            self.refresh_arp(live_sync=True)
        return view

    def _apply(self, view: PortSnapshotView) -> None:
        self._snapshot = view
        self._hint_label.setVisible(False)

        if view.available:
            self._set_error(None)
            self._port_model.set_rows(view.rows)
            self._audit_model.set_rows(build_port_audit_rows(view.rows))
            self._count_label.setText(f"Endpoints: {view.count}")
            self._last_updated_label.setText(f"Last updated: {format_timestamp(view.collected_at)}")
        else:
            self._port_model.set_rows(())
            self._audit_model.set_rows(())
            self._count_label.setText(_NO_DATA_TEXT)
            self._last_updated_label.setText("Last updated: —")
            self._set_error(view.error or PORT_ERROR)

    def _apply_monitoring(self, view: NetworkMonitoringView) -> None:
        status = view.status
        self._monitoring_label.setText(
            "Network Monitoring: RUNNING" if status.running else "Network Monitoring: STOPPED"
        )
        set_state(self._monitoring_label, "running" if status.running else "stopped")
        capture_text = {
            CAPTURE_ACTIVE: "ACTIVE",
            CAPTURE_ERROR: "ERROR",
        }.get(status.capture_state, "INACTIVE")
        self._capture_label.setText(f"Capture: {capture_text}")
        set_state(
            self._capture_label,
            {"active": "active", "error": "error"}.get(status.capture_state, "inactive"),
        )
        self._interface_label.setText(f"Interface: {status.interface or '—'}")

        if status.capture_error:
            self._capture_error_label.setText(
                f"Network Capture: ERROR\nReason: {status.capture_error}"
            )
            self._capture_error_label.setVisible(True)
        else:
            self._capture_error_label.setVisible(False)
            self._capture_error_label.setText("")

        counters = status.counters
        self._packets_label.setText(_counter_text("Packets", counters.packets, fmt_bytes=False))
        self._bytes_label.setText(_counter_text("Bytes", counters.bytes, fmt_bytes=True))
        self._flows_label.setText(_counter_text("Flows", counters.flows, fmt_bytes=False))
        self._active_flows_label.setText(
            _counter_text("Active Flows", counters.active_flows, fmt_bytes=False)
        )

        self._flow_model.set_rows(view.flows)
        self._event_model.set_rows(view.events)

        if status.running and not view.flows and not view.events:
            self._hint_label.setText("No network activity observed")
            self._hint_label.setVisible(True)

    def _show_initial_state(self) -> None:
        self._snapshot = None
        self._monitoring = None
        self._port_model.set_rows(())
        self._audit_model.set_rows(())
        self._flow_model.set_rows(())
        self._event_model.set_rows(())
        self._count_label.setText(_NO_DATA_TEXT)
        self._last_updated_label.setText("Last updated: —")
        self._hint_label.setText(_INITIAL_HINT)
        self._hint_label.setVisible(True)
        self._apply_monitoring(NetworkMonitoringView(status=_initial_status(), flows=(), events=()))
        self._set_error(None)

    def _show_error(self, message: str) -> None:
        self._snapshot = None
        self._hint_label.setVisible(False)
        self._port_model.set_rows(())
        self._audit_model.set_rows(())
        self._count_label.setText(_NO_DATA_TEXT)
        self._last_updated_label.setText("Last updated: —")
        self._set_error(message)

    def _set_error(self, message: str | None) -> None:
        self._error_active = message is not None
        self._error_label.setText(message or "")
        self._error_label.setVisible(message is not None)

    # -- Read-only accessors (also used by tests) --------------------------

    @property
    def snapshot(self) -> PortSnapshotView | None:
        """The last successfully applied endpoint snapshot, if any."""
        return self._snapshot

    @property
    def monitoring(self) -> NetworkMonitoringView | None:
        """The last applied live monitoring view, if any."""
        return self._monitoring

    @property
    def source_model(self) -> PortTableModel:
        """The underlying port table model."""
        return self._port_model

    @property
    def proxy_model(self) -> QSortFilterProxyModel:
        """The sorting proxy model for the port table."""
        return self._proxy

    @property
    def table_view(self) -> QTableView:
        """The port table view widget."""
        return self._port_table

    def column_headers(self) -> tuple[str, ...]:
        """Return the listening-port table's column headers."""
        return _PORT_COLUMNS

    def row_count(self) -> int:
        """Number of listening endpoints currently displayed."""
        return self._port_model.rowCount()

    def row_at(self, row: int) -> PortRow:
        """Return the displayed endpoint row at ``row``."""
        return self._port_model.row_at(row)

    def flow_count(self) -> int:
        """Number of flows currently displayed."""
        return self._flow_model.rowCount()

    def flow_row_at(self, row: int) -> FlowRow:
        """Return the displayed flow row at ``row``."""
        return self._flow_model.row_at(row)

    def event_count(self) -> int:
        """Number of network events currently displayed."""
        return self._event_model.rowCount()

    def endpoint_count_text(self) -> str:
        """Return the 'Endpoints: <count>' text."""
        return self._count_label.text()

    def monitoring_status_text(self) -> str:
        """Return the 'Network Monitoring: RUNNING/STOPPED' text."""
        return self._monitoring_label.text()

    def capture_status_text(self) -> str:
        """Return the 'Capture: ACTIVE/INACTIVE/ERROR' text."""
        return self._capture_label.text()

    def interface_text(self) -> str:
        """Return the 'Interface: <name>' text."""
        return self._interface_label.text()

    def packets_text(self) -> str:
        """Return the 'Packets: <n>' text."""
        return self._packets_label.text()

    def bytes_text(self) -> str:
        """Return the 'Bytes: <n>' text."""
        return self._bytes_label.text()

    def flows_text(self) -> str:
        """Return the 'Flows: <n>' text."""
        return self._flows_label.text()

    def active_flows_text(self) -> str:
        """Return the 'Active Flows: <n>' text."""
        return self._active_flows_label.text()

    def capture_error_text(self) -> str:
        """Return the capture error banner text (empty when none)."""
        return self._capture_error_label.text()

    def last_updated_text(self) -> str:
        """Return the 'Last updated' text."""
        return self._last_updated_label.text()

    def has_error(self) -> bool:
        """Whether the page is showing a safe error state."""
        return self._error_active

    def error_text(self) -> str:
        """Return the current error banner text (empty when there is no error)."""
        return self._error_label.text()

    def _build_arp_tab(self) -> QWidget:
        container = QWidget()
        lay = QVBoxLayout(container)
        lay.setContentsMargins(0, 8, 0, 0)
        lay.setSpacing(8)

        bar = QHBoxLayout()
        bar.setSpacing(16)

        hdr_lbl = QLabel("📡 ARP RADAR:")
        hdr_lbl.setObjectName("FieldKey")
        hdr_lbl.setStyleSheet("font-weight: 700; color: #38BDF8;")

        self._arp_status_lbl = QLabel(f"Subnet: {self._arp_service.subnet_cidr} | Devices: 0")
        self._arp_status_lbl.setObjectName("FieldValue")

        self._arp_gw_lbl = QLabel(f"Gateway: {self._arp_service.gateway_ip}")
        self._arp_gw_lbl.setObjectName("CardHint")

        hint_lbl = QLabel("(Use toolbar 'Refresh' to update local subnet devices)")
        hint_lbl.setObjectName("CardHint")

        bar.addWidget(hdr_lbl)
        bar.addWidget(self._arp_status_lbl)
        bar.addWidget(self._arp_gw_lbl)
        bar.addWidget(hint_lbl)
        bar.addStretch(1)

        lay.addLayout(bar)

        self._arp_alert_banner = QLabel("")
        self._arp_alert_banner.setObjectName("ErrorBanner")
        self._arp_alert_banner.setWordWrap(True)
        self._arp_alert_banner.setVisible(False)
        lay.addWidget(self._arp_alert_banner)

        lay.addWidget(self._arp_table, 1)
        return container

    def scan_arp_subnet(self) -> None:
        """Trigger an ARP scan of the local subnet and refresh the table."""
        self._arp_service.scan_subnet()
        self.refresh_arp()

    def refresh_arp(self, *, live_sync: bool = False) -> None:
        """Update the displayed ARP Radar devices and alerts."""
        if live_sync:
            self._arp_service.sync_live_endpoints()
        rows = self._arp_service.get_rows()
        self._arp_model.set_rows(tuple(rows))
        summary = self._arp_service.get_summary()
        self._arp_status_lbl.setText(
            f"Subnet: {summary['subnet']} | Devices: {summary['total_devices']}"
        )
        self._arp_gw_lbl.setText(f"Gateway: {summary['gateway_ip']}")
        if summary["is_mitm_detected"]:
            self._arp_alert_banner.setText(
                "🚨 CRITICAL ALERT: ARP SPOOFING / MITM ATTACK DETECTED! "
                "A rogue MAC address is attempting to hijack the default gateway."
            )
            self._arp_alert_banner.setVisible(True)
        elif summary["suspicious_count"] > 0:
            self._arp_alert_banner.setText(
                "⚠️ WARNING: Suspicious ARP activity observed on the local network."
            )
            self._arp_alert_banner.setVisible(True)
        else:
            self._arp_alert_banner.setVisible(False)

    def arp_device_count(self) -> int:
        """Number of ARP devices currently displayed."""
        return self._arp_model.rowCount()

    def arp_row_at(self, row: int) -> ArpDeviceRow:
        """Return the displayed ARP device row at ``row``."""
        return self._arp_model.row_at(row)

    def arp_status_text(self) -> str:
        """Return the current ARP status text."""
        return self._arp_status_lbl.text()

    def arp_alert_text(self) -> str:
        """Return the current ARP alert text."""
        return self._arp_alert_banner.text()


def _counter_text(label: str, value: int | None, *, fmt_bytes: bool) -> str:
    if value is None:
        return f"{label}: {_UNAVAILABLE}"
    if fmt_bytes:
        return f"{label}: {format_bytes(value)}"
    return f"{label}: {value}"


def _initial_status() -> MonitoringStatus:
    from aegis_desktop.services.monitoring import CAPTURE_INACTIVE, NetworkCounters

    return MonitoringStatus(
        running=False,
        capture_state=CAPTURE_INACTIVE,
        capture_error=None,
        interface=None,
        counters=NetworkCounters(packets=None, bytes=None, flows=None, active_flows=None),
    )


__all__ = [
    "ArpRadarTableModel",
    "FlowTableModel",
    "NetworkEventTableModel",
    "NetworkPage",
    "PortTableModel",
]
