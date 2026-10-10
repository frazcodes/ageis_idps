"""Bounded in-memory store for live network activity on the SOC dashboard.

Provides a time-ordered, deduplicated ring buffer of recent network activity
rows and a Qt table model for displaying them.  All data is read-only and
collected from the existing runtime -- no capture, no fabrication.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QPersistentModelIndex, Qt
from PySide6.QtGui import QColor

from aegis_desktop.theme import TEXT_MUTED, state_color
from aegis_shared.logging import get_logger

logger = get_logger(__name__)

#: Maximum number of live network activity rows retained in memory.
MAX_ACTIVITY_ROWS = 100

_COLUMNS = (
    "Time",
    "Source",
    "Destination",
    "Port",
    "Protocol",
    "Packets",
    "Bytes",
    "Direction",
    "State",
)

_PORT_WIDTHS = (90, 185, 185, 75, 80, 80, 95, 85, 85)


#: Critical attack, reconnaissance, and lateral movement ports.
_CRITICAL_PORTS: dict[int, tuple[str, str]] = {
    445: ("SMB EXPLOIT", "SMB Port 445: High-risk lateral movement / EternalBlue exploit attempt"),
    3389: ("RDP BRUTE", "RDP Port 3389: Remote Desktop brute-force or unauthorized session"),
    23: ("TELNET INSECURE", "Telnet Port 23: Cleartext credentials / Mirai botnet probe"),
    21: ("FTP INSECURE", "FTP Port 21: Unencrypted file transfer / credential sniffing"),
    135: ("MSRPC PROBE", "MSRPC Port 135: Windows RPC endpoint mapper exploit probe"),
    139: ("NETBIOS SCAN", "NetBIOS Port 139: Windows name/file sharing enumeration"),
    4444: ("METASPLOIT C2", "Port 4444: Metasploit default payload / reverse shell C2 beacon"),
    5985: ("WINRM EXEC", "WinRM Port 5985: Remote PowerShell execution probe"),
    6379: ("REDIS EXPOSURE", "Redis Port 6379: Unauthenticated memory dump / code execution"),
    6667: ("IRC BOTNET", "IRC Port 6667: Internet Relay Chat botnet command & control channel"),
    31337: ("BACKDOOR", "Port 31337: Elite backdoor / Trojan communication"),
}


def _check_domain_ioc(clean_domain: str, matcher: Any = None) -> tuple[bool, str, str] | None:
    try:
        from aegis_shared.enums import IndicatorType
        from aegis_shared.threat_intel import IOCMatcher, get_threat_intel_settings

        m = (
            matcher
            if matcher is not None
            else IOCMatcher.from_settings(get_threat_intel_settings())
        )
        if m and m.enabled:
            bucket = m._index.get(IndicatorType.DOMAIN, {})
            indicator = bucket.get(clean_domain)
            if indicator is not None:
                desc = (
                    indicator.description
                    or f"Configured threat indicator {indicator.indicator_id}"
                )
                return (
                    True,
                    "MALICIOUS IOC DOMAIN",
                    f"TLS SNI matches configured threat-intelligence indicator: "
                    f"{indicator.value} ({desc})",
                )
    except Exception as exc:
        logger.debug("Domain IOC check failed: %s", exc)
    return None


def analyze_packet_threat(
    source: str = "",
    destination: str = "",
    port: str = "",
    protocol: str = "",
    packets: int = 0,
    bytes_transferred: int = 0,
    state: str = "",
    domain: str = "",
    ioc_matcher: Any = None,
) -> tuple[bool, str, str]:
    """Analyze a network flow or packet event for suspicious signatures and anomalies.

    Returns:
        tuple of (is_suspicious: bool, threat_tag: str, threat_detail: str)
    """
    st = state.strip().lower()
    if st in ("alert", "threat", "suspicious", "blocked", "exploit", "critical"):
        return True, "ACTIVE ALERT", f"Security engine flagged active security state: {state}"

    # 1. Threat Intelligence Domain IOC Matching (deterministic, high priority)
    clean_domain = domain.strip().lower().rstrip(".") if domain else ""
    if clean_domain:
        ioc_hit = _check_domain_ioc(clean_domain, ioc_matcher)
        if ioc_hit is not None:
            return ioc_hit

    # 2. Critical Ports Analysis
    candidate_ports: list[int] = []
    if port and port.isdigit():
        candidate_ports.append(int(port))
    for endpoint in (destination, source):
        # Strip domain suffix if present in endpoint string
        ep_base = endpoint.split(" ", 1)[0]
        if ":" in ep_base:
            p_str = ep_base.rsplit(":", 1)[1]
            if p_str.isdigit():
                candidate_ports.append(int(p_str))

    for cp in candidate_ports:
        if cp in _CRITICAL_PORTS:
            tag, desc = _CRITICAL_PORTS[cp]
            if clean_domain:
                desc = f"{desc} | Target domain: {clean_domain}"
            return True, tag, desc

    # 3. High Volume Flooding
    proto = protocol.strip().upper()
    if "ICMP" in proto and packets > 500:
        return True, "ICMP FLOOD", f"High-volume ICMP flood detected: {packets} packets"

    if packets > 5000 or bytes_transferred > 10_000_000:
        return (
            True,
            "TRAFFIC FLOOD",
            f"Anomalous high-volume flow: {packets} packets, {bytes_transferred} bytes",
        )

    # Note: Benign domains with unusual TLDs (e.g., .xyz, .top) are NOT classified as
    # malicious on their own without corresponding IOC matches, anomaly findings, or exploit ports.
    return False, "", ""


@dataclass(frozen=True)
class LiveActivityRow:
    """One row of live network activity for the SOC dashboard."""

    timestamp: datetime
    source: str
    destination: str
    port: str
    protocol: str
    packets: int
    bytes: int
    direction: str
    state: str
    flow_id: str
    is_suspicious: bool = False
    threat_tag: str = ""
    threat_detail: str = ""
    sni: str | None = None



class LiveNetworkActivity:
    """Bounded in-memory store of recent network activity rows.

    Maintains a FIFO ring buffer of at most ``max_rows`` entries.  Duplicate
    ``flow_id`` values update the existing row rather than adding new entries.
    """

    def __init__(self, max_rows: int = MAX_ACTIVITY_ROWS) -> None:
        self._max_rows = max_rows
        self._rows: deque[LiveActivityRow] = deque(maxlen=max_rows)
        self._index: dict[str, int] = {}
        self._seen_flow_ids: set[str] = set()

    @property
    def count(self) -> int:
        """Number of rows currently stored."""
        return len(self._rows)

    @property
    def max_rows(self) -> int:
        """Maximum rows this store can hold."""
        return self._max_rows

    def add(self, row: LiveActivityRow) -> None:
        """Add or update a row.  Duplicate flow_ids update in place."""
        if row.flow_id in self._seen_flow_ids:
            for idx, existing in enumerate(self._rows):
                if existing.flow_id == row.flow_id:
                    self._rows[idx] = row
                    break
        else:
            if len(self._rows) == self._max_rows:
                removed = self._rows.popleft()
                self._seen_flow_ids.discard(removed.flow_id)
            self._rows.append(row)
            self._seen_flow_ids.add(row.flow_id)

    def rows(self) -> tuple[LiveActivityRow, ...]:
        """Return all rows in chronological order (oldest first)."""
        return tuple(self._rows)

    def latest(self) -> LiveActivityRow | None:
        """Return the most recent row, or ``None`` if empty."""
        return self._rows[-1] if self._rows else None

    def clear(self) -> None:
        """Remove all stored rows."""
        self._rows.clear()
        self._seen_flow_ids.clear()


_PARENT_INDEX = QModelIndex()


class LiveNetworkTableModel(QAbstractTableModel):
    """Qt table model for live network activity rows."""

    def __init__(self, parent: Any = None) -> None:
        super().__init__(parent)
        self._rows: list[LiveActivityRow] = []

    def rowCount(  # noqa: N802
        self, parent: QModelIndex | QPersistentModelIndex = _PARENT_INDEX
    ) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(  # noqa: N802
        self, parent: QModelIndex | QPersistentModelIndex = _PARENT_INDEX
    ) -> int:
        return len(_COLUMNS)

    def data(
        self,
        index: QModelIndex | QPersistentModelIndex,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:
        if not index.isValid() or index.row() >= len(self._rows):
            return None
        row = self._rows[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.BackgroundRole:
            if row.is_suspicious:
                return QColor(248, 81, 73, 40)
            return None
        if role == Qt.ItemDataRole.ToolTipRole:
            if row.is_suspicious:
                sni_info = f"\nSNI Hostname: {row.sni}" if row.sni else ""
                return (
                    f"[\U0001f6a8 SUSPICIOUS NETWORK ACTIVITY DETECTED]\n"
                    f"Threat: {row.threat_tag}\n"
                    f"Details: {row.threat_detail}\n"
                    f"Flow: {row.source} -> {row.destination} ({row.protocol}){sni_info}\n"
                    f"Triage: Review endpoint containment or firewall block rule."
                )
            if col == 2 and row.sni:
                return f"Resolved TLS SNI Hostname: {row.sni}"
            return None
        if role == Qt.ItemDataRole.DisplayRole:
            return self._display(row, col)
        if role == Qt.ItemDataRole.UserRole:
            return self._sort_key(row, col)
        if role == Qt.ItemDataRole.TextAlignmentRole:
            if col in (0, 3, 4, 7, 8):
                return Qt.AlignmentFlag.AlignCenter
            if col in (5, 6):
                return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
            return Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        if role == Qt.ItemDataRole.ForegroundRole:
            if row.is_suspicious:
                if col in (1, 2):
                    return QColor("#FFA198")
                if col == 3:
                    return QColor("#FF7B72")
                if col == 8:
                    return QColor("#FF4444")
                return QColor("#FF7B72")
            if col == 0:  # Time
                return QColor("#94A3B8")
            if col in (1, 2):  # Source, Destination
                return QColor("#E2E8F0")
            if col == 3:  # Port column
                return QColor("#38BDF8") if row.port else QColor(TEXT_MUTED)
            if col == 4:  # Protocol
                proto = row.protocol.upper()
                if "TCP" in proto:
                    return QColor("#60A5FA")
                if "UDP" in proto:
                    return QColor("#F59E0B")
                if "ICMP" in proto:
                    return QColor("#EC4899")
                return QColor("#A78BFA")
            if col == 5:  # Packets
                return QColor("#F1F5F9")
            if col == 6:  # Bytes
                return QColor("#34D399")
            if col == 7:  # Direction
                direction_colors = {
                    "outbound": QColor("#3B82F6"),
                    "inbound": QColor("#10B981"),
                }
                return direction_colors.get(row.direction.lower(), QColor("#94A3B8"))
            if col == 8:  # State
                return state_color(row.state)
        return None

    def headerData(  # noqa: N802
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if (
            role == Qt.ItemDataRole.DisplayRole
            and orientation == Qt.Orientation.Horizontal
            and 0 <= section < len(_COLUMNS)
        ):
            return _COLUMNS[section]
        return None

    def set_rows(self, rows: tuple[LiveActivityRow, ...]) -> None:
        """Replace all rows and reset the model."""
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def row_at(self, row: int) -> LiveActivityRow | None:
        """Return the row at ``row`` index, or ``None`` if out of range."""
        if 0 <= row < len(self._rows):
            return self._rows[row]
        return None

    @staticmethod
    def _display(row: LiveActivityRow, col: int) -> str:
        from aegis_desktop.services.dashboard import format_bytes

        if col == 0:
            return row.timestamp.strftime("%H:%M:%S") if row.timestamp else ""
        if col == 1:
            return row.source
        if col == 2:
            if row.sni and f"({row.sni})" not in row.destination:
                return f"{row.destination} ({row.sni})"
            return row.destination
        if col == 3:
            return row.port
        if col == 4:
            return row.protocol
        if col == 5:
            return str(row.packets) if row.packets else "0"
        if col == 6:
            return format_bytes(row.bytes) if row.bytes else "0 B"
        if col == 7:
            return row.direction
        if col == 8:
            if row.is_suspicious and row.threat_tag:
                return f"\U0001f6a8 {row.threat_tag}"
            return row.state
        return ""

    @staticmethod
    def _sort_key(row: LiveActivityRow, col: int) -> Any:
        if col == 0:
            return row.timestamp.timestamp() if row.timestamp else 0
        if col == 5:
            return row.packets
        if col == 6:
            return row.bytes
        return _display(row, col)


def _display(row: LiveActivityRow, col: int) -> str:
    return LiveNetworkTableModel._display(row, col)


__all__ = [
    "MAX_ACTIVITY_ROWS",
    "LiveActivityRow",
    "LiveNetworkActivity",
    "LiveNetworkTableModel",
    "analyze_packet_threat",
]
