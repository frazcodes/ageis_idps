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

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QColor

from aegis_desktop.theme import TEXT_MUTED, state_color

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

_PORT_WIDTHS = (80, 160, 160, 60, 70, 65, 75, 70, 70)


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

    def rowCount(self, parent: QModelIndex = _PARENT_INDEX) -> int:  # noqa: N802
        return len(self._rows)

    def columnCount(self, parent: QModelIndex = _PARENT_INDEX) -> int:  # noqa: N802
        return len(_COLUMNS)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or index.row() >= len(self._rows):
            return None
        row = self._rows[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            return self._display(row, col)
        if role == Qt.ItemDataRole.UserRole:
            return self._sort_key(row, col)
        if role == Qt.ItemDataRole.ForegroundRole:
            if col == 3:  # Port column
                return QColor(TEXT_MUTED)
            if col == 7:  # Direction
                direction_colors = {
                    "outbound": QColor("#3B82F6"),
                    "inbound": QColor("#10B981"),
                }
                return direction_colors.get(row.direction.lower())
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
]
