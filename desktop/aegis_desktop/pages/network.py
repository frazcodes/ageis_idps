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
from aegis_desktop.services.dashboard import format_bytes, format_timestamp
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
        if role == Qt.ItemDataRole.DisplayRole:
            return self._display(row, column)
        if role == Qt.ItemDataRole.ToolTipRole and column == 0:
            return row.flow_id
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
    for index, width in enumerate(widths):
        table.setColumnWidth(index, width)
    table.setProperty("proxy", proxy)
    return table


class NetworkPage(BasePage):
    """Read-only network monitoring, endpoints, flows and events."""

    PAGE_KEY = "network"
    TITLE = "Network"
    SUBTITLE = "Read-only network monitoring: capture status, endpoints, flows and events."
    EMPTY_STATE = ""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        provider: Callable[[], PortSnapshotView] | None = None,
        monitoring_provider: Callable[[], NetworkMonitoringView] | None = None,
    ) -> None:
        self._provider: Callable[[], PortSnapshotView] = provider or collect_port_view
        self._monitoring_provider: Callable[[], NetworkMonitoringView] = (
            monitoring_provider or collect_network_monitoring_view
        )
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

        self._flow_model = FlowTableModel(self)
        self._flow_table = _make_table(self._flow_model, _FLOW_WIDTHS)

        self._event_model = NetworkEventTableModel(self)
        self._event_table = _make_table(self._event_model, _EVENT_WIDTHS)

        self._tabs = QTabWidget()
        self._tabs.addTab(self._port_table, "Listening Ports")
        self._tabs.addTab(self._flow_table, "Flows")
        self._tabs.addTab(self._event_table, "Network Events")
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

    def _on_refresh_clicked(self) -> None:
        self.refresh()
        self.refresh_live()

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
        return view

    def _apply(self, view: PortSnapshotView) -> None:
        self._snapshot = view
        self._hint_label.setVisible(False)

        if view.available:
            self._set_error(None)
            self._port_model.set_rows(view.rows)
            self._count_label.setText(f"Endpoints: {view.count}")
            self._last_updated_label.setText(f"Last updated: {format_timestamp(view.collected_at)}")
        else:
            self._port_model.set_rows(())
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
    "FlowTableModel",
    "NetworkEventTableModel",
    "NetworkPage",
    "PortTableModel",
]
