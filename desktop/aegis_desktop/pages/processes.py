"""Processes page: read-only process table backed by the Step 3 collector.

The page is presentation only. It performs a single one-shot collection per
``Refresh`` through :mod:`aegis_desktop.services.processes` (which calls the
existing collector) and renders the result with a Qt model/view table. There are
no destructive controls and no background polling.

Nothing is collected when the application starts; the user must press Refresh.
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
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from aegis_desktop.pages.base import BasePage
from aegis_desktop.services.dashboard import format_timestamp
from aegis_desktop.services.processes import (
    MISSING,
    PROCESS_ERROR,
    ProcessRow,
    ProcessSnapshotView,
    collect_process_view,
)
from aegis_shared.logging import get_logger

logger = get_logger(__name__)

_COLUMNS = (
    "PID",
    "Name",
    "Executable",
    "User",
    "Started",
    "PPID",
    "Parent",
    "Identity",
    "Command Line",
)

_COLUMN_WIDTHS = (80, 200, 320, 150, 160, 70, 170, 230, 120)

_INITIAL_HINT = (
    "Select Refresh to collect the current process list. Nothing is collected automatically."
)

#: Shared invalid index; avoids a function call in argument defaults (B008).
_NO_INDEX = QModelIndex()


class ProcessTableModel(QAbstractTableModel):
    """Qt table model over a tuple of :class:`ProcessRow`."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._rows: list[ProcessRow] = []

    def set_rows(self, rows: tuple[ProcessRow, ...]) -> None:
        """Replace the displayed rows."""
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def rows(self) -> tuple[ProcessRow, ...]:
        """Return the current rows."""
        return tuple(self._rows)

    def row_at(self, row: int) -> ProcessRow:
        """Return the row at ``row``."""
        return self._rows[row]

    def rowCount(  # noqa: N802
        self, parent: QModelIndex | QPersistentModelIndex = _NO_INDEX
    ) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(  # noqa: N802
        self, parent: QModelIndex | QPersistentModelIndex = _NO_INDEX
    ) -> int:
        return len(_COLUMNS)

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
        return _COLUMNS[section]

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

            if column in (0, 5):
                return QColor("#38BDF8")
            if column == 1:
                return QColor("#F8FAFC")
            if column == 8:
                return QColor("#10B981") if row.command_line_available else QColor("#64748B")
        if role == Qt.ItemDataRole.TextAlignmentRole:
            if column in (0, 4, 5, 8):
                return int(Qt.AlignmentFlag.AlignCenter)
            return int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        return None

    @staticmethod
    def _display(row: ProcessRow, column: int) -> str:
        if column == 0:
            return MISSING if row.pid is None else str(row.pid)
        if column == 1:
            return row.name or MISSING
        if column == 2:
            return row.executable or MISSING
        if column == 3:
            return row.username or MISSING
        if column == 4:
            return format_timestamp(row.create_time) if row.create_time else MISSING
        if column == 5:
            return MISSING if row.ppid is None else str(row.ppid)
        if column == 6:
            return row.parent_name or MISSING
        if column == 7:
            return row.identity or MISSING
        if column == 8:
            # The command line itself is sensitive and never displayed.
            return "Available" if row.command_line_available else "Not available"
        return MISSING

    @staticmethod
    def _tooltip(row: ProcessRow, column: int) -> str | None:
        if column == 2 and row.executable:
            return row.executable
        return None

    @staticmethod
    def _sort_key(row: ProcessRow, column: int) -> object:
        if column == 0:
            return row.pid if row.pid is not None else -1
        if column == 5:
            return row.ppid if row.ppid is not None else -1
        if column == 4:
            return row.create_time.timestamp() if row.create_time else 0.0
        if column == 8:
            return 1 if row.command_line_available else 0
        return ProcessTableModel._display(row, column).lower()


class ProcessesPage(BasePage):
    """Read-only process monitoring table."""

    PAGE_KEY  = "processes"
    ICON       = "≡"
    ICON_COLOR = "#8B5CF6"
    TITLE     = "Processes"
    SUBTITLE = "Read-only process inventory from the endpoint agent."
    EMPTY_STATE = ""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        provider: Callable[[], ProcessSnapshotView] | None = None,
    ) -> None:
        self._provider: Callable[[], ProcessSnapshotView] = provider or collect_process_view
        self._snapshot: ProcessSnapshotView | None = None
        self._error_active = False

        super().__init__(parent)
        # Deliberately no automatic collection: opening the application must not
        # start process monitoring.
        self._show_initial_state()

    # -- Construction ------------------------------------------------------

    def build_content(self) -> QWidget:
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        layout.addLayout(self._build_toolbar())

        self._error_label = QLabel("")
        self._error_label.setObjectName("ErrorBanner")
        self._error_label.setWordWrap(True)
        self._error_label.setVisible(False)
        layout.addWidget(self._error_label)

        self._hint_label = QLabel(_INITIAL_HINT)
        self._hint_label.setObjectName("EmptyState")
        self._hint_label.setWordWrap(True)
        layout.addWidget(self._hint_label)

        self._model = ProcessTableModel(self)
        self._proxy = QSortFilterProxyModel(self)
        self._proxy.setSourceModel(self._model)
        self._proxy.setSortRole(Qt.ItemDataRole.UserRole)
        self._proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._proxy.setFilterKeyColumn(-1)

        self._table = QTableView()
        self._table.setModel(self._proxy)
        self._table.setSortingEnabled(True)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        self._table.setWordWrap(False)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setStretchLastSection(False)
        self._table.horizontalHeader().setSectionsMovable(True)
        for index, width in enumerate(_COLUMN_WIDTHS):
            self._table.setColumnWidth(index, width)
        self._table.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        layout.addWidget(self._table, 1)
        return content

    def _build_toolbar(self) -> QHBoxLayout:
        toolbar = QHBoxLayout()
        toolbar.setSpacing(12)

        self._refresh_button = QPushButton("Refresh")
        self._refresh_button.setObjectName("PrimaryButton")
        self._refresh_button.clicked.connect(self.refresh)

        self._count_label = QLabel("Processes: —")
        self._count_label.setObjectName("FieldValue")
        self._last_updated_label = QLabel("Last updated: —")
        self._last_updated_label.setObjectName("CardHint")

        self._filter_input = QLineEdit()
        self._filter_input.setPlaceholderText("Filter processes by name, PID, user, or path...")
        self._filter_input.setClearButtonEnabled(True)
        self._filter_input.setMinimumWidth(280)
        self._filter_input.setMaximumWidth(380)
        self._filter_input.textChanged.connect(self._on_filter_changed)

        toolbar.addWidget(self._refresh_button)
        toolbar.addWidget(self._count_label)
        toolbar.addWidget(self._last_updated_label)
        toolbar.addStretch(1)
        toolbar.addWidget(self._filter_input)
        return toolbar

    def _on_filter_changed(self, text: str) -> None:
        self._proxy.setFilterFixedString(text.strip())

    # -- Refresh -----------------------------------------------------------

    def refresh(self) -> ProcessSnapshotView | None:
        """Perform one one-shot collection and update the table.

        Never starts the ``ProcessMonitor`` lifecycle, never polls and never
        modifies a process. On failure a safe error state is shown.
        """
        try:
            view = self._provider()
        except Exception as exc:
            logger.warning("Process refresh failed: %s", exc)
            self._show_error(PROCESS_ERROR)
            return None

        self._apply(view)
        return view

    def _apply(self, view: ProcessSnapshotView) -> None:
        self._snapshot = view
        self._hint_label.setVisible(False)

        if view.available:
            self._set_error(None)
            self._model.set_rows(view.rows)
            self._count_label.setText(f"Processes: {view.count}")
            self._last_updated_label.setText(f"Last updated: {format_timestamp(view.collected_at)}")
        else:
            self._model.set_rows(())
            self._count_label.setText("Processes: —")
            self._last_updated_label.setText("Last updated: —")
            self._set_error(view.error or PROCESS_ERROR)

    def _show_initial_state(self) -> None:
        self._snapshot = None
        self._model.set_rows(())
        self._count_label.setText("Processes: —")
        self._last_updated_label.setText("Last updated: —")
        self._hint_label.setVisible(True)
        self._set_error(None)

    def _show_error(self, message: str) -> None:
        self._snapshot = None
        self._hint_label.setVisible(False)
        self._model.set_rows(())
        self._count_label.setText("Processes: —")
        self._last_updated_label.setText("Last updated: —")
        self._set_error(message)

    def _set_error(self, message: str | None) -> None:
        self._error_active = message is not None
        self._error_label.setText(message or "")
        self._error_label.setVisible(message is not None)

    # -- Read-only accessors (also used by tests) --------------------------

    @property
    def snapshot(self) -> ProcessSnapshotView | None:
        """The last successfully applied snapshot, if any."""
        return self._snapshot

    @property
    def source_model(self) -> ProcessTableModel:
        """The underlying table model."""
        return self._model

    @property
    def proxy_model(self) -> QSortFilterProxyModel:
        """The sorting proxy model shown by the view."""
        return self._proxy

    @property
    def table_view(self) -> QTableView:
        """The table view widget."""
        return self._table

    def column_headers(self) -> tuple[str, ...]:
        """Return the table's column headers."""
        return _COLUMNS

    def row_count(self) -> int:
        """Number of rows currently displayed."""
        return self._model.rowCount()

    def row_at(self, row: int) -> ProcessRow:
        """Return the displayed row at ``row``."""
        return self._model.row_at(row)

    def process_count_text(self) -> str:
        """Return the 'Processes: <count>' text."""
        return self._count_label.text()

    def last_updated_text(self) -> str:
        """Return the 'Last updated' text."""
        return self._last_updated_label.text()

    def has_error(self) -> bool:
        """Whether the page is showing a safe error state."""
        return self._error_active

    def error_text(self) -> str:
        """Return the current error banner text (empty when there is no error)."""
        return self._error_label.text()


__all__ = ["ProcessTableModel", "ProcessesPage"]
