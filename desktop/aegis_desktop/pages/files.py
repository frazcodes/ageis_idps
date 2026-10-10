"""File Integrity page: read-only FIM posture and baseline table.

The page is presentation only. It shows the current FIM configuration read-only
and performs a single bounded one-shot collection per ``Refresh`` through
:mod:`aegis_desktop.services.files` (which calls the existing Step 5 collector).

It never scans on startup, never hashes during rendering, never starts the
``FileIntegrityMonitor`` lifecycle and offers no remediation controls. When FIM
is disabled or unconfigured, no filesystem access occurs.
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
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from aegis_desktop.pages.base import BasePage
from aegis_desktop.services.dashboard import format_bytes, format_timestamp
from aegis_desktop.services.files import (
    FILE_ERROR,
    FIM_DISABLED_NOTICE,
    MISSING,
    FileIntegrityConfig,
    FileRow,
    FileSnapshotView,
    collect_file_view,
    file_integrity_config,
)
from aegis_shared.logging import get_logger

logger = get_logger(__name__)

_COLUMNS = (
    "Path",
    "Type",
    "Size",
    "Modified",
    "SHA-256",
    "Hash Status",
    "Identity",
)

_COLUMN_WIDTHS = (380, 90, 100, 160, 190, 130, 380)

_INITIAL_HINT = "Select Refresh to inspect the configured paths. Nothing is scanned automatically."

_NO_DATA_TEXT = "Files: No data"

#: Number of hash characters shown in the cell; the full value is in the tooltip.
_HASH_PREVIEW_LENGTH = 16

#: Shared invalid index; avoids a function call in argument defaults (B008).
_NO_INDEX = QModelIndex()


class FileTableModel(QAbstractTableModel):
    """Qt table model over a tuple of :class:`FileRow`."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._rows: list[FileRow] = []

    def set_rows(self, rows: tuple[FileRow, ...]) -> None:
        """Replace the displayed rows."""
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def rows(self) -> tuple[FileRow, ...]:
        """Return the current rows."""
        return tuple(self._rows)

    def row_at(self, row: int) -> FileRow:
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

            if column == 4 and row.sha256:
                return QColor("#38BDF8")
            if column == 5:
                return QColor("#10B981") if row.hash_status == "hashed" else QColor("#F59E0B")
        if role == Qt.ItemDataRole.TextAlignmentRole:
            if column in (1, 2, 3, 5):
                return int(Qt.AlignmentFlag.AlignCenter)
            return int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        return None

    @staticmethod
    def _display(row: FileRow, column: int) -> str:
        if column == 0:
            return row.path
        if column == 1:
            return row.file_type
        if column == 2:
            return MISSING if row.size_bytes is None else format_bytes(row.size_bytes)
        if column == 3:
            return format_timestamp(row.modified_at) if row.modified_at else MISSING
        if column == 4:
            if not row.sha256:
                return MISSING
            return f"{row.sha256[:_HASH_PREVIEW_LENGTH]}…"
        if column == 5:
            return row.hash_status
        if column == 6:
            return row.identity
        return MISSING

    @staticmethod
    def _tooltip(row: FileRow, column: int) -> str | None:
        if column == 0:
            return row.path
        if column == 4 and row.sha256:
            # Full, unmodified hash is available via tooltip.
            return row.sha256
        return None

    @staticmethod
    def _sort_key(row: FileRow, column: int) -> object:
        if column == 2:
            return row.size_bytes if row.size_bytes is not None else -1
        if column == 3:
            return row.modified_at.timestamp() if row.modified_at else 0.0
        return FileTableModel._display(row, column).lower()


class FilesPage(BasePage):
    """Read-only file-integrity posture and baseline table."""

    PAGE_KEY  = "files"
    ICON       = "▤"
    ICON_COLOR = "#F59E0B"
    TITLE     = "File Integrity"
    SUBTITLE = "Read-only baseline for explicitly configured files and directories."
    EMPTY_STATE = ""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        provider: Callable[[], FileSnapshotView] | None = None,
        config_provider: Callable[[], FileIntegrityConfig] | None = None,
    ) -> None:
        self._provider: Callable[[], FileSnapshotView] = provider or collect_file_view
        self._config_provider: Callable[[], FileIntegrityConfig] = (
            config_provider or file_integrity_config
        )
        self._snapshot: FileSnapshotView | None = None
        self._error_active = False

        super().__init__(parent)
        # Configuration only: no filesystem scan happens here.
        self._config = self._config_provider()
        self._show_initial_state()

    # -- Construction ------------------------------------------------------

    def build_content(self) -> QWidget:
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        layout.addLayout(self._build_toolbar())
        layout.addLayout(self._build_posture())

        self._error_label = QLabel("")
        self._error_label.setObjectName("ErrorBanner")
        self._error_label.setWordWrap(True)
        self._error_label.setVisible(False)
        layout.addWidget(self._error_label)

        self._hint_label = QLabel(_INITIAL_HINT)
        self._hint_label.setObjectName("EmptyState")
        self._hint_label.setWordWrap(True)
        layout.addWidget(self._hint_label)

        self._model = FileTableModel(self)
        self._proxy = QSortFilterProxyModel(self)
        self._proxy.setSourceModel(self._model)
        self._proxy.setSortRole(Qt.ItemDataRole.UserRole)

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

        self._count_label = QLabel(_NO_DATA_TEXT)
        self._count_label.setObjectName("FieldValue")
        self._last_updated_label = QLabel("Last updated: —")
        self._last_updated_label.setObjectName("CardHint")

        toolbar.addWidget(self._refresh_button)
        toolbar.addWidget(self._count_label)
        toolbar.addWidget(self._last_updated_label)
        toolbar.addStretch(1)
        return toolbar

    def _build_posture(self) -> QHBoxLayout:
        posture = QHBoxLayout()
        posture.setSpacing(18)

        self._fim_status_label = QLabel("FIM: —")
        self._fim_status_label.setObjectName("FieldValue")
        self._paths_label = QLabel("Configured paths: —")
        self._paths_label.setObjectName("CardHint")
        self._symlink_label = QLabel("Symlink policy: —")
        self._symlink_label.setObjectName("CardHint")
        self._hash_limit_label = QLabel("Hash limit: —")
        self._hash_limit_label.setObjectName("CardHint")

        posture.addWidget(self._fim_status_label)
        posture.addWidget(self._paths_label)
        posture.addWidget(self._symlink_label)
        posture.addWidget(self._hash_limit_label)
        posture.addStretch(1)
        return posture

    # -- Refresh -----------------------------------------------------------

    def refresh(self) -> FileSnapshotView | None:
        """Perform one bounded read-only collection and update the table.

        Never starts the ``FileIntegrityMonitor`` lifecycle, never scans on
        startup and never modifies a file. When FIM is disabled, no filesystem
        access occurs. On failure a safe error state is shown.
        """
        try:
            view = self._provider()
        except Exception as exc:
            logger.warning("File integrity refresh failed: %s", exc)
            self._show_error(FILE_ERROR)
            return None

        self._apply(view)
        return view

    def _apply(self, view: FileSnapshotView) -> None:
        self._snapshot = view
        self._config = view.config
        self._render_posture(view.config)

        if view.available:
            self._set_error(None)
            self._hint_label.setVisible(False)
            self._model.set_rows(view.rows)
            self._count_label.setText(f"Files: {view.count}")
            self._last_updated_label.setText(f"Last updated: {format_timestamp(view.collected_at)}")
        elif view.error is not None:
            self._model.set_rows(())
            self._count_label.setText(_NO_DATA_TEXT)
            self._last_updated_label.setText("Last updated: —")
            self._hint_label.setVisible(False)
            self._set_error(view.error)
        else:
            # Disabled / unconfigured: no filesystem access occurred.
            self._set_error(None)
            self._model.set_rows(())
            self._count_label.setText(_NO_DATA_TEXT)
            self._last_updated_label.setText("Last updated: —")
            self._hint_label.setText(view.notice or FIM_DISABLED_NOTICE)
            self._hint_label.setVisible(True)

    def _show_initial_state(self) -> None:
        self._snapshot = None
        self._render_posture(self._config)
        self._model.set_rows(())
        self._count_label.setText(_NO_DATA_TEXT)
        self._last_updated_label.setText("Last updated: —")
        self._hint_label.setText(_INITIAL_HINT)
        self._hint_label.setVisible(True)
        self._set_error(None)

    def _show_error(self, message: str) -> None:
        self._snapshot = None
        self._model.set_rows(())
        self._count_label.setText(_NO_DATA_TEXT)
        self._last_updated_label.setText("Last updated: —")
        self._hint_label.setVisible(False)
        self._set_error(message)

    def _render_posture(self, config: FileIntegrityConfig) -> None:
        self._fim_status_label.setText(f"FIM: {'Enabled' if config.enabled else 'Disabled'}")
        self._paths_label.setText(f"Configured paths: {config.configured_paths}")
        self._symlink_label.setText(f"Symlink policy: {config.symlink_policy}")
        self._hash_limit_label.setText(f"Hash limit: {format_bytes(config.max_hash_bytes)}")

    def _set_error(self, message: str | None) -> None:
        self._error_active = message is not None
        self._error_label.setText(message or "")
        self._error_label.setVisible(message is not None)

    # -- Read-only accessors (also used by tests) --------------------------

    @property
    def snapshot(self) -> FileSnapshotView | None:
        """The last applied snapshot, if any."""
        return self._snapshot

    @property
    def source_model(self) -> FileTableModel:
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

    def row_at(self, row: int) -> FileRow:
        """Return the displayed row at ``row``."""
        return self._model.row_at(row)

    def fim_status_text(self) -> str:
        """Return the 'FIM: Enabled/Disabled' text."""
        return self._fim_status_label.text()

    def configured_paths_text(self) -> str:
        """Return the 'Configured paths: <n>' text."""
        return self._paths_label.text()

    def symlink_policy_text(self) -> str:
        """Return the 'Symlink policy: <value>' text."""
        return self._symlink_label.text()

    def hash_limit_text(self) -> str:
        """Return the 'Hash limit: <value>' text."""
        return self._hash_limit_label.text()

    def file_count_text(self) -> str:
        """Return the 'Files: <count>' text."""
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

    def notice_text(self) -> str:
        """Return the current hint/notice text."""
        return self._hint_label.text()


__all__ = ["FileTableModel", "FilesPage"]
