"""Risk page: read-only inspection of explainable risk assessments.

The page is presentation only. It reads assessments from the existing Step 9
:class:`RiskEngine` through :mod:`aegis_desktop.services.risk` and renders them
with a Qt model/view table plus a read-only structured detail panel.

It never starts a producer, a scoring loop, ML, correlation or response, and it
duplicates no scoring logic. No assessments are fabricated to populate the table.
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
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from aegis_desktop.pages.base import BasePage
from aegis_desktop.services.dashboard import format_timestamp
from aegis_desktop.services.processes import MISSING
from aegis_desktop.services.risk import (
    RISK_ERROR,
    RiskRow,
    RiskSnapshotView,
    collect_risk_view,
    describe_assessment,
)
from aegis_desktop.theme import state_color
from aegis_shared.enums import RiskLevel
from aegis_shared.logging import get_logger

logger = get_logger(__name__)

_COLUMNS = (
    "Timestamp",
    "Assessment ID",
    "Event ID",
    "Host ID",
    "Score",
    "Risk Level",
    "Severity",
    "Reasons",
    "Findings",
    "Scoring Version",
)

_COLUMN_WIDTHS = (160, 220, 180, 140, 70, 100, 90, 320, 200, 110)

_INITIAL_HINT = (
    "Select Refresh to inspect risk assessments. No monitor, capture or scoring loop is started."
)

_NO_DATA_TEXT = "Risk: No data"

#: Numeric rank for the existing RiskLevel ordering (sorts most severe last).
_RISK_LEVEL_RANK = {
    RiskLevel.INFORMATIONAL: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}

#: Shared invalid index; avoids a function call in argument defaults (B008).
_NO_INDEX = QModelIndex()


class RiskTableModel(QAbstractTableModel):
    """Qt table model over a tuple of :class:`RiskRow`."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._rows: list[RiskRow] = []

    def set_rows(self, rows: tuple[RiskRow, ...]) -> None:
        """Replace the displayed rows."""
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def rows(self) -> tuple[RiskRow, ...]:
        """Return the current rows."""
        return tuple(self._rows)

    def row_at(self, row: int) -> RiskRow:
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
        if role == Qt.ItemDataRole.ForegroundRole and column in (5, 6):
            return state_color(row.risk_level if column == 5 else row.severity)
        return None

    @staticmethod
    def _display(row: RiskRow, column: int) -> str:
        if column == 0:
            return format_timestamp(row.timestamp)
        if column == 1:
            return row.assessment_id
        if column == 2:
            return row.event_id
        if column == 3:
            return row.host_id or MISSING
        if column == 4:
            return str(row.risk_score)
        if column == 5:
            return row.risk_level
        if column == 6:
            return row.severity
        if column == 7:
            return row.reasons_summary
        if column == 8:
            return ", ".join(row.finding_ids) if row.finding_ids else MISSING
        if column == 9:
            return row.scoring_version
        return MISSING

    @staticmethod
    def _tooltip(row: RiskRow, column: int) -> str | None:
        if column in (1, 7, 8):
            return RiskTableModel._display(row, column)
        return None

    @staticmethod
    def _sort_key(row: RiskRow, column: int) -> object:
        if column == 0:
            return row.timestamp.timestamp()
        if column == 4:
            return row.risk_score
        if column == 5:
            try:
                return _RISK_LEVEL_RANK[RiskLevel(row.risk_level)]
            except ValueError:
                return -1
        return RiskTableModel._display(row, column).lower()


class RiskPage(BasePage):
    """Read-only table + detail view of explainable risk assessments."""

    PAGE_KEY  = "risk"
    ICON       = "▲"
    ICON_COLOR = "#EC4899"
    TITLE     = "Risk"
    SUBTITLE = "Read-only inspection of explainable 0-100 risk assessments."
    EMPTY_STATE = ""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        provider: Callable[[], RiskSnapshotView] | None = None,
    ) -> None:
        self._provider: Callable[[], RiskSnapshotView] = provider or collect_risk_view
        self._snapshot: RiskSnapshotView | None = None
        self._error_active = False

        super().__init__(parent)
        # Deliberately no automatic evaluation: opening the application must not
        # start the risk engine.
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

        self._model = RiskTableModel(self)
        self._proxy = QSortFilterProxyModel(self)
        self._proxy.setSourceModel(self._model)
        self._proxy.setSortRole(Qt.ItemDataRole.UserRole)

        self._table = QTableView()
        self._table.setModel(self._proxy)
        self._table.setSortingEnabled(True)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        self._table.setWordWrap(False)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setStretchLastSection(False)
        for index, width in enumerate(_COLUMN_WIDTHS):
            self._table.setColumnWidth(index, width)
        self._table.sortByColumn(0, Qt.SortOrder.DescendingOrder)

        self._detail = self._build_detail_panel()

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self._table)
        splitter.addWidget(self._detail)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter, 1)

        self._table.selectionModel().selectionChanged.connect(self._on_selection_changed)
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

        self._engine_status_label = QLabel("Risk Engine: Not running")
        self._engine_status_label.setObjectName("FieldValue")
        self._assessments_label = QLabel("Assessments: No data")
        self._assessments_label.setObjectName("CardHint")
        self._scoring_version_label = QLabel("Scoring Version: —")
        self._scoring_version_label.setObjectName("CardHint")

        posture.addWidget(self._engine_status_label)
        posture.addWidget(self._assessments_label)
        posture.addWidget(self._scoring_version_label)
        posture.addStretch(1)
        return posture

    def _build_detail_panel(self) -> QWidget:
        card = QWidget()
        card.setObjectName("Card")
        outer = QVBoxLayout(card)
        outer.setContentsMargins(16, 12, 16, 12)
        outer.setSpacing(8)

        heading = QLabel("SELECTED RISK ASSESSMENT")
        heading.setObjectName("CardTitle")
        outer.addWidget(heading)

        self._detail_hint = QLabel("Select an assessment to inspect its structured details.")
        self._detail_hint.setObjectName("CardHint")
        self._detail_hint.setWordWrap(True)
        outer.addWidget(self._detail_hint)

        self._detail_form = QFormLayout()
        self._detail_form.setHorizontalSpacing(24)
        self._detail_form.setVerticalSpacing(4)
        outer.addLayout(self._detail_form)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(card)
        scroll.setMinimumHeight(160)
        return scroll

    # -- Refresh -----------------------------------------------------------

    def refresh(self) -> RiskSnapshotView | None:
        """Read existing risk assessments from the risk engine.

        Never starts a producer, a scoring loop, ML, correlation or response. On
        failure a safe error state is shown.
        """
        try:
            view = self._provider()
        except Exception as exc:
            logger.warning("Risk refresh failed: %s", exc)
            self._show_error(RISK_ERROR)
            return None

        self._apply(view)
        return view

    def _apply(self, view: RiskSnapshotView) -> None:
        self._snapshot = view
        self._render_posture(view)
        self._clear_detail()

        if view.available:
            self._set_error(None)
            self._hint_label.setVisible(False)
            self._model.set_rows(view.rows)
            self._count_label.setText(f"Risk: {view.count}" if view.count else _NO_DATA_TEXT)
            self._last_updated_label.setText(
                f"Last updated: {format_timestamp(view.collected_at)}"
                if view.collected_at is not None
                else "Last updated: —"
            )
        else:
            self._model.set_rows(())
            self._count_label.setText(_NO_DATA_TEXT)
            self._last_updated_label.setText("Last updated: —")
            self._hint_label.setVisible(False)
            self._set_error(view.error or RISK_ERROR)

    def _show_initial_state(self) -> None:
        self._snapshot = None
        self._render_posture(None)
        self._model.set_rows(())
        self._count_label.setText(_NO_DATA_TEXT)
        self._last_updated_label.setText("Last updated: —")
        self._hint_label.setText(_INITIAL_HINT)
        self._hint_label.setVisible(True)
        self._clear_detail()
        self._set_error(None)

    def _show_error(self, message: str) -> None:
        self._snapshot = None
        self._model.set_rows(())
        self._count_label.setText(_NO_DATA_TEXT)
        self._last_updated_label.setText("Last updated: —")
        self._hint_label.setVisible(False)
        self._clear_detail()
        self._set_error(message)

    def _render_posture(self, view: RiskSnapshotView | None) -> None:
        if view is None:
            self._engine_status_label.setText("Risk Engine: Not running")
            self._assessments_label.setText("Assessments: No data")
            self._scoring_version_label.setText("Scoring Version: —")
            return
        posture = view.posture
        self._engine_status_label.setText(
            "Risk Engine: Running" if posture.running else "Risk Engine: Not running"
        )
        self._assessments_label.setText(
            f"Assessments: {posture.assessments}" if posture.assessments else "Assessments: No data"
        )
        self._scoring_version_label.setText(
            f"Scoring Version: {posture.scoring_version}"
            if posture.scoring_version
            else "Scoring Version: —"
        )

    def _set_error(self, message: str | None) -> None:
        self._error_active = message is not None
        self._error_label.setText(message or "")
        self._error_label.setVisible(message is not None)

    # -- Detail view -------------------------------------------------------

    def _on_selection_changed(self, *_args: object) -> None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            self._clear_detail()
            return
        source_index = self._proxy.mapToSource(rows[0])
        row = self._model.row_at(source_index.row())
        self.show_detail_for(row)

    def show_detail_for(self, row: RiskRow) -> None:
        """Populate the read-only detail panel for ``row``."""
        if self._snapshot is None:
            return
        assessment = self._snapshot.assessment_by_id(row.assessment_id)
        if assessment is None:
            self._clear_detail()
            return

        self._clear_detail()
        self._detail_hint.setVisible(False)
        for key, value in describe_assessment(assessment).items():
            key_label = QLabel(key)
            key_label.setObjectName("FieldKey")
            value_label = QLabel(value)
            value_label.setObjectName("FieldValue")
            value_label.setWordWrap(True)
            value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self._detail_form.addRow(key_label, value_label)

    def _clear_detail(self) -> None:
        while self._detail_form.rowCount():
            self._detail_form.removeRow(0)
        self._detail_hint.setText("Select an assessment to inspect its structured details.")
        self._detail_hint.setVisible(True)

    # -- Read-only accessors (also used by tests) --------------------------

    @property
    def snapshot(self) -> RiskSnapshotView | None:
        """The last applied snapshot, if any."""
        return self._snapshot

    @property
    def source_model(self) -> RiskTableModel:
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

    def row_at(self, row: int) -> RiskRow:
        """Return the displayed row at ``row``."""
        return self._model.row_at(row)

    def risk_count_text(self) -> str:
        """Return the 'Risk: <count>' text."""
        return self._count_label.text()

    def engine_status_text(self) -> str:
        """Return the 'Risk Engine: Running/Not running' text."""
        return self._engine_status_label.text()

    def assessments_text(self) -> str:
        """Return the 'Assessments: <n>' text."""
        return self._assessments_label.text()

    def scoring_version_text(self) -> str:
        """Return the 'Scoring Version: <v>' text."""
        return self._scoring_version_label.text()

    def last_updated_text(self) -> str:
        """Return the 'Last updated' text."""
        return self._last_updated_label.text()

    def detail_keys(self) -> tuple[str, ...]:
        """Return the field keys currently shown in the detail panel."""
        keys: list[str] = []
        for row in range(self._detail_form.rowCount()):
            item = self._detail_form.itemAt(row, QFormLayout.ItemRole.LabelRole)
            widget = item.widget() if item is not None else None
            if isinstance(widget, QLabel):
                keys.append(widget.text())
        return tuple(keys)

    def detail_values(self) -> tuple[str, ...]:
        """Return the field values currently shown in the detail panel."""
        values: list[str] = []
        for row in range(self._detail_form.rowCount()):
            item = self._detail_form.itemAt(row, QFormLayout.ItemRole.FieldRole)
            widget = item.widget() if item is not None else None
            if isinstance(widget, QLabel):
                values.append(widget.text())
        return tuple(values)

    def has_error(self) -> bool:
        """Whether the page is showing a safe error state."""
        return self._error_active

    def error_text(self) -> str:
        """Return the current error banner text (empty when there is no error)."""
        return self._error_label.text()


__all__ = ["RiskPage", "RiskTableModel"]
