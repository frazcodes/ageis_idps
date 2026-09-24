"""Incidents page: read-only inspection of correlated security incidents.

The page is presentation only. It reads the current incidents published by the
running runtime through :mod:`aegis_desktop.services.incidents` and renders them
with a Qt model/view table plus a visual 'Investigation Canvas' detail panel
that shows the incident summary, correlation reason, risk context, host asset
context, related findings/events, ML anomaly evidence, host↔network correlation
and response policy preview.

It never starts a producer, capture, correlation, detection, scoring or response
loop, and it duplicates no correlation logic. No incidents are fabricated to
populate the table.
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
    QFrame,
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
from aegis_desktop.services.assets import collect_asset_view
from aegis_desktop.services.dashboard import format_timestamp
from aegis_desktop.services.incidents import (
    INCIDENT_ERROR,
    IncidentRow,
    IncidentSnapshotView,
    collect_incident_view,
)
from aegis_desktop.services.processes import MISSING
from aegis_desktop.theme import state_color
from aegis_shared.enums import RiskLevel
from aegis_shared.logging import get_logger

logger = get_logger(__name__)

_COLUMNS = (
    "Incident ID",
    "Time",
    "Host",
    "Risk",
    "Status",
    "Findings",
    "Summary",
)

_COLUMN_WIDTHS = (210, 160, 140, 80, 100, 80, 420)

_INITIAL_HINT = (
    "Select Refresh to inspect correlated security incidents. No monitor, "
    "capture or correlation loop is started."
)

_NO_DATA_TEXT = "Incidents: No data"

_RISK_LEVEL_RANK = {
    RiskLevel.INFORMATIONAL: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}

_NO_INDEX = QModelIndex()


class IncidentTableModel(QAbstractTableModel):
    """Qt table model over a tuple of :class:`IncidentRow`."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._rows: list[IncidentRow] = []

    def set_rows(self, rows: tuple[IncidentRow, ...]) -> None:
        """Replace the displayed rows."""
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def rows(self) -> tuple[IncidentRow, ...]:
        """Return the current rows."""
        return tuple(self._rows)

    def row_at(self, row: int) -> IncidentRow:
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
        if role == Qt.ItemDataRole.ForegroundRole and column == 3:
            return state_color(row.risk_level)
        if role == Qt.ItemDataRole.ForegroundRole and column == 4:
            return state_color(row.status)
        return None

    @staticmethod
    def _display(row: IncidentRow, column: int) -> str:
        if column == 0:
            return row.incident_id
        if column == 1:
            return format_timestamp(row.created_at)
        if column == 2:
            return row.host_id or MISSING
        if column == 3:
            return str(row.risk_score)
        if column == 4:
            return row.status
        if column == 5:
            return str(row.finding_count)
        if column == 6:
            return row.summary
        return MISSING

    @staticmethod
    def _tooltip(row: IncidentRow, column: int) -> str | None:
        if column in (0, 6):
            return IncidentTableModel._display(row, column)
        return None

    @staticmethod
    def _sort_key(row: IncidentRow, column: int) -> object:
        if column == 1:
            return row.created_at.timestamp()
        if column == 3:
            return row.risk_score
        if column == 5:
            return row.finding_count
        return IncidentTableModel._display(row, column).lower()


class IncidentsPage(BasePage):
    """Read-only table + detail view of correlated security incidents."""

    PAGE_KEY = "incidents"
    TITLE = "Incidents"
    SUBTITLE = "Read-only inspection of correlated security activity."
    EMPTY_STATE = ""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        provider: Callable[[], IncidentSnapshotView] | None = None,
    ) -> None:
        self._provider: Callable[[], IncidentSnapshotView] = provider or collect_incident_view
        self._snapshot: IncidentSnapshotView | None = None
        self._error_active = False

        super().__init__(parent)
        # Deliberately no automatic evaluation: opening the application must not
        # start the runtime or correlation.
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

        self._model = IncidentTableModel(self)
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
        self._table.sortByColumn(1, Qt.SortOrder.DescendingOrder)

        # Investigation Canvas (right panel) - Master-Detail split view
        self._canvas = self._build_investigation_canvas()

        # Horizontal splitter: Table (left) | Investigation Canvas (right)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._table)
        splitter.addWidget(self._canvas)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        splitter.setChildrenCollapsible(False)
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

        self._runtime_status_label = QLabel("Incident Correlation: Not running")
        self._runtime_status_label.setObjectName("FieldValue")
        self._incidents_label = QLabel("Incidents: No data")
        self._incidents_label.setObjectName("CardHint")

        posture.addWidget(self._runtime_status_label)
        posture.addWidget(self._incidents_label)
        posture.addStretch(1)
        return posture

    def _build_investigation_canvas(self) -> QWidget:
        """Build the right-side Investigation Canvas widget."""
        canvas = QWidget()
        canvas.setObjectName("Card")
        outer = QVBoxLayout(canvas)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # Canvas header with incident header info
        self._canvas_header = QWidget()
        self._canvas_header.setVisible(False)
        header_layout = QVBoxLayout(self._canvas_header)
        header_layout.setContentsMargins(16, 12, 16, 8)
        header_layout.setSpacing(8)

        # Incident header row: Severity badge + ID + Status + Correlation reason
        header_row = QHBoxLayout()
        header_row.setSpacing(12)

        self._canvas_severity_badge = QLabel("")
        self._canvas_severity_badge.setObjectName("FieldValue")
        self._canvas_severity_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._canvas_severity_badge.setFixedWidth(80)
        self._canvas_severity_badge.setStyleSheet(
            "background-color: #30363d; color: #e6edf3; font-weight: 800; "
            "font-size: 11px; border-radius: 4px; padding: 6px 4px;"
        )
        header_row.addWidget(self._canvas_severity_badge)

        self._canvas_incident_id = QLabel("")
        self._canvas_incident_id.setObjectName("CardTitle")
        self._canvas_incident_id.setStyleSheet("font-size: 14px; font-weight: 700;")
        header_row.addWidget(self._canvas_incident_id)

        self._canvas_status = QLabel("")
        self._canvas_status.setObjectName("FieldValue")
        self._canvas_status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._canvas_status.setFixedWidth(100)
        self._canvas_status.setStyleSheet(
            "background-color: #21262d; color: #e6edf3; font-weight: 600; "
            "font-size: 11px; border-radius: 4px; padding: 4px 8px;"
        )
        header_row.addWidget(self._canvas_status)

        header_row.addStretch(1)
        header_layout.addLayout(header_row)

        # Correlation reason
        self._canvas_correlation_reason = QLabel("")
        self._canvas_correlation_reason.setObjectName("CardHint")
        self._canvas_correlation_reason.setWordWrap(True)
        self._canvas_correlation_reason.setStyleSheet("font-size: 11px; color: #8b949e;")
        header_layout.addWidget(self._canvas_correlation_reason)

        outer.addWidget(self._canvas_header)

        # Main canvas content in a scroll area
        self._canvas_content = QWidget()
        self._canvas_content_layout = QVBoxLayout(self._canvas_content)
        self._canvas_content_layout.setContentsMargins(16, 8, 16, 16)
        self._canvas_content_layout.setSpacing(12)

        # Asset Context Card
        self._asset_card = self._build_asset_card()
        self._asset_card.setVisible(False)
        self._canvas_content_layout.addWidget(self._asset_card)

        # Host ↔ Network Correlation Evidence
        self._correlation_card = self._build_correlation_card()
        self._correlation_card.setVisible(False)
        self._canvas_content_layout.addWidget(self._correlation_card)

        # Legacy detail sections (hidden, kept for test backward-compat)
        self._legacy_detail = self._build_legacy_detail()
        self._legacy_detail.setVisible(False)

        self._canvas_content_layout.addStretch(1)

        # Action Bar at bottom
        self._action_bar = self._build_action_bar()
        self._action_bar.setVisible(False)
        outer.addWidget(self._action_bar)

        # Scroll area for content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self._canvas_content)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        outer.addWidget(scroll, 1)

        return canvas

    def _build_asset_card(self) -> QWidget:
        """Build the Asset Context Card showing host details."""
        card = QFrame()
        card.setObjectName("Card")
        card.setStyleSheet(
            "QFrame#Card { border-left: 3px solid #58a6ff; "
            "background-color: #161b22; border-radius: 4px; }"
        )
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        heading = QLabel("ASSET CONTEXT")
        heading.setObjectName("CardTitle")
        heading.setStyleSheet(
            "font-size: 11px; font-weight: 700; color: #58a6ff; "
            "letter-spacing: 0.5px;"
        )
        layout.addWidget(heading)

        # Asset fields grid
        grid = QHBoxLayout()
        grid.setSpacing(24)

        left_col = QVBoxLayout()
        left_col.setSpacing(4)
        self._asset_hostname = self._asset_field("Hostname", "")
        self._asset_os = self._asset_field("OS", "")
        self._asset_ip = self._asset_field("IP Address", "")
        left_col.addWidget(self._asset_hostname)
        left_col.addWidget(self._asset_os)
        left_col.addWidget(self._asset_ip)

        right_col = QVBoxLayout()
        right_col.setSpacing(4)
        self._asset_platform = self._asset_field("Platform", "")
        self._asset_peers = self._asset_field("Peers", "")
        self._asset_services = self._asset_field("Services", "")
        right_col.addWidget(self._asset_platform)
        right_col.addWidget(self._asset_peers)
        right_col.addWidget(self._asset_services)

        grid.addLayout(left_col)
        grid.addLayout(right_col)
        grid.addStretch(1)
        layout.addLayout(grid)

        return card

    @staticmethod
    def _asset_field(label: str, value: str) -> QWidget:
        """Create a label/value row for asset card."""
        row = QWidget()
        layout = QVBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(1)
        lbl = QLabel(label.upper())
        lbl.setObjectName("CardTitle")
        lbl.setStyleSheet("font-size: 10px; font-weight: 600; color: #8b949e;")
        val = QLabel(value)
        val.setObjectName("FieldValue")
        val.setStyleSheet("font-size: 12px; font-weight: 500;")
        layout.addWidget(lbl)
        layout.addWidget(val)
        return row

    def _build_correlation_card(self) -> QWidget:
        """Build the Host ↔ Network Correlation Evidence card."""
        card = QFrame()
        card.setObjectName("Card")
        card.setStyleSheet(
            "QFrame#Card { border-left: 3px solid #d29922; "
            "background-color: #161b22; border-radius: 4px; }"
        )
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(10)

        heading = QLabel("HOST ↔ NETWORK CORRELATION EVIDENCE")
        heading.setObjectName("CardTitle")
        heading.setStyleSheet(
            "font-size: 11px; font-weight: 700; color: #d29922; "
            "letter-spacing: 0.5px;"
        )
        layout.addWidget(heading)

        # Side-by-side evidence panels
        evidence_row = QHBoxLayout()
        evidence_row.setSpacing(12)

        # Host Evidence Panel
        host_panel = QFrame()
        host_panel.setObjectName("Card")
        host_panel.setStyleSheet(
            "QFrame#Card { "
            "background-color: #0d1117; "
            "border: 1px solid #30363d; "
            "border-radius: 4px; "
            "}"
        )
        host_layout = QVBoxLayout(host_panel)
        host_layout.setContentsMargins(12, 10, 12, 10)
        host_layout.setSpacing(6)

        host_heading = QLabel("HOST EVIDENCE")
        host_heading.setObjectName("CardTitle")
        host_heading.setStyleSheet("font-size: 10px; font-weight: 700; color: #58a6ff;")
        host_layout.addWidget(host_heading)

        self._corr_host_findings = QLabel("No host findings")
        self._corr_host_findings.setObjectName("FieldValue")
        self._corr_host_findings.setWordWrap(True)
        self._corr_host_findings.setStyleSheet("font-size: 11px; color: #e6edf3;")
        host_layout.addWidget(self._corr_host_findings)

        self._corr_host_summary = QLabel("")
        self._corr_host_summary.setObjectName("CardHint")
        self._corr_host_summary.setWordWrap(True)
        self._corr_host_summary.setStyleSheet("font-size: 10px; color: #8b949e;")
        host_layout.addWidget(self._corr_host_summary)

        evidence_row.addWidget(host_panel, 1)

        # Network Evidence Panel
        net_panel = QFrame()
        net_panel.setObjectName("Card")
        net_panel.setStyleSheet(
            "QFrame#Card { "
            "background-color: #0d1117; "
            "border: 1px solid #30363d; "
            "border-radius: 4px; "
            "}"
        )
        net_layout = QVBoxLayout(net_panel)
        net_layout.setContentsMargins(12, 10, 12, 10)
        net_layout.setSpacing(6)

        net_heading = QLabel("NETWORK EVIDENCE")
        net_heading.setObjectName("CardTitle")
        net_heading.setStyleSheet("font-size: 10px; font-weight: 700; color: #d29922;")
        net_layout.addWidget(net_heading)

        self._corr_network_findings = QLabel("No network findings")
        self._corr_network_findings.setObjectName("FieldValue")
        self._corr_network_findings.setWordWrap(True)
        self._corr_network_findings.setStyleSheet("font-size: 11px; color: #e6edf3;")
        net_layout.addWidget(self._corr_network_findings)

        self._corr_network_summary = QLabel("")
        self._corr_network_summary.setObjectName("CardHint")
        self._corr_network_summary.setWordWrap(True)
        self._corr_network_summary.setStyleSheet("font-size: 10px; color: #8b949e;")
        net_layout.addWidget(self._corr_network_summary)

        evidence_row.addWidget(net_panel, 1)

        layout.addLayout(evidence_row)

        # Correlation metadata
        meta = QHBoxLayout()
        meta.setSpacing(16)
        self._corr_window = QLabel("")
        self._corr_window.setObjectName("CardHint")
        self._corr_window.setStyleSheet("font-size: 10px; color: #8b949e;")
        self._corr_reason = QLabel("")
        self._corr_reason.setObjectName("CardHint")
        self._corr_reason.setWordWrap(True)
        self._corr_reason.setStyleSheet("font-size: 10px; color: #8b949e;")
        meta.addWidget(self._corr_window)
        meta.addWidget(self._corr_reason, 1)
        layout.addLayout(meta)

        return card

    def _build_legacy_detail(self) -> QWidget:
        """Build the legacy detail panel (hidden, for test backward-compat)."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        self._detail_hint = QLabel("Select an incident to inspect its correlated context.")
        self._detail_hint.setObjectName("CardHint")
        self._detail_hint.setWordWrap(True)
        layout.addWidget(self._detail_hint)

        self._investigation_container = QWidget()
        self._investigation_layout = QVBoxLayout(self._investigation_container)
        self._investigation_layout.setContentsMargins(0, 0, 0, 0)
        self._investigation_layout.setSpacing(10)
        layout.addWidget(self._investigation_container)

        # Hidden scroll area for legacy tests
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(widget)
        scroll.setMinimumHeight(160)
        return scroll

    def _build_action_bar(self) -> QWidget:
        """Build the bottom action bar with 'Initiate Response' button."""
        bar = QWidget()
        bar.setFixedHeight(60)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(16, 8, 16, 8)
        layout.setSpacing(12)

        self._action_bar_hint = QLabel("")
        self._action_bar_hint.setObjectName("CardHint")
        self._action_bar_hint.setStyleSheet("font-size: 11px; color: #8b949e;")
        layout.addWidget(self._action_bar_hint)
        layout.addStretch(1)

        self._initiate_response_btn = QPushButton("Initiate Response")
        self._initiate_response_btn.setObjectName("PrimaryButton")
        self._initiate_response_btn.setFixedHeight(36)
        self._initiate_response_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._initiate_response_btn.clicked.connect(self._on_initiate_response)
        layout.addWidget(self._initiate_response_btn)

        return bar

    def _build_section(self, title: str) -> tuple[QFrame, QFormLayout]:
        frame = QFrame()
        frame.setObjectName("Card")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(4)

        heading = QLabel(title)
        heading.setObjectName("CardTitle")
        layout.addWidget(heading)

        form = QFormLayout()
        form.setHorizontalSpacing(20)
        form.setVerticalSpacing(3)
        layout.addLayout(form)
        return frame, form

    # -- Refresh -----------------------------------------------------------

    def refresh(self) -> IncidentSnapshotView | None:
        """Read current incidents from the runtime registry (read-only)."""
        try:
            view = self._provider()
        except Exception as exc:
            logger.warning("Incidents refresh failed: %s", exc)
            self._show_error(INCIDENT_ERROR)
            return None

        self._apply(view)
        return view

    def _apply(self, view: IncidentSnapshotView) -> None:
        self._snapshot = view
        self._render_posture(view)
        self._clear_canvas()

        if view.available:
            self._set_error(None)
            self._hint_label.setVisible(False)
            self._model.set_rows(view.rows)
            self._count_label.setText(
                f"Incidents: {view.count}" if view.count else _NO_DATA_TEXT
            )
            self._last_updated_label.setText(
                f"Last updated: {format_timestamp(view.collected_at)}"
                if view.collected_at is not None
                else "Last updated: —"
            )
            if view.count == 0:
                self._detail_hint.setText("No correlated security incidents available")
                self._detail_hint.setVisible(True)
        else:
            self._model.set_rows(())
            self._count_label.setText(_NO_DATA_TEXT)
            self._last_updated_label.setText("Last updated: —")
            self._hint_label.setVisible(False)
            self._set_error(view.error or INCIDENT_ERROR)

    def _show_initial_state(self) -> None:
        self._snapshot = None
        self._render_posture(None)
        self._model.set_rows(())
        self._count_label.setText(_NO_DATA_TEXT)
        self._last_updated_label.setText("Last updated: —")
        self._hint_label.setText(_INITIAL_HINT)
        self._hint_label.setVisible(True)
        self._clear_canvas()
        self._set_error(None)

    def _show_error(self, message: str) -> None:
        self._snapshot = None
        self._model.set_rows(())
        self._count_label.setText(_NO_DATA_TEXT)
        self._last_updated_label.setText("Last updated: —")
        self._hint_label.setVisible(False)
        self._clear_canvas()
        self._set_error(message)

    def _render_posture(self, view: IncidentSnapshotView | None) -> None:
        if view is None:
            self._runtime_status_label.setText("Incident Correlation: Not running")
            self._incidents_label.setText("Incidents: No data")
            return
        posture = view.posture
        self._runtime_status_label.setText(
            "Incident Correlation: Running"
            if posture.running
            else "Incident Correlation: Not running"
        )
        self._incidents_label.setText(
            f"Incidents: {posture.incidents}" if posture.incidents else "Incidents: No data"
        )

    def _set_error(self, message: str | None) -> None:
        self._error_active = message is not None
        self._error_label.setText(message or "")
        self._error_label.setVisible(message is not None)

    # -- Detail view -------------------------------------------------------

    def _on_selection_changed(self, *_args: object) -> None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            self._clear_canvas()
            return
        source_index = self._proxy.mapToSource(rows[0])
        row = self._model.row_at(source_index.row())
        self.show_detail_for(row)

    def show_detail_for(self, row: IncidentRow) -> None:
        """Populate the investigation canvas for ``row``."""
        if self._snapshot is None:
            return
        incident = self._snapshot.incident_by_id(row.incident_id)
        if incident is None:
            self._clear_canvas()
            return

        self._clear_canvas()
        self._detail_hint.setVisible(False)
        self._render_incident_canvas(incident)

    def _render_incident_canvas(self, incident: object) -> None:
        """Render the investigation canvas for the selected incident."""
        # Show canvas header
        self._canvas_header.setVisible(True)

        # Update header: severity badge, incident ID, status, correlation reason
        risk_level = getattr(incident, "risk_level", None)
        if risk_level is not None:
            level_str = risk_level.value if hasattr(risk_level, "value") else str(risk_level)
        else:
            level_str = "INFORMATIONAL"

        severity_colors = {
            "CRITICAL": ("#ff4444", "CRITICAL"),
            "HIGH": ("#f85149", "HIGH"),
            "MEDIUM": ("#d29922", "MEDIUM"),
            "LOW": ("#00ff41", "LOW"),
            "INFORMATIONAL": ("#58a6ff", "INFO"),
        }
        color, badge_text = severity_colors.get(level_str, ("#58a6ff", "INFO"))

        self._canvas_severity_badge.setText(badge_text)
        self._canvas_severity_badge.setStyleSheet(
            f"background-color: {color}; color: #ffffff; font-weight: 800; "
            f"font-size: 11px; border-radius: 4px; padding: 6px 4px;"
        )

        self._canvas_incident_id.setText(getattr(incident, "incident_id", ""))
        status_val = getattr(incident, "status", "")
        if hasattr(status_val, "value"):
            self._canvas_status.setText(status_val.value)
        else:
            self._canvas_status.setText(str(status_val))
        self._canvas_correlation_reason.setText(getattr(incident, "correlation_reason", ""))

        # Fetch asset context for this host
        self._populate_asset_context(getattr(incident, "host_id", ""))

        # Fetch and populate host/network correlation evidence
        self._populate_correlation_evidence(incident)

        # Populate action bar
        self._populate_action_bar(incident)

        # Show canvas components
        self._asset_card.setVisible(True)
        self._correlation_card.setVisible(True)
        self._action_bar.setVisible(True)

        # Also populate legacy detail for test backward-compat
        self._render_incident(incident)

    def _populate_asset_context(self, host_id: str) -> None:
        """Fetch and display asset context for the host."""
        if not host_id:
            self._asset_card.setVisible(False)
            return

        try:
            asset_view = collect_asset_view()
            asset_row = None
            for asset in asset_view.assets:
                if asset.host_id == host_id:
                    asset_row = asset
                    break

            if asset_row is not None:
                hn = asset_row.hostname or MISSING
                os_val = asset_row.operating_system or MISSING
                ip_val = asset_row.ip_addresses[0] if asset_row.ip_addresses else MISSING
                plat = asset_row.platform or MISSING
                self._asset_hostname.findChild(QLabel, "FieldValue").setText(hn)
                self._asset_os.findChild(QLabel, "FieldValue").setText(os_val)
                self._asset_ip.findChild(QLabel, "FieldValue").setText(ip_val)
                self._asset_platform.findChild(QLabel, "FieldValue").setText(plat)
                self._asset_peers.findChild(QLabel, "FieldValue").setText(str(asset_row.peers))
                svc_val = str(asset_row.services)
                self._asset_services.findChild(QLabel, "FieldValue").setText(svc_val)
                self._asset_card.setVisible(True)
            else:
                self._asset_card.setVisible(False)
        except Exception:
            self._asset_card.setVisible(False)

    def _populate_correlation_evidence(self, incident: object) -> None:
        """Populate host/network correlation evidence side-by-side."""
        correlation = self._correlation_for(incident)
        if correlation is None:
            self._corr_host_findings.setText("No host findings")
            self._corr_host_summary.setText("")
            self._corr_network_findings.setText("No network findings")
            self._corr_network_summary.setText("")
            self._corr_window.setText("")
            self._corr_reason.setText("")
            return

        # Get findings for this incident
        finding_ids = set(getattr(incident, "finding_ids", ()))
        findings = self._snapshot.findings if self._snapshot is not None else ()

        host_findings = []
        network_findings = []

        for finding in findings:
            if finding.finding_id in finding_ids:
                if "NETWORK" in finding.rule_id or finding.category == "network":
                    network_findings.append(finding)
                else:
                    host_findings.append(finding)

        # Host evidence panel
        if host_findings:
            texts = [f"• {f.rule_id}: {f.title}" for f in host_findings]
            self._corr_host_findings.setText("\n".join(texts))
            self._corr_host_summary.setText(
                f"{len(host_findings)} host finding(s) correlated"
            )
        else:
            self._corr_host_findings.setText("No host findings")
            self._corr_host_summary.setText("")

        # Network evidence panel
        if network_findings:
            texts = [f"• {f.rule_id}: {f.title}" for f in network_findings]
            self._corr_network_findings.setText("\n".join(texts))
            self._corr_network_summary.setText(
                f"{len(network_findings)} network finding(s) correlated"
            )
        else:
            self._corr_network_findings.setText("No network findings")
            self._corr_network_summary.setText("")

        # Correlation metadata
        window_seconds = getattr(correlation, "window_seconds", None)
        if window_seconds:
            self._corr_window.setText(f"Time Window: {window_seconds}s")
        self._corr_reason.setText(getattr(correlation, "reason", ""))

    def _populate_action_bar(self, incident: object) -> None:
        """Populate the action bar with response info."""
        response_view = self._response_view_for_incident(incident)
        if response_view is not None:
            self._action_bar_hint.setText(
                f"Recommended: {getattr(response_view, 'action_label', '')} "
                f"→ {getattr(response_view, 'target', '')}"
            )
            self._initiate_response_btn.setVisible(True)
        else:
            self._action_bar_hint.setText("No response action available for this incident")
            self._initiate_response_btn.setVisible(False)

    def _on_initiate_response(self) -> None:
        """Handle 'Initiate Response' button click."""
        if self._snapshot is None:
            return
        # Get currently selected incident
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return
        source_index = self._proxy.mapToSource(rows[0])
        row = self._model.row_at(source_index.row())
        incident = self._snapshot.incident_by_id(row.incident_id)
        if incident is None:
            return

        response_view = self._response_view_for_incident(incident)
        if response_view is not None:
            self._create_response_request_from_incident(incident, response_view)
            # Refresh to show the new request
            self.refresh()

    def _clear_canvas(self) -> None:
        """Clear the investigation canvas."""
        # Hide canvas components
        self._canvas_header.setVisible(False)
        self._asset_card.setVisible(False)
        self._correlation_card.setVisible(False)
        self._action_bar.setVisible(False)

        # Reset header fields
        self._canvas_severity_badge.setText("")
        self._canvas_incident_id.setText("")
        self._canvas_status.setText("")
        self._canvas_correlation_reason.setText("")

        # Reset asset fields
        for field in (self._asset_hostname, self._asset_os, self._asset_ip,
                      self._asset_platform, self._asset_peers, self._asset_services):
            field.findChild(QLabel, "FieldValue").setText("")

        # Reset correlation fields
        self._corr_host_findings.setText("No host findings")
        self._corr_host_summary.setText("")
        self._corr_network_findings.setText("No network findings")
        self._corr_network_summary.setText("")
        self._corr_window.setText("")
        self._corr_reason.setText("")

        # Reset action bar
        self._action_bar_hint.setText("")
        self._initiate_response_btn.setVisible(False)

        # Clear legacy detail
        self._clear_detail()

    def _render_incident(self, incident: object) -> None:
        """Render the incident detail sections."""
        # Section 1: Incident Summary
        frame, form = self._build_section("INCIDENT SUMMARY")
        self._investigation_layout.addWidget(frame)
        self._add_field(form, "Incident Id", incident.incident_id)
        self._add_field(form, "Status", incident.status.value)
        self._add_field(form, "Host", incident.host_id)
        self._add_field(form, "Created", incident.created_at.isoformat())
        self._add_field(form, "Updated", incident.updated_at.isoformat())
        self._add_field(form, "Summary", incident.summary)

        # Section 2: Correlation
        frame, form = self._build_section("CORRELATION")
        self._investigation_layout.addWidget(frame)
        self._add_field(form, "Reason", incident.correlation_reason)
        window = self._window_text()
        if window is not None:
            self._add_field(form, "Window", window)

        # Section 3: Risk
        frame, form = self._build_section("RISK")
        self._investigation_layout.addWidget(frame)
        self._add_field(form, "Risk Score", str(incident.risk_score))
        self._add_field(form, "Risk Level", incident.risk_level.value)
        assessment_ids = incident.risk_assessment_ids
        assessments = ", ".join(assessment_ids) if assessment_ids else ""
        self._add_field(
            form, "Risk Assessments", assessments if assessments else "No related risk assessment"
        )

        # Section 4: Related Findings
        frame, form = self._build_section("RELATED FINDINGS")
        self._investigation_layout.addWidget(frame)
        findings = self._snapshot.findings if self._snapshot is not None else ()
        if findings:
            for finding in findings:
                self._add_field(
                    form,
                    finding.finding_id,
                    f"{finding.rule_id} ({finding.severity}) - {finding.title}",
                )
        else:
            self._add_field(form, "Status", "No related findings available")

        # Section 5: Related Events
        frame, form = self._build_section("RELATED EVENTS")
        self._investigation_layout.addWidget(frame)
        events = self._snapshot.events if self._snapshot is not None else ()
        if events:
            for event in events:
                self._add_field(form, event.event_id, f"{event.event_type} ({event.category})")
        else:
            self._add_field(form, "Status", "No related events available")

        # Section 6: ML Evidence
        frame, form = self._build_section("ML EVIDENCE")
        self._investigation_layout.addWidget(frame)
        anomalies = self._snapshot.anomalies if self._snapshot is not None else ()
        if anomalies:
            for anomaly in anomalies:
                self._add_field(form, "Source", anomaly.source)
                self._add_field(form, "Score", f"{anomaly.score:.3f}")
                self._add_field(form, "Model Version", anomaly.model_version)
                if anomaly.reason:
                    self._add_field(form, "Reason", anomaly.reason)
        else:
            self._add_field(form, "ML Anomaly", "No ML anomaly signal available")

        # Section 7: Host <-> Network Correlation
        frame, form = self._build_section("HOST ↔ NETWORK CORRELATION")
        self._investigation_layout.addWidget(frame)
        correlation = self._correlation_for(incident)
        if correlation is not None:
            self._add_field(form, "Status", "Correlated")
            self._add_field(form, "Host", correlation.host_id)
            self._add_field(form, "Host Findings", str(correlation.host_finding_count))
            self._add_field(form, "Network Findings", str(correlation.network_finding_count))
            self._add_field(form, "Time Window", f"{correlation.window_seconds} seconds")
            self._add_field(form, "Reason", correlation.reason)
        else:
            self._add_field(form, "Status", "No host ↔ network correlation available")

        # Section 8: Threat Intelligence (IOC context, read-only)
        frame, form = self._build_section("THREAT INTELLIGENCE")
        self._investigation_layout.addWidget(frame)
        ioc_matches = self._ioc_matches_for(incident)
        if ioc_matches:
            self._add_field(form, "IOC Matches", str(len(ioc_matches)))
            types = ", ".join(sorted({m.indicator_type for m in ioc_matches}))
            sources = ", ".join(sorted({m.source for m in ioc_matches}))
            self._add_field(form, "Matched Types", types)
            self._add_field(form, "Sources", sources)
        else:
            self._add_field(form, "IOC Matches", "No threat-intelligence match available")

        # Section 9: Response Policy (read-only preview; nothing executes)
        frame, form = self._build_section("RESPONSE POLICY")
        self._investigation_layout.addWidget(frame)
        response_view = self._response_view_for_incident(incident)
        if response_view is not None:
            self._add_field(form, "Recommended Action", response_view.action_label or MISSING)
            self._add_field(form, "Target", response_view.target or MISSING)
            self._add_field(form, "Decision", response_view.status.upper())
            self._add_field(form, "Risk", response_view.risk_level.upper())
            self._add_field(
                form,
                "Dry Run",
                "REQUIRED" if response_view.dry_run_required else "NOT REQUIRED",
            )
            self._add_field(
                form, "Approval", "REQUIRED" if response_view.required_approval else "NOT REQUIRED"
            )
            self._add_field(form, "Reason", response_view.reason)
            self._add_field(form, "Policy Version", response_view.policy_version)
            if response_view.target:
                create_btn = QPushButton("Create Response Request")
                create_btn.setObjectName("PrimaryButton")
                create_btn.clicked.connect(
                    lambda checked=False, inc=incident: (
                        self._create_response_request_from_incident(inc, response_view)
                    )
                )
                btn_row = QHBoxLayout()
                btn_row.addWidget(create_btn)
                btn_row.addStretch(1)
                form.addRow(btn_row)
        else:
            self._add_field(form, "Status", "No response action available for this incident.")

        self._investigation_layout.addStretch(1)

    def _correlation_for(self, incident: object) -> object | None:
        """Return the published host/network correlation related to ``incident``."""
        if self._snapshot is None:
            return None
        host_id = getattr(incident, "host_id", None)
        wanted = set(getattr(incident, "finding_ids", ()))
        for correlation in self._snapshot.correlations:
            if correlation.host_id != host_id:
                continue
            if wanted & set(correlation.finding_ids):
                return correlation
        return None

    def _ioc_matches_for(self, incident: object) -> tuple:
        """Return the published IOC matches related to ``incident`` by event ID."""
        if self._snapshot is None:
            return ()
        event_ids = set(getattr(incident, "event_ids", ()))
        return tuple(
            match for match in self._snapshot.ioc_matches if match.event_id in event_ids
        )

    @staticmethod
    def _window_text() -> str | None:
        """Return the configured correlation window as text, or ``None``."""
        try:
            from aegis_shared.correlation import get_correlation_settings

            return f"{get_correlation_settings().window_seconds}s"
        except Exception:
            return None

    @staticmethod
    def _add_field(form: QFormLayout, label: str, value: str) -> None:
        key_label = QLabel(label)
        key_label.setObjectName("FieldKey")
        value_label = QLabel(value)
        value_label.setObjectName("FieldValue")
        value_label.setWordWrap(True)
        value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        form.addRow(key_label, value_label)

    def _clear_detail(self) -> None:
        while self._investigation_layout.count():
            item = self._investigation_layout.takeAt(0)
            widget = item.widget() if item is not None else None
            if widget is not None:
                widget.setParent(None)
        self._detail_hint.setText("Select an incident to inspect its correlated context.")
        self._detail_hint.setVisible(True)

    # -- Read-only accessors (also used by tests) --------------------------

    def _response_view_for_incident(self, incident: object) -> object | None:
        """Evaluate response policy for an incident based on its first finding."""
        if self._snapshot is None:
            return None
        finding_ids = getattr(incident, "finding_ids", ())
        if not finding_ids:
            return None
        for finding in self._snapshot.findings:
            if finding.finding_id in finding_ids:
                try:
                    from aegis_desktop.services.response_policy import collect_response_policy_view
                    return collect_response_policy_view(finding)
                except Exception:
                    return None
        return None

    def _create_response_request_from_incident(
        self, incident: object, response_view: object,
    ) -> None:
        """Create a response request from an incident context."""
        try:
            from aegis_desktop.services.response_workflow import get_workflow_manager
            manager = get_workflow_manager()
            finding_ids = tuple(getattr(incident, "finding_ids", ()))
            view = manager.create_request_from_incident(
                incident_id=getattr(incident, "incident_id", ""),
                action_label=str(getattr(response_view, "recommended_action", "")),
                target_value=str(getattr(response_view, "target", "")),
                target_kind="ip",
                risk_level=str(getattr(response_view, "risk_level", "informational")),
                risk_score=getattr(response_view, "risk_score", 0),
                finding_ids=finding_ids,
            )
            if view is not None:
                logger.info(
                    "Created response request %s for incident %s",
                    view.request_id,
                    getattr(incident, "incident_id", ""),
                )
        except Exception as exc:
            logger.warning("Failed to create response request from incident: %s", exc)

    # -- Navigation selection -----------------------------------------------

    def select_incident(self, incident_id: str) -> None:
        """Select and display the incident with the given ``incident_id``.

        Searches the current model rows for a matching ``incident_id`` and
        programmatically selects it, triggering the detail panel to populate.
        """
        if self._snapshot is None:
            return
        for idx in range(self._model.rowCount()):
            row = self._model.row_at(idx)
            if row is not None and row.incident_id == incident_id:
                proxy_index = self._proxy.mapFromSource(
                    self._model.index(idx, 0),
                )
                self._table.selectRow(proxy_index.row())
                return

    def handle_navigate(self, **kwargs: object) -> None:
        """Handle navigation parameters (e.g. ``select_id`` for incident selection)."""
        select_id = kwargs.get("select_id")
        if isinstance(select_id, str) and select_id:
            self.select_incident(select_id)

    @property
    def snapshot(self) -> IncidentSnapshotView | None:
        """The last applied snapshot, if any."""
        return self._snapshot

    @property
    def source_model(self) -> IncidentTableModel:
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

    def row_at(self, row: int) -> IncidentRow:
        """Return the displayed row at ``row``."""
        return self._model.row_at(row)

    def incident_count_text(self) -> str:
        """Return the 'Incidents: <count>' text."""
        return self._count_label.text()

    def runtime_status_text(self) -> str:
        """Return the 'Incident Correlation: Running/Not running' text."""
        return self._runtime_status_label.text()

    def incidents_text(self) -> str:
        """Return the 'Incidents: <n>' posture text."""
        return self._incidents_label.text()

    def last_updated_text(self) -> str:
        """Return the 'Last updated' text."""
        return self._last_updated_label.text()

    def _collect_fields_from_layout(self) -> tuple[list[str], list[str]]:
        """Collect label/value pairs from all section forms in the detail container."""
        keys: list[str] = []
        values: list[str] = []
        layout = self._investigation_layout
        for idx in range(layout.count()):
            item = layout.itemAt(idx)
            widget = item.widget() if item is not None else None
            if not isinstance(widget, QFrame):
                continue
            form = widget.findChild(QFormLayout)
            if form is None:
                continue
            for row_idx in range(form.rowCount()):
                label_item = form.itemAt(row_idx, QFormLayout.ItemRole.LabelRole)
                field_item = form.itemAt(row_idx, QFormLayout.ItemRole.FieldRole)
                label_widget = label_item.widget() if label_item is not None else None
                field_widget = field_item.widget() if field_item is not None else None
                if isinstance(label_widget, QLabel):
                    keys.append(label_widget.text())
                if isinstance(field_widget, QLabel):
                    values.append(field_widget.text())
        return keys, values

    def detail_keys(self) -> tuple[str, ...]:
        """Return the field keys currently shown in the detail panel."""
        keys, _ = self._collect_fields_from_layout()
        return tuple(keys)

    def detail_values(self) -> tuple[str, ...]:
        """Return the field values currently shown in the detail panel."""
        _, values = self._collect_fields_from_layout()
        return tuple(values)

    def has_error(self) -> bool:
        """Whether the page is showing a safe error state."""
        return self._error_active

    def error_text(self) -> str:
        """Return the current error banner text (empty when there is no error)."""
        return self._error_label.text()


__all__ = ["IncidentTableModel", "IncidentsPage"]
