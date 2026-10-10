"""Assets page: read-only inspection of observed hosts and their identities.

The page is presentation only. It reads the asset snapshot published by the
running runtime through :mod:`aegis_desktop.services.assets` and renders it with a
Qt model/view table plus a read-only structured detail panel showing asset
identity, network identity, observed services and network relationships.

It never starts a monitor, capture, detection or response, and it fabricates no
assets. With no runtime data it shows an honest empty state.
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
from aegis_desktop.services.assets import (
    AssetRow,
    AssetSnapshotView,
    collect_asset_view,
)
from aegis_desktop.services.dashboard import format_timestamp
from aegis_desktop.services.processes import MISSING
from aegis_desktop.theme import state_color
from aegis_shared.logging import get_logger

logger = get_logger(__name__)

_COLUMNS = (
    "Asset ID",
    "Hostname",
    "IP Addresses",
    "Services",
    "Peers",
    "Exposure",
    "Status",
)

_COLUMN_WIDTHS = (180, 180, 220, 80, 70, 110, 90)

_INITIAL_HINT = (
    "Select Refresh to inspect observed hosts. Assets are observed by the running "
    "runtime; nothing is collected here."
)

_NO_DATA_TEXT = "Assets: No data"

_NO_INDEX = QModelIndex()


class AssetTableModel(QAbstractTableModel):
    """Qt table model over a tuple of :class:`AssetRow`."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._rows: list[AssetRow] = []

    def set_rows(self, rows: tuple[AssetRow, ...]) -> None:
        """Replace the displayed rows."""
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def row_at(self, row: int) -> AssetRow:
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
        if role != Qt.ItemDataRole.DisplayRole or orientation != Qt.Orientation.Horizontal:
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
        if role == Qt.ItemDataRole.ToolTipRole and column == 2:
            return ", ".join(row.ip_addresses) if row.ip_addresses else MISSING
        if role == Qt.ItemDataRole.UserRole:
            return self._sort_key(row, column)
        if role == Qt.ItemDataRole.ForegroundRole:
            from PySide6.QtGui import QColor

            if column == 1:
                return QColor("#F8FAFC")
            if column == 2:
                return QColor("#38BDF8")
            if column in (3, 4):
                return QColor("#10B981")
            if column == 5:
                grade = getattr(row, "exposure_grade", "A")
                if grade in ("A", "B"):
                    return QColor("#10B981")
                if grade == "C":
                    return QColor("#F59E0B")
                return QColor("#EF4444")
            if column == 6:
                return state_color(row.status)
        if role == Qt.ItemDataRole.TextAlignmentRole:
            if column in (3, 4, 5, 6):
                return int(Qt.AlignmentFlag.AlignCenter)
            return int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        return None

    @staticmethod
    def _display(row: AssetRow, column: int) -> str:
        if column == 0:
            return row.asset_id
        if column == 1:
            return row.hostname or MISSING
        if column == 2:
            return ", ".join(row.ip_addresses) if row.ip_addresses else MISSING
        if column == 3:
            return str(row.service_count)
        if column == 4:
            return str(row.peer_count)
        if column == 5:
            grade = getattr(row, "exposure_grade", "A")
            score = getattr(row, "exposure_score", 0)
            return f"GRADE {grade} ({score}%)"
        if column == 6:
            return row.status.upper()
        return MISSING

    @staticmethod
    def _sort_key(row: AssetRow, column: int) -> object:
        if column == 3:
            return row.service_count
        if column == 4:
            return row.peer_count
        if column == 5:
            return getattr(row, "exposure_score", 0)
        return AssetTableModel._display(row, column).lower()


class AssetsPage(BasePage):
    """Read-only table + detail view of observed hosts/assets."""

    PAGE_KEY  = "assets"
    ICON       = "⬡"
    ICON_COLOR = "#10B981"
    TITLE     = "Assets"
    SUBTITLE = "Read-only inspection of observed hosts, services and network peers."
    EMPTY_STATE = ""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        provider: Callable[[], AssetSnapshotView] | None = None,
    ) -> None:
        self._provider: Callable[[], AssetSnapshotView] = provider or collect_asset_view
        self._snapshot: AssetSnapshotView | None = None
        self._error_active = False

        super().__init__(parent)
        # Deliberately no automatic collection: opening the application must not
        # start the runtime.
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

        self._model = AssetTableModel(self)
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
        self._table.horizontalHeader().setSectionsMovable(True)
        for index, width in enumerate(_COLUMN_WIDTHS):
            self._table.setColumnWidth(index, width)

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

        self._runtime_label = QLabel("Assets: Not observed")
        self._runtime_label.setObjectName("FieldValue")
        self._active_label = QLabel("Active Assets: —")
        self._active_label.setObjectName("CardHint")
        self._peers_label = QLabel("Observed Peers: —")
        self._peers_label.setObjectName("CardHint")
        self._new_label = QLabel("New Observations: —")
        self._new_label.setObjectName("CardHint")
        self._exposure_label = QLabel("Fleet Exposure: —")
        self._exposure_label.setObjectName("CardHint")

        posture.addWidget(self._runtime_label)
        posture.addWidget(self._active_label)
        posture.addWidget(self._peers_label)
        posture.addWidget(self._new_label)
        posture.addWidget(self._exposure_label)
        posture.addStretch(1)
        return posture

    def _build_detail_panel(self) -> QWidget:
        card = QWidget()
        card.setObjectName("Card")
        outer = QVBoxLayout(card)
        outer.setContentsMargins(16, 12, 16, 12)
        outer.setSpacing(8)

        heading = QLabel("ASSET DETAIL")
        heading.setObjectName("CardTitle")
        outer.addWidget(heading)

        self._detail_hint = QLabel("Select an asset to inspect its identity and context.")
        self._detail_hint.setObjectName("CardHint")
        self._detail_hint.setWordWrap(True)
        outer.addWidget(self._detail_hint)

        self._detail_container = QWidget()
        self._detail_layout = QVBoxLayout(self._detail_container)
        self._detail_layout.setContentsMargins(0, 0, 0, 0)
        self._detail_layout.setSpacing(10)
        outer.addWidget(self._detail_container)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(card)
        scroll.setMinimumHeight(160)
        return scroll

    @staticmethod
    def _build_section(title: str) -> tuple[QFrame, QFormLayout]:
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

    def refresh(self) -> AssetSnapshotView | None:
        """Read the published asset snapshot (read-only)."""
        try:
            view = self._provider()
        except Exception as exc:
            logger.warning("Assets refresh failed: %s", exc)
            self._show_error("Unable to read observed assets")
            return None
        self._apply(view)
        return view

    def _apply(self, view: AssetSnapshotView) -> None:
        self._snapshot = view
        self._render_posture(view)
        self._clear_detail()
        self._hint_label.setVisible(False)
        self._set_error(None)
        self._model.set_rows(view.rows)
        self._count_label.setText(f"Assets: {view.count}" if view.count else _NO_DATA_TEXT)
        self._last_updated_label.setText(
            f"Last updated: {format_timestamp(view.collected_at)}"
            if view.collected_at is not None
            else "Last updated: —"
        )
        if view.count == 0:
            self._hint_label.setText("No assets observed")
            self._hint_label.setVisible(True)
        else:
            self._table.selectRow(0)

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

    def _render_posture(self, view: AssetSnapshotView | None) -> None:
        if view is None:
            self._runtime_label.setText("Assets: Not observed")
            self._active_label.setText("Active Assets: —")
            self._peers_label.setText("Observed Peers: —")
            self._new_label.setText("New Observations: —")
            self._exposure_label.setText("Fleet Exposure: —")
            return
        posture = view.posture
        self._runtime_label.setText(
            f"Assets: {posture.assets}" if posture.assets else "Assets: Not observed"
        )
        self._active_label.setText(f"Active Assets: {posture.active_assets}")
        self._peers_label.setText(f"Observed Peers: {posture.peers}")
        self._new_label.setText(f"New Observations: {posture.new_observations}")

        if view.rows:
            total_score = sum(getattr(r, "exposure_score", 0) for r in view.rows)
            avg_score = int(total_score / len(view.rows))
            grades = {getattr(r, "exposure_grade", "A") for r in view.rows}
            worst_grade = "A"
            for candidate in ("F", "D", "C", "B"):
                if candidate in grades:
                    worst_grade = candidate
                    break
            self._exposure_label.setText(f"Fleet Exposure: Grade {worst_grade} ({avg_score}% avg)")
        else:
            self._exposure_label.setText("Fleet Exposure: —")

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
        self.show_detail_for(self._model.row_at(source_index.row()))

    def show_detail_for(self, row: AssetRow) -> None:
        """Populate the read-only detail panel for ``row``."""
        if self._snapshot is None:
            return
        self._clear_detail()
        self._detail_hint.setVisible(False)

        frame, form = self._build_section("ASSET IDENTITY")
        self._detail_layout.addWidget(frame)
        self._add_field(form, "Asset ID", row.asset_id)
        self._add_field(form, "Host ID", row.host_id)
        self._add_field(form, "Hostname", row.hostname or MISSING)
        self._add_field(form, "Operating System", row.os or MISSING)
        self._add_field(form, "Platform", row.platform)
        self._add_field(form, "Architecture", row.architecture or MISSING)

        frame, form = self._build_section("NETWORK IDENTITY")
        self._detail_layout.addWidget(frame)
        self._add_field(
            form, "IP Addresses", ", ".join(row.ip_addresses) if row.ip_addresses else MISSING
        )
        self._add_field(form, "Observed Interfaces", str(row.interface_count))

        frame, form = self._build_section("OBSERVED SERVICES")
        self._detail_layout.addWidget(frame)
        services = self._snapshot.services_for(row.asset_id)
        if services:
            for service in services:
                label = f"{service.port}/{service.protocol}"
                state = "known" if service.known else "new"
                detail = f"{service.status or MISSING} ({state})"
                if service.process_name:
                    detail = f"{detail} - {service.process_name}"
                self._add_field(form, label, detail)
        else:
            self._add_field(form, "Status", "No listening services observed")

        frame, form = self._build_section("NETWORK RELATIONSHIPS")
        self._detail_layout.addWidget(frame)
        peers = self._snapshot.peers_for(row.asset_id)
        if peers:
            for peer in peers:
                label = f"{peer.remote_ip}:{peer.remote_port or '-'}"
                state = "known" if peer.known else "new"
                detail = (
                    f"{peer.protocol}/{peer.direction} flows={peer.flow_count} "
                    f"packets={peer.packet_count} bytes={peer.byte_count} ({state})"
                )
                self._add_field(form, label, detail)
        else:
            self._add_field(form, "Status", "No network relationships observed")

        frame, form = self._build_section("ATTACK SURFACE & EXPOSURE ANALYSIS")
        self._detail_layout.addWidget(frame)
        grade = getattr(row, "exposure_grade", "A")
        score = getattr(row, "exposure_score", 0)
        grade_desc = {
            "A": "LOW EXPOSURE (Hardened Endpoint)",
            "B": "MODERATE EXPOSURE (Standard Endpoint)",
            "C": "ELEVATED RISK (Multiple Open Services)",
            "D": "HIGH ATTACK SURFACE (Exposed Services)",
            "F": "CRITICAL RISK (High-Risk Management Ports)",
        }.get(grade, "MONITORED")
        self._add_field(form, "Exposure Grade", f"GRADE {grade} — {grade_desc}")
        self._add_field(form, "Exposure Score", f"{score} / 100")
        if score >= 60:
            rec = "CRITICAL: Isolate host or block high-risk ports via Response Center."
        elif score >= 40:
            rec = "ELEVATED: Audit active listening ports and limit remote peer ingress."
        else:
            rec = "HEALTHY: Endpoint attack surface is minimal and well-segmented."
        self._add_field(form, "Hardening Advice", rec)

        self._detail_layout.addStretch(1)

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
        while self._detail_layout.count():
            item = self._detail_layout.takeAt(0)
            widget = item.widget() if item is not None else None
            if widget is not None:
                widget.setParent(None)
        self._detail_hint.setText("Select an asset to inspect its identity and context.")
        self._detail_hint.setVisible(True)

    # -- Read-only accessors (also used by tests) --------------------------

    @property
    def snapshot(self) -> AssetSnapshotView | None:
        """The last applied snapshot, if any."""
        return self._snapshot

    def column_headers(self) -> tuple[str, ...]:
        """Return the table's column headers."""
        return _COLUMNS

    def row_count(self) -> int:
        """Number of rows currently displayed."""
        return self._model.rowCount()

    def row_at(self, row: int) -> AssetRow:
        """Return the displayed row at ``row``."""
        return self._model.row_at(row)

    def asset_count_text(self) -> str:
        """Return the 'Assets: <n>' text."""
        return self._count_label.text()

    def peers_text(self) -> str:
        """Return the 'Observed Peers: <n>' text."""
        return self._peers_label.text()

    def last_updated_text(self) -> str:
        """Return the 'Last updated' text."""
        return self._last_updated_label.text()

    def _collect_fields_from_layout(self) -> tuple[list[str], list[str]]:
        keys: list[str] = []
        values: list[str] = []
        layout = self._detail_layout
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


__all__ = ["AssetTableModel", "AssetsPage"]
