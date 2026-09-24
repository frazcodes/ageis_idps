"""Detections page: read-only inspection of deterministic detection findings.

The page is presentation only. It reads findings from the existing Step 8
:class:`DetectionEngine` through :mod:`aegis_desktop.services.detections` and
renders them with a Qt model/view table plus a read-only structured detail panel.

It never starts a monitor, capture, FIM, detection loop, ML, scoring or response,
and it duplicates no rules. No findings are fabricated to populate the table.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

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
from aegis_desktop.services.dashboard import format_timestamp
from aegis_desktop.services.detections import (
    DETECTION_ERROR,
    FindingRow,
    FindingSnapshotView,
    InvestigationView,
    collect_finding_view,
    collect_investigation_view,
    describe_finding,
)
from aegis_desktop.services.processes import MISSING
from aegis_desktop.theme import state_color
from aegis_shared.enums import Severity
from aegis_shared.logging import get_logger

if TYPE_CHECKING:
    from aegis_shared.detection import DetectionFinding

logger = get_logger(__name__)

_COLUMNS = (
    "Timestamp",
    "Finding ID",
    "Rule ID",
    "Severity",
    "Title",
    "Event ID",
    "Description",
    "Evidence",
    "Tags",
)

_COLUMN_WIDTHS = (160, 240, 150, 90, 240, 220, 300, 320, 140)

_INITIAL_HINT = (
    "Select Refresh to inspect detection findings. No monitor, capture or "
    "detection loop is started."
)

_NO_DATA_TEXT = "Detections: No data"

#: Numeric rank for the existing severity ordering (sorts most severe last).
_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

#: Shared invalid index; avoids a function call in argument defaults (B008).
_NO_INDEX = QModelIndex()


class FindingTableModel(QAbstractTableModel):
    """Qt table model over a tuple of :class:`FindingRow`."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._rows: list[FindingRow] = []

    def set_rows(self, rows: tuple[FindingRow, ...]) -> None:
        """Replace the displayed rows."""
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def rows(self) -> tuple[FindingRow, ...]:
        """Return the current rows."""
        return tuple(self._rows)

    def row_at(self, row: int) -> FindingRow:
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
            return state_color(row.severity)
        return None

    @staticmethod
    def _display(row: FindingRow, column: int) -> str:
        if column == 0:
            return format_timestamp(row.timestamp)
        if column == 1:
            return row.finding_id
        if column == 2:
            return row.rule_id
        if column == 3:
            return row.severity
        if column == 4:
            return row.title
        if column == 5:
            return row.event_id
        if column == 6:
            return row.description
        if column == 7:
            return row.evidence_summary
        if column == 8:
            return ", ".join(row.tags) if row.tags else MISSING
        return MISSING

    @staticmethod
    def _tooltip(row: FindingRow, column: int) -> str | None:
        if column in (1, 4, 6, 7):
            return FindingTableModel._display(row, column)
        return None

    @staticmethod
    def _sort_key(row: FindingRow, column: int) -> object:
        if column == 0:
            return row.timestamp.timestamp()
        if column == 3:
            try:
                return _SEVERITY_RANK[Severity(row.severity)]
            except ValueError:
                return -1
        return FindingTableModel._display(row, column).lower()


class DetectionsPage(BasePage):
    """Read-only table + detail view of deterministic detection findings."""

    PAGE_KEY = "detections"
    TITLE = "Detections"
    SUBTITLE = "Read-only inspection of deterministic rule-based findings."
    EMPTY_STATE = ""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        provider: Callable[[], FindingSnapshotView] | None = None,
        investigation_provider: Callable[[DetectionFinding], InvestigationView] | None = None,
    ) -> None:
        self._provider: Callable[[], FindingSnapshotView] = provider or collect_finding_view
        self._investigation_provider: Callable[[DetectionFinding], InvestigationView] | None = (
            investigation_provider
        )
        self._snapshot: FindingSnapshotView | None = None
        self._error_active = False

        super().__init__(parent)
        # Deliberately no automatic evaluation: opening the application must not
        # start the detection engine.
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

        self._model = FindingTableModel(self)
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

        self._engine_status_label = QLabel("Detection Engine: Not running")
        self._engine_status_label.setObjectName("FieldValue")
        self._rules_label = QLabel("Rules: —")
        self._rules_label.setObjectName("CardHint")
        self._findings_label = QLabel("Findings: No data")
        self._findings_label.setObjectName("CardHint")

        posture.addWidget(self._engine_status_label)
        posture.addWidget(self._rules_label)
        posture.addWidget(self._findings_label)
        posture.addStretch(1)
        return posture

    def _build_detail_panel(self) -> QWidget:
        card = QWidget()
        card.setObjectName("Card")
        outer = QVBoxLayout(card)
        outer.setContentsMargins(16, 12, 16, 12)
        outer.setSpacing(8)

        heading = QLabel("FINDING INVESTIGATION")
        heading.setObjectName("CardTitle")
        outer.addWidget(heading)

        self._detail_hint = QLabel("Select a finding to inspect its investigation details.")
        self._detail_hint.setObjectName("CardHint")
        self._detail_hint.setWordWrap(True)
        outer.addWidget(self._detail_hint)

        self._investigation_container = QWidget()
        self._investigation_layout = QVBoxLayout(self._investigation_container)
        self._investigation_layout.setContentsMargins(0, 0, 0, 0)
        self._investigation_layout.setSpacing(10)
        outer.addWidget(self._investigation_container)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(card)
        scroll.setMinimumHeight(160)
        return scroll

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

    def refresh(self) -> FindingSnapshotView | None:
        """Read existing findings from the detection engine.

        Never starts a producer or a detection loop, and never performs a
        response. On failure a safe error state is shown.
        """
        try:
            view = self._provider()
        except Exception as exc:
            logger.warning("Detections refresh failed: %s", exc)
            self._show_error(DETECTION_ERROR)
            return None

        self._apply(view)
        return view

    def _apply(self, view: FindingSnapshotView) -> None:
        self._snapshot = view
        self._render_posture(view)
        self._clear_detail()

        if view.available:
            self._set_error(None)
            self._hint_label.setVisible(False)
            self._model.set_rows(view.rows)
            self._count_label.setText(f"Detections: {view.count}" if view.count else _NO_DATA_TEXT)
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
            self._set_error(view.error or DETECTION_ERROR)

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

    def _render_posture(self, view: FindingSnapshotView | None) -> None:
        if view is None:
            self._engine_status_label.setText("Detection Engine: Not running")
            self._rules_label.setText("Rules: —")
            self._findings_label.setText("Findings: No data")
            return
        posture = view.posture
        self._engine_status_label.setText(
            "Detection Engine: Running" if posture.running else "Detection Engine: Not running"
        )
        self._rules_label.setText(f"Rules: {posture.rule_count}" if posture.running else "Rules: —")
        self._findings_label.setText(
            f"Findings: {posture.findings}" if posture.findings else "Findings: No data"
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

    def show_detail_for(self, row: FindingRow) -> None:
        """Populate the read-only investigation panel for ``row``."""
        if self._snapshot is None:
            return
        finding = self._snapshot.finding_by_id(row.finding_id)
        if finding is None:
            self._clear_detail()
            return

        try:
            if self._investigation_provider is not None:
                investigation = self._investigation_provider(finding)
            else:
                investigation = collect_investigation_view(finding)
        except Exception as exc:
            logger.warning("Investigation view failed for %s: %s", row.finding_id, exc)
            investigation = None

        self._clear_detail()
        self._detail_hint.setVisible(False)

        if investigation is None:
            self._render_fallback_detail(finding)
            return

        self._render_investigation(investigation)

    def _render_investigation(self, inv: InvestigationView) -> None:
        """Render the full investigation panel with sections."""
        # Section 1: Finding Summary
        frame, form = self._build_section("FINDING SUMMARY")
        self._investigation_layout.addWidget(frame)
        for key in (
            "finding_id", "rule_id", "severity", "title",
            "event_id", "timestamp", "description",
        ):
            value = inv.finding.get(key, "")
            self._add_field(form, key.replace("_", " ").title(), value)

        # Section 2: Why Detected
        if inv.rule_info:
            frame, form = self._build_section("WHY DETECTED")
            self._investigation_layout.addWidget(frame)
            for key in ("name", "description", "tags"):
                value = inv.rule_info.get(key, "")
                if value:
                    self._add_field(form, key.replace("_", " ").title(), value)

        # Section 3: Evidence
        if inv.evidence:
            frame, form = self._build_section("EVIDENCE")
            self._investigation_layout.addWidget(frame)
            for key in sorted(inv.evidence):
                self._add_field(form, key, inv.evidence[key])

        # Section 4: Risk Assessment
        frame, form = self._build_section("RISK ASSESSMENT")
        self._investigation_layout.addWidget(frame)
        if inv.risk is not None:
            self._add_field(form, "Risk Score", str(inv.risk.risk_score))
            self._add_field(form, "Risk Level", inv.risk.risk_level)
            self._add_field(form, "Severity", inv.risk.severity)
            if inv.risk.reasons:
                self._add_field(form, "Reasons", " | ".join(inv.risk.reasons))
            if inv.risk.contributors:
                self._add_field(form, "Contributors", "; ".join(inv.risk.contributors))
        else:
            self._add_field(form, "Status", "Risk engine not available")

        # ML anomaly signal (existing RiskAssessment.anomaly, read-only).
        anomaly = inv.risk.anomaly if inv.risk is not None else None
        if anomaly is not None:
            self._add_field(form, "Anomaly Detected", "Yes")
            self._add_field(form, "Anomaly Score", f"{anomaly.score:.3f}")
            self._add_field(form, "Model Version", anomaly.model_version)
            self._add_field(form, "Source", anomaly.source)
            self._add_field(form, "Confidence", f"{anomaly.confidence:.3f}")
            if anomaly.reason:
                self._add_field(form, "Reason", anomaly.reason)
        else:
            self._add_field(form, "ML Anomaly", "No ML anomaly signal available")

        # Section 5: Correlation Evidence (host <-> network, read-only)
        frame, form = self._build_section("CORRELATION EVIDENCE")
        self._investigation_layout.addWidget(frame)
        correlation = inv.correlation
        if correlation is not None:
            self._add_field(form, "Status", "Correlated")
            self._add_field(form, "Host", correlation.host_id)
            self._add_field(form, "Host Findings", str(correlation.host_finding_count))
            self._add_field(form, "Network Findings", str(correlation.network_finding_count))
            self._add_field(form, "Time Window", f"{correlation.window_seconds} seconds")
            self._add_field(form, "Reason", correlation.reason)
        else:
            self._add_field(form, "Status", "No host ↔ network correlation available")

        # Section 6: Threat Intelligence (IOC context, read-only)
        frame, form = self._build_section("THREAT INTELLIGENCE")
        self._investigation_layout.addWidget(frame)
        threat_intel = inv.threat_intel
        if threat_intel is None:
            self._add_field(form, "IOC Match", "No threat-intelligence match available")
        else:
            self._add_field(form, "IOC Match", "Yes")
            if threat_intel.count > 1:
                self._add_field(form, "Matches", str(threat_intel.count))
            for match in threat_intel.matches:
                self._add_field(form, "Type", match.indicator_type)
                self._add_field(form, "Observed", match.observed_value)
                self._add_field(form, "Source", match.source)
                self._add_field(form, "Confidence", f"{match.confidence:.2f}")
                self._add_field(form, "Severity", match.severity)
            self._add_field(
                form,
                "Context",
                "Configured threat-intelligence indicator matched observed telemetry.",
            )

        # Section 7: Asset Context (observed host identity, read-only)
        frame, form = self._build_section("ASSET CONTEXT")
        self._investigation_layout.addWidget(frame)
        asset = inv.asset_context
        if asset is not None:
            self._add_field(form, "Host", asset.host_id)
            self._add_field(form, "Hostname", asset.hostname or MISSING)
            self._add_field(
                form,
                "Observed IP",
                ", ".join(asset.ip_addresses) if asset.ip_addresses else MISSING,
            )
            self._add_field(
                form,
                "Observed Services",
                ", ".join(asset.observed_ports) if asset.observed_ports else MISSING,
            )
            self._add_field(
                form,
                "Network Peers",
                f"{asset.known_peers} known, {asset.new_peers} new",
            )
        else:
            self._add_field(form, "Status", "No asset context available")

        # Section 8: Communication Analysis (multi-signal, read-only)
        frame, form = self._build_section("COMMUNICATION ANALYSIS")
        self._investigation_layout.addWidget(frame)
        communication = inv.communication
        if communication is not None:
            signals = set(communication.signals)
            self._add_field(form, "Communication", communication.relationship)
            self._add_field(form, "Protocol", communication.protocol)
            self._add_field(
                form,
                "Relationship",
                "NEW" if "new_relationship" in signals else "KNOWN",
            )
            self._add_field(
                form, "Destination", "NEW" if "new_destination" in signals else "KNOWN"
            )
            self._add_field(
                form,
                "Destination Port",
                "NEW" if "new_destination_port" in signals else "KNOWN",
            )
            self._add_field(form, "Signals", ", ".join(communication.signals))
            self._add_field(form, "Signal Count", str(communication.signal_count))
            if communication.related_finding_ids:
                self._add_field(
                    form, "Related Findings", ", ".join(communication.related_finding_ids)
                )
            self._add_field(form, "Assessment", communication.assessment)
        else:
            self._add_field(form, "Status", "No communication analysis available")

        # Section 9: Response Policy (read-only preview; nothing executes)
        frame, form = self._build_section("RESPONSE POLICY")
        self._investigation_layout.addWidget(frame)
        policy = inv.response_policy
        if policy is not None:
            self._add_field(form, "Recommended Action", policy.action_label or MISSING)
            self._add_field(form, "Target", policy.target or MISSING)
            self._add_field(form, "Decision", policy.status.upper())
            self._add_field(form, "Risk", policy.risk_level.upper())
            self._add_field(
                form,
                "Dry Run",
                "REQUIRED" if policy.dry_run_required else "NOT REQUIRED",
            )
            self._add_field(
                form, "Approval", "REQUIRED" if policy.required_approval else "NOT REQUIRED"
            )
            self._add_field(form, "Reason", policy.reason)
            self._add_field(form, "Policy Version", policy.policy_version)
            if policy.target:
                create_btn = QPushButton("Create Response Request")
                create_btn.setObjectName("PrimaryButton")
                fid = inv.finding.get("finding_id", "")
                create_btn.clicked.connect(
                    lambda checked=False, f=fid: self._create_response_request(f)
                )
                btn_row = QHBoxLayout()
                btn_row.addWidget(create_btn)
                btn_row.addStretch(1)
                form.addRow(btn_row)
        else:
            self._add_field(form, "Status", "No response action available for this finding.")

        # Section 10: Response Posture
        frame, form = self._build_section("RESPONSE POSTURE")
        self._investigation_layout.addWidget(frame)
        self._add_field(form, "Mode", inv.response.mode)
        self._add_field(form, "Dry Run", "Yes" if inv.response.dry_run else "No")
        self._add_field(form, "Approval Required", "Yes" if inv.response.require_approval else "No")

        # Section 11: Related Event
        frame, form = self._build_section("RELATED EVENT")
        self._investigation_layout.addWidget(frame)
        if inv.event_details is not None:
            for key in ("event_id", "event_type", "category", "severity", "timestamp", "source"):
                value = inv.event_details.get(key, "")
                if value:
                    self._add_field(form, key.replace("_", " ").title(), value)
        else:
            self._add_field(form, "Status", "Event not available in pipeline")

        self._investigation_layout.addStretch(1)

    def _render_fallback_detail(self, finding: object) -> None:
        """Render minimal fallback detail when investigation fails."""
        frame, form = self._build_section("FINDING DETAIL")
        self._investigation_layout.addWidget(frame)
        for key, value in describe_finding(finding).items():
            self._add_field(form, key, value)

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
        self._detail_hint.setText("Select a finding to inspect its investigation details.")
        self._detail_hint.setVisible(True)

    # -- Navigation selection -----------------------------------------------

    def select_finding(self, finding_id: str) -> None:
        """Select and display the finding with the given ``finding_id``.

        Searches the current model rows for a matching ``finding_id`` and
        programmatically selects it, triggering the detail panel to populate.
        """
        if self._snapshot is None:
            return
        for idx in range(self._model.rowCount()):
            row = self._model.row_at(idx)
            if row is not None and row.finding_id == finding_id:
                proxy_index = self._proxy.mapFromSource(
                    self._model.index(idx, 0),
                )
                self._table.selectRow(proxy_index.row())
                return

    def handle_navigate(self, **kwargs: object) -> None:
        """Handle navigation parameters (e.g. ``select_id`` for finding selection)."""
        select_id = kwargs.get("select_id")
        if isinstance(select_id, str) and select_id:
            self.select_finding(select_id)

    # -- Read-only accessors (also used by tests) --------------------------

    def _create_response_request(self, finding_id: str) -> None:
        """Create a response request from the current finding and navigate to Response Center."""
        if self._snapshot is None:
            return
        finding = self._snapshot.finding_by_id(finding_id)
        if finding is None:
            return
        try:
            from aegis_desktop.services.response_workflow import get_workflow_manager
            manager = get_workflow_manager()
            view = manager.create_request(finding)
            if view is not None:
                logger.info(
                    "Created response request %s for finding %s",
                    view.request_id, finding_id,
                )
        except Exception as exc:
            logger.warning("Failed to create response request: %s", exc)

    @property
    def snapshot(self) -> FindingSnapshotView | None:
        """The last applied snapshot, if any."""
        return self._snapshot

    @property
    def source_model(self) -> FindingTableModel:
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

    def row_at(self, row: int) -> FindingRow:
        """Return the displayed row at ``row``."""
        return self._model.row_at(row)

    def detection_count_text(self) -> str:
        """Return the 'Detections: <count>' text."""
        return self._count_label.text()

    def engine_status_text(self) -> str:
        """Return the 'Detection Engine: Running/Not running' text."""
        return self._engine_status_label.text()

    def rules_text(self) -> str:
        """Return the 'Rules: <n>' text."""
        return self._rules_label.text()

    def findings_text(self) -> str:
        """Return the 'Findings: <n>' text."""
        return self._findings_label.text()

    def last_updated_text(self) -> str:
        """Return the 'Last updated' text."""
        return self._last_updated_label.text()

    def _collect_fields_from_layout(self) -> tuple[list[str], list[str]]:
        """Collect label/value pairs from all section forms in the investigation container."""
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
        """Return the field keys currently shown in the investigation panel."""
        keys, _ = self._collect_fields_from_layout()
        return tuple(keys)

    def detail_values(self) -> tuple[str, ...]:
        """Return the field values currently shown in the investigation panel."""
        _, values = self._collect_fields_from_layout()
        return tuple(values)

    def has_error(self) -> bool:
        """Whether the page is showing a safe error state."""
        return self._error_active

    def error_text(self) -> str:
        """Return the current error banner text (empty when there is no error)."""
        return self._error_label.text()


__all__ = ["DetectionsPage", "FindingTableModel"]
