"""Response Center page: desktop-managed dry-run + approval + execution workflow.

Table + detail view of response requests.  Buttons drive the workflow states
(Dry Run, Approve, Reject, Execute).  Execution is only available for approved
BLOCK_IP requests and requires an explicit confirmation.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
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
    QDialog,
    QDialogButtonBox,
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
from aegis_desktop.services.processes import MISSING
from aegis_desktop.services.response_workflow import (
    ResponseRequestView,
    get_audit_history,
    get_workflow_manager,
)
from aegis_desktop.theme import state_color
from aegis_shared.logging import get_logger

if TYPE_CHECKING:  # pragma: no cover
    pass

logger = get_logger(__name__)

_COLUMNS = (
    "Request ID",
    "Action",
    "Target",
    "Risk",
    "Policy",
    "Dry Run",
    "Approval",
    "Status",
    "Time",
)

_COLUMN_WIDTHS = (170, 120, 130, 80, 110, 120, 120, 100, 160)

_AUDIT_COLUMNS = (
    "Audit ID",
    "Request ID",
    "Action",
    "Target",
    "Source",
    "Policy",
    "Before",
    "After",
    "Execution",
    "Verification",
    "Changed",
    "Time",
)

_AUDIT_COLUMN_WIDTHS = (140, 140, 100, 110, 100, 110, 100, 100, 100, 110, 70, 160)

_INITIAL_HINT = (
    "Response Center manages response-request workflows. No monitor, "
    "capture or execution loop is started."
)

_NO_DATA_TEXT = "Requests: No data"

_NO_INDEX = QModelIndex()


class _ExecutionConfirmDialog(QDialog):
    """Confirmation dialog for response execution."""

    def __init__(self, action: str, target: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Confirm Response Execution")
        self.setMinimumWidth(400)

        layout = QVBoxLayout(self)

        warning = QLabel(
            "Execute Response?\n\n"
            f"Action:\n{action}\n\n"
            f"Target:\n{target}\n\n"
            "This will modify the local firewall."
        )
        warning.setObjectName("FieldValue")
        warning.setWordWrap(True)
        layout.addWidget(warning)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


class RequestTableModel(QAbstractTableModel):
    """Qt table model over a tuple of :class:`ResponseRequestView`."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._rows: list[ResponseRequestView] = []

    def set_rows(self, rows: tuple[ResponseRequestView, ...]) -> None:
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def rows(self) -> tuple[ResponseRequestView, ...]:
        return tuple(self._rows)

    def row_at(self, row: int) -> ResponseRequestView:
        return self._rows[row]

    def rowCount(  # noqa: N802
        self, parent: QModelIndex | QPersistentModelIndex = _NO_INDEX,
    ) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(  # noqa: N802
        self, parent: QModelIndex | QPersistentModelIndex = _NO_INDEX,
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
        if role == Qt.ItemDataRole.ForegroundRole and column == 7:
            return state_color(row.approval_status)
        return None

    @staticmethod
    def _display(row: ResponseRequestView, column: int) -> str:
        if column == 0:
            return row.request_id
        if column == 1:
            return row.action_label
        if column == 2:
            return row.target
        if column == 3:
            return str(row.risk_score)
        if column == 4:
            return row.policy_decision.upper() if row.policy_decision else MISSING
        if column == 5:
            return row.dry_run_status.upper() if row.dry_run_status else "NOT STARTED"
        if column == 6:
            return row.approval_status.upper()
        if column == 7:
            return row.status.upper()
        if column == 8:
            return format_timestamp(row.created_at)
        return MISSING

    @staticmethod
    def _tooltip(row: ResponseRequestView, column: int) -> str | None:
        if column in (0, 1, 4, 7):
            return RequestTableModel._display(row, column)
        return None

    @staticmethod
    def _sort_key(row: ResponseRequestView, column: int) -> object:
        if column == 3:
            return row.risk_score
        if column == 8:
            return row.created_at.timestamp()
        return RequestTableModel._display(row, column).lower()


class AuditTableModel(QAbstractTableModel):
    """Qt table model for response audit records."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._rows: list[object] = []

    def set_rows(self, rows: tuple[object, ...]) -> None:
        self.beginResetModel()
        self._rows = list(rows)
        self.endResetModel()

    def rowCount(  # noqa: N802
        self, parent: QModelIndex | QPersistentModelIndex = _NO_INDEX,
    ) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(  # noqa: N802
        self, parent: QModelIndex | QPersistentModelIndex = _NO_INDEX,
    ) -> int:
        return len(_AUDIT_COLUMNS)

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
        return _AUDIT_COLUMNS[section]

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
        if role == Qt.ItemDataRole.ForegroundRole and column == 9:
            return state_color(
                getattr(row, "verification_status", ""),
            )
        return None

    @staticmethod
    def _display(row: object, column: int) -> str:
        cols = (
            "audit_id",
            "request_id",
            "action",
            "target",
            "source_type",
            "policy_decision",
            "workflow_status_before",
            "workflow_status_after",
            "execution_status",
            "verification_status",
            "changed",
        )
        if column < len(cols):
            val = getattr(row, cols[column], "")
            if column == 11:
                return format_timestamp(getattr(row, "timestamp", datetime.min))
            return str(val).upper() if isinstance(val, bool) else str(val)
        if column == 11:
            return format_timestamp(getattr(row, "timestamp", datetime.min))
        return MISSING


class ResponseCenterPage(BasePage):
    """Read-only table + detail view of response-request workflows."""

    PAGE_KEY = "response"
    TITLE = "Response Center"
    SUBTITLE = "Response-request workflow: dry run, approval, controlled execution."
    EMPTY_STATE = ""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        manager_provider: Callable[..., object] | None = None,
    ) -> None:
        self._manager_provider = manager_provider or (lambda: get_workflow_manager())
        self._snapshot: tuple[ResponseRequestView, ...] = ()
        self._error_active = False

        super().__init__(parent)
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

        self._model = RequestTableModel(self)
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
        self._table.sortByColumn(8, Qt.SortOrder.DescendingOrder)

        self._detail = self._build_detail_panel()

        self._audit_model = AuditTableModel(self)
        self._audit_table = QTableView()
        self._audit_table.setModel(self._audit_model)
        self._audit_table.setAlternatingRowColors(True)
        self._audit_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._audit_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._audit_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._audit_table.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        self._audit_table.setWordWrap(False)
        self._audit_table.verticalHeader().setVisible(False)
        self._audit_table.horizontalHeader().setStretchLastSection(False)
        for index, width in enumerate(_AUDIT_COLUMN_WIDTHS):
            self._audit_table.setColumnWidth(index, width)
        self._audit_table.sortByColumn(11, Qt.SortOrder.DescendingOrder)

        audit_heading = QLabel("RESPONSE AUDIT HISTORY")
        audit_heading.setObjectName("CardTitle")

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self._table)
        splitter.addWidget(self._detail)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter, 1)

        audit_container = QWidget()
        audit_layout = QVBoxLayout(audit_container)
        audit_layout.setContentsMargins(0, 0, 0, 0)
        audit_layout.setSpacing(4)
        audit_layout.addWidget(audit_heading)
        audit_layout.addWidget(self._audit_table)
        layout.addWidget(audit_container, 1)

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

        self._pending_label = QLabel("Pending Approval: 0")
        self._pending_label.setObjectName("FieldValue")
        self._approved_label = QLabel("Approved: 0")
        self._approved_label.setObjectName("FieldValue")
        self._executed_label = QLabel("Executed: 0")
        self._executed_label.setObjectName("FieldValue")

        posture.addWidget(self._pending_label)
        posture.addWidget(self._approved_label)
        posture.addWidget(self._executed_label)
        posture.addStretch(1)
        return posture

    def _build_detail_panel(self) -> QWidget:
        card = QWidget()
        card.setObjectName("Card")
        outer = QVBoxLayout(card)
        outer.setContentsMargins(16, 12, 16, 12)
        outer.setSpacing(8)

        heading = QLabel("RESPONSE REQUEST")
        heading.setObjectName("CardTitle")
        outer.addWidget(heading)

        self._detail_hint = QLabel("Select a response request to inspect its workflow details.")
        self._detail_hint.setObjectName("CardHint")
        self._detail_hint.setWordWrap(True)
        outer.addWidget(self._detail_hint)

        self._detail_container = QWidget()
        self._detail_layout = QVBoxLayout(self._detail_container)
        self._detail_layout.setContentsMargins(0, 0, 0, 0)
        self._detail_layout.setSpacing(10)
        outer.addWidget(self._detail_container)

        self._controls_container = QWidget()
        self._controls_layout = QVBoxLayout(self._controls_container)
        self._controls_layout.setContentsMargins(0, 0, 0, 0)
        self._controls_layout.setSpacing(6)
        outer.addWidget(self._controls_container)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(card)
        scroll.setMinimumHeight(200)
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

    def refresh(self) -> tuple[ResponseRequestView, ...]:
        """Read current response requests from the workflow manager."""
        try:
            manager = self._manager_provider()
            self._snapshot = manager.all_requests()
        except Exception as exc:
            logger.warning("Response Center refresh failed: %s", exc)
            self._snapshot = ()
            self._show_error("Response Center refresh failed.")
            return ()

        self._apply(self._snapshot)
        self._refresh_audit()
        return self._snapshot

    def _refresh_audit(self, request_id: str | None = None) -> None:
        """Refresh the audit history table, optionally filtered by request."""
        try:
            history = get_audit_history()
            if request_id:
                records = history.records_for_request(request_id)
            else:
                records = history.all_records()
            self._audit_model.set_rows(records)
        except Exception as exc:
            logger.warning("Audit history refresh failed: %s", exc)
            self._audit_model.set_rows(())

    def _apply(self, rows: tuple[ResponseRequestView, ...]) -> None:
        self._clear_detail()
        manager = self._manager_provider()
        pending = manager.pending_count()
        approved = manager.approved_count()
        executed = manager.executed_count()

        self._pending_label.setText(f"Pending Approval: {pending}")
        self._approved_label.setText(f"Approved: {approved}")
        self._executed_label.setText(f"Executed: {executed}")

        if rows:
            self._hint_label.setVisible(False)
            self._model.set_rows(rows)
            self._count_label.setText(f"Requests: {len(rows)}")
            self._last_updated_label.setText("Last updated: —")
            self._set_error(None)
        else:
            self._model.set_rows(())
            self._count_label.setText(_NO_DATA_TEXT)
            self._last_updated_label.setText("Last updated: —")
            self._hint_label.setText(_INITIAL_HINT)
            self._hint_label.setVisible(True)
            self._set_error(None)

    def _show_initial_state(self) -> None:
        self._snapshot = ()
        self._model.set_rows(())
        self._count_label = getattr(self, "_count_label", None)
        if self._count_label is not None:
            self._count_label.setText(_NO_DATA_TEXT)
        lbl = getattr(self, "_last_updated_label", None)
        if lbl is not None:
            lbl.setText("Last updated: —")
        self._clear_detail()
        self._set_error(None)

    def _show_error(self, message: str) -> None:
        self._model.set_rows(())
        self._count_label.setText(_NO_DATA_TEXT)
        self._last_updated_label.setText("Last updated: —")
        self._hint_label.setVisible(False)
        self._clear_detail()
        self._set_error_active(message)

    def _set_error(self, message: str | None) -> None:
        self._error_active = message is not None
        self._error_label.setText(message or "")
        self._error_label.setVisible(message is not None)

    def _set_error_active(self, message: str) -> None:
        self._error_active = True
        self._error_label.setText(message)
        self._error_label.setVisible(True)

    # -- Detail view -------------------------------------------------------

    def _on_selection_changed(self, *_args: object) -> None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            self._clear_detail()
            self._refresh_audit()
            return
        source_index = self._proxy.mapToSource(rows[0])
        row = self._model.row_at(source_index.row())
        self._render_detail(row)
        self._refresh_audit(row.request_id)

    def _render_detail(self, view: ResponseRequestView) -> None:
        self._clear_detail()
        self._detail_hint.setVisible(False)

        # Request Info
        frame, form = self._build_section("RESPONSE REQUEST")
        self._detail_layout.addWidget(frame)
        self._add_field(form, "Request ID", view.request_id)
        self._add_field(form, "Action", view.action_label)
        self._add_field(form, "Target", view.target)
        self._add_field(form, "Risk Score", str(view.risk_score))
        self._add_field(form, "Risk Level", view.risk_level.upper())

        # Source Context
        frame, form = self._build_section("SOURCE CONTEXT")
        self._detail_layout.addWidget(frame)
        findings_text = ", ".join(view.source_finding_ids) if view.source_finding_ids else MISSING
        self._add_field(form, "Source Findings", findings_text)
        self._add_field(form, "Incident", view.incident_id or MISSING)
        self._add_field(form, "Reason", view.reason)

        # Policy Decision
        frame, form = self._build_section("POLICY DECISION")
        self._detail_layout.addWidget(frame)
        policy_decision_text = view.policy_decision.upper() if view.policy_decision else MISSING
        self._add_field(form, "Policy Decision", policy_decision_text)
        self._add_field(form, "Policy Version", view.policy_version)

        # Dry Run
        frame, form = self._build_section("DRY RUN")
        self._detail_layout.addWidget(frame)
        dry_run_text = view.dry_run_status.upper() if view.dry_run_status else "NOT STARTED"
        self._add_field(form, "Dry Run Status", dry_run_text)

        # Approval
        frame, form = self._build_section("APPROVAL")
        self._detail_layout.addWidget(frame)
        self._add_field(form, "Approval Status", view.approval_status.upper())
        if view.rejection_reason:
            self._add_field(form, "Rejection Reason", view.rejection_reason)

        # Workflow
        frame, form = self._build_section("WORKFLOW")
        self._detail_layout.addWidget(frame)
        self._add_field(form, "Status", view.status.upper())
        self._add_field(form, "Created", format_timestamp(view.created_at))
        self._add_field(form, "Updated", format_timestamp(view.updated_at))

        self._detail_layout.addStretch(1)

        # Controls (state-dependent)
        self._render_controls(view)

    def _render_controls(self, view: ResponseRequestView) -> None:
        """Add state-dependent workflow buttons."""
        status = view.status

        if status in ("draft", "dry_run_ready"):
            btn = QPushButton("Run Dry Run")
            btn.setObjectName("PrimaryButton")
            btn.clicked.connect(
                lambda checked=False, rid=view.request_id: self._on_dry_run(rid)
            )
            self._controls_layout.addWidget(btn)

        if status == "dry_run_completed":
            approve_btn = QPushButton("Approve")
            approve_btn.setObjectName("PrimaryButton")
            approve_btn.clicked.connect(
                lambda checked=False, rid=view.request_id: self._on_approve(rid)
            )
            self._controls_layout.addWidget(approve_btn)

            reject_btn = QPushButton("Reject")
            reject_btn.setObjectName("PrimaryButton")
            reject_btn.clicked.connect(
                lambda checked=False, rid=view.request_id: self._on_reject(rid)
            )
            self._controls_layout.addWidget(reject_btn)

        if status == "approved":
            # Show execution section for approved requests
            if view.action_label == "Block IP":
                exec_frame, exec_form = self._build_section("RESPONSE EXECUTION")
                self._detail_layout.addWidget(exec_frame)
                self._add_field(exec_form, "Action", view.action_label)
                self._add_field(exec_form, "Target", view.target)
                self._add_field(exec_form, "Approval", "APPROVED")
                self._add_field(exec_form, "Execution", "READY")

                exec_btn = QPushButton("Execute Response")
                exec_btn.setObjectName("PrimaryButton")
                exec_btn.clicked.connect(
                    lambda checked=False, v=view: self._on_execute(v)
                )
                btn_row = QHBoxLayout()
                btn_row.addWidget(exec_btn)
                btn_row.addStretch(1)
                exec_form.addRow(btn_row)
            else:
                info = QLabel("APPROVED\n\nExecution:\nNOT AVAILABLE IN THIS VERSION")
                info.setObjectName("FieldValue")
                info.setWordWrap(True)
                self._controls_layout.addWidget(info)

        if status == "executed":
            exec_frame, exec_form = self._build_section("RESPONSE EXECUTION")
            self._detail_layout.addWidget(exec_frame)
            self._add_field(exec_form, "Action", view.action_label)
            self._add_field(exec_form, "Target", view.target)
            self._add_field(exec_form, "Status", "APPLIED")
            self._add_field(exec_form, "Firewall", view.execution_adapter)
            verified_text = "VERIFIED" if view.execution_verified else "NOT VERIFIED"
            self._add_field(exec_form, "Verification", verified_text)
            changed_text = "YES" if view.execution_changed else "NO"
            self._add_field(exec_form, "Changed", changed_text)
            if view.execution_message:
                self._add_field(exec_form, "Message", view.execution_message)

        if status == "execution_failed":
            exec_frame, exec_form = self._build_section("RESPONSE EXECUTION")
            self._detail_layout.addWidget(exec_frame)
            self._add_field(exec_form, "Action", view.action_label)
            self._add_field(exec_form, "Target", view.target)
            self._add_field(exec_form, "Status", "FAILED")
            if view.execution_message:
                self._add_field(exec_form, "Reason", view.execution_message)
            self._add_field(exec_form, "Verification", "NOT VERIFIED")

        if status == "rejected":
            info = QLabel("REJECTED")
            info.setObjectName("FieldValue")
            info.setWordWrap(True)
            self._controls_layout.addWidget(info)

        if status == "cancelled":
            info = QLabel("CANCELLED")
            info.setObjectName("FieldValue")
            info.setWordWrap(True)
            self._controls_layout.addWidget(info)

    def _on_dry_run(self, request_id: str) -> None:
        manager = self._manager_provider()
        manager.run_dry_run(request_id)
        manager.request_approval(request_id)
        self.refresh()
        self._re_select(request_id)

    def _on_approve(self, request_id: str) -> None:
        manager = self._manager_provider()
        manager.approve(request_id)
        self.refresh()
        self._re_select(request_id)

    def _on_reject(self, request_id: str) -> None:
        manager = self._manager_provider()
        manager.reject(request_id, reason="Operator rejected via Response Center")
        self.refresh()
        self._re_select(request_id)

    def _on_execute(self, view: ResponseRequestView) -> None:
        """Show confirmation dialog and execute if confirmed."""
        dialog = _ExecutionConfirmDialog(
            action=view.action_label,
            target=view.target,
            parent=self,
        )
        if dialog.exec() == QDialog.DialogCode.Accepted:
            manager = self._manager_provider()
            manager.execute(view.request_id)
            self.refresh()
            self._re_select(view.request_id)

    def _re_select(self, request_id: str) -> None:
        """Re-select the given request after a refresh."""
        model = self._model
        for row_idx in range(model.rowCount()):
            row = model.row_at(row_idx)
            if row.request_id == request_id:
                proxy_idx = self._proxy.mapFromSource(
                    model.index(row_idx, 0),
                )
                if proxy_idx.isValid():
                    self._table.selectRow(proxy_idx.row())
                break

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
        while self._controls_layout.count():
            item = self._controls_layout.takeAt(0)
            widget = item.widget() if item is not None else None
            if widget is not None:
                widget.setParent(None)
        self._detail_hint.setText("Select a response request to inspect its workflow details.")
        self._detail_hint.setVisible(True)

    # -- Read-only accessors (used by tests) -------------------------------

    @property
    def source_model(self) -> RequestTableModel:
        return self._model

    @property
    def proxy_model(self) -> QSortFilterProxyModel:
        return self._proxy

    @property
    def table_view(self) -> QTableView:
        return self._table

    def column_headers(self) -> tuple[str, ...]:
        return _COLUMNS

    def row_count(self) -> int:
        return self._model.rowCount()

    def pending_count_text(self) -> str:
        return self._pending_label.text()

    def approved_count_text(self) -> str:
        return self._approved_label.text()

    def count_text(self) -> str:
        return self._count_label.text()

    def has_error(self) -> bool:
        return self._error_active

    @property
    def audit_model(self) -> AuditTableModel:
        return self._audit_model

    @property
    def audit_table_view(self) -> QTableView:
        return self._audit_table

    def audit_column_headers(self) -> tuple[str, ...]:
        return _AUDIT_COLUMNS

    def audit_row_count(self) -> int:
        return self._audit_model.rowCount()


__all__ = ["AuditTableModel", "RequestTableModel", "ResponseCenterPage"]
