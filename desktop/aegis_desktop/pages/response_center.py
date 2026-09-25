"""Response Center page: desktop-managed dry-run + approval + execution workflow.

The page presents the response workflow as a strict, staged execution pipeline:

``[ DRAFT ] ── [ DRY RUN ] ── [ PENDING APPROVAL ] ── [ EXECUTED ]``

Selecting a request renders three things: the lifecycle stepper (which stages
are done, active, locked or failed), an *Execution Preview* box showing the
deterministic dry-run outcome, and a state-dependent control block with
high-contrast buttons (blue *Run Dry Run*, amber *Approve Action*, red
*Execute Response*).  A read-only audit log of previous executions sits at the
bottom of the page.

Table + detail view of response requests.  Buttons drive the workflow states
(Dry Run, Approve, Reject, Execute).  Execution is only available for approved
BLOCK_IP requests and requires an explicit confirmation.  All workflow state
changes go through the existing :class:`ResponseWorkflowManager` — this module
never touches the firewall itself.
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
    QLayout,
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
from aegis_desktop.styles import apply_severity_style
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

# -- Response execution pipeline ---------------------------------------------

#: Stepper stages, in lifecycle order.
PIPELINE_STAGES: tuple[str, ...] = (
    "DRAFT",
    "DRY RUN",
    "PENDING APPROVAL",
    "EXECUTED",
)

#: Short guidance shown under each stage title.
_PIPELINE_HINTS: tuple[str, ...] = (
    "Request created",
    "Simulated only",
    "Analyst authorization",
    "Controlled change",
)

#: Workflow status -> index of the active (highlighted) stage.
_STATUS_STAGE: dict[str, int] = {
    "draft": 0,
    "dry_run_ready": 0,
    "dry_run_completed": 2,
    "pending_approval": 2,
    "approved": 3,
    "executed": 3,
    "execution_failed": 3,
    "rejected": 2,
    "cancelled": 2,
}

_STAGE_DONE = "done"
_STAGE_ACTIVE = "active"
_STAGE_FUTURE = "future"
_STAGE_ERROR = "error"

_STAGE_ORDER: tuple[str, ...] = (
    _STAGE_DONE,
    _STAGE_ACTIVE,
    _STAGE_FUTURE,
    _STAGE_ERROR,
)

_PREVIEW_BADGE_STATES: dict[str, str] = {
    "would_apply": "low",
    "blocked": "critical",
    "invalid": "critical",
    "not_started": "info",
}

#: Analyst-facing explanation shown under the execution preview action line.
_PREVIEW_NOTES: dict[str, str] = {
    "would_apply": (
        "Dry run complete: this change would be applied on execution. "
        "Nothing has been modified on this host yet."
    ),
    "blocked": (
        "Dry run complete: policy blocked this action. "
        "Execution is not possible for this request."
    ),
    "invalid": (
        "Dry run could not validate this action. "
        "Review the request before any further step."
    ),
    "not_started": (
        "No dry run yet — this is the planned action only. "
        "Run the dry run before requesting approval."
    ),
}

_CONTROL_HINTS: dict[str, str] = {
    "draft": (
        "Stage 1 of 4 — nothing is changed on this host until a dry run, "
        "an approval and an explicit execution step are all completed."
    ),
    "dry_run_ready": (
        "Stage 1 of 4 — run the dry run to validate the action before it "
        "can be submitted for approval."
    ),
    "dry_run_completed": (
        "Stage 2 of 4 — dry run complete. Submit the request for analyst "
        "approval; execution stays locked until it is approved."
    ),
    "pending_approval": (
        "Stage 3 of 4 — elevated intent required: approving authorizes a "
        "future firewall change but does not apply anything by itself."
    ),
    "approved": (
        "Stage 4 of 4 — approved. Executing this request modifies the local "
        "firewall and is recorded in the audit log."
    ),
    "rejected": "This request was rejected. No action will be executed.",
    "cancelled": "This request was cancelled. No action will be executed.",
    "executed": "This request was executed. See the audit log below.",
    "execution_failed": "Execution failed. No change was applied.",
}


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

        self._pipeline_card = self._build_pipeline_card()
        self._pipeline_card.setVisible(False)
        self._preview_action_text = ""
        self._preview_status_text = ""
        self._preview_note_text = ""
        layout.addWidget(self._pipeline_card)

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

        audit_heading = QLabel("AUDIT HISTORY (READ-ONLY)")
        audit_heading.setObjectName("CardTitle")

        audit_hint = QLabel(
            "Recent executions recorded in memory: what ran, the policy decision, "
            "verification result and timestamp. This log cannot be edited.",
        )
        audit_hint.setObjectName("CardHint")
        audit_hint.setWordWrap(True)

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
        audit_layout.addWidget(audit_hint)
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

        # Persistent action-control block.  It is inserted into the detail
        # layout by _render_controls() so the buttons always live next to the
        # request detail they act on, and so _clear_detail() can reuse one
        # widget instead of recreating it on every selection.
        self._controls_container = QFrame()
        self._controls_container.setObjectName("Card")
        controls_outer = QVBoxLayout(self._controls_container)
        controls_outer.setContentsMargins(14, 10, 14, 10)
        controls_outer.setSpacing(8)

        controls_heading = QLabel("ACTION CONTROLS")
        controls_heading.setObjectName("CardTitle")
        controls_outer.addWidget(controls_heading)

        self._controls_hint = QLabel("")
        self._controls_hint.setObjectName("CardHint")
        self._controls_hint.setWordWrap(True)
        controls_outer.addWidget(self._controls_hint)

        self._controls_layout = QVBoxLayout()
        self._controls_layout.setSpacing(6)
        controls_outer.addLayout(self._controls_layout)

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

    # -- Execution pipeline (stepper) --------------------------------------

    def _build_pipeline_card(self) -> QFrame:
        """Build the four-stage lifecycle stepper shown above the request table."""
        card = QFrame()
        card.setObjectName("PipelineCard")
        outer = QVBoxLayout(card)
        outer.setContentsMargins(16, 12, 16, 12)
        outer.setSpacing(8)

        head = QHBoxLayout()
        head.setSpacing(10)
        heading = QLabel("RESPONSE EXECUTION PIPELINE")
        heading.setObjectName("CardTitle")
        head.addWidget(heading)
        head.addStretch(1)

        self._pipeline_status_badge = QLabel("")
        self._pipeline_status_badge.setObjectName("PreviewStatus")
        self._pipeline_status_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        head.addWidget(self._pipeline_status_badge)
        outer.addLayout(head)

        self._pipeline_meta = QLabel("No request selected.")
        self._pipeline_meta.setObjectName("PipelineMeta")
        self._pipeline_meta.setWordWrap(True)
        outer.addWidget(self._pipeline_meta)

        stages_row = QHBoxLayout()
        stages_row.setSpacing(4)
        self._stage_frames: list[QFrame] = []
        self._stage_titles: list[QLabel] = []
        self._stage_states: list[QLabel] = []
        self._stage_hints: list[QLabel] = []
        for index, title in enumerate(PIPELINE_STAGES):
            if index:
                arrow = QLabel("➔")
                arrow.setObjectName("PipelineArrow")
                arrow.setAlignment(Qt.AlignmentFlag.AlignCenter)
                stages_row.addWidget(arrow)
            frame, title_label, state_label, hint_label = self._build_stage(index, title)
            self._stage_frames.append(frame)
            self._stage_titles.append(title_label)
            self._stage_states.append(state_label)
            self._stage_hints.append(hint_label)
            stages_row.addWidget(frame, 1)
        outer.addLayout(stages_row)
        return card

    @staticmethod
    def _build_stage(index: int, title: str) -> tuple[QFrame, QLabel, QLabel, QLabel]:
        """Create one stepper stage widget (title, state text and hint labels)."""
        frame = QFrame()
        frame.setObjectName("PipelineStage")
        frame.setProperty("stage_state", _STAGE_FUTURE)
        frame.setMinimumHeight(70)

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(2)

        title_label = QLabel(f"{index + 1}. {title}")
        title_label.setObjectName("PipelineStageTitle")
        title_label.setProperty("stage_state", _STAGE_FUTURE)
        layout.addWidget(title_label)

        state_label = QLabel("LOCKED")
        state_label.setObjectName("PipelineStageState")
        state_label.setProperty("stage_state", _STAGE_FUTURE)
        layout.addWidget(state_label)

        hint_label = QLabel("Locked")
        hint_label.setObjectName("PipelineStageHint")
        hint_label.setWordWrap(True)
        layout.addWidget(hint_label)
        return frame, title_label, state_label, hint_label

    def _render_pipeline(self, view: ResponseRequestView) -> None:
        """Render the lifecycle stepper for the selected request."""
        states = self._stage_states_for(view)
        for index, frame in enumerate(self._stage_frames):
            state = states[index]
            self._set_stage_state(frame, state)
            self._set_stage_state(self._stage_titles[index], state)
            self._set_stage_state(self._stage_states[index], state)
            self._stage_states[index].setText(self._stage_state_text(view, index, state))
            hint = self._stage_hints[index]
            if state == _STAGE_FUTURE:
                hint.setText("Locked — previous stage incomplete")
            else:
                hint.setText(_PIPELINE_HINTS[index])
            self._set_stage_state(hint, state)

        self._pipeline_meta.setText(
            f"{view.request_id}  ·  {view.action_label}  ·  {view.target}  ·  "
            f"risk {view.risk_level.upper()} ({view.risk_score})",
        )
        badge = self._pipeline_status_badge
        badge.setText(view.status.upper())
        apply_severity_style(badge, self._status_severity(view.status))
        self._pipeline_card.setVisible(True)

    @staticmethod
    def _stage_states_for(view: ResponseRequestView) -> tuple[str, str, str, str]:
        """Return the visual state (done/active/future/error) for each stage."""
        current = _STATUS_STAGE.get(view.status, 0)
        states: list[str] = []
        for index in range(len(PIPELINE_STAGES)):
            if index < current:
                states.append(_STAGE_DONE)
            elif index > current:
                states.append(_STAGE_FUTURE)
            elif view.status == "executed":
                states.append(_STAGE_DONE)
            elif view.status in ("rejected", "cancelled", "execution_failed"):
                states.append(_STAGE_ERROR)
            else:
                states.append(_STAGE_ACTIVE)
        return tuple(states)

    @staticmethod
    def _stage_state_text(view: ResponseRequestView, index: int, state: str) -> str:
        """Human-readable stage state for the selected request."""
        if state == _STAGE_FUTURE:
            return "LOCKED"
        if state == _STAGE_ERROR:
            if index == 2:
                return view.status.upper()
            return "FAILED"
        if index == 0:
            return "COMPLETE" if state == _STAGE_DONE else "CREATED"
        if index == 1:
            if state == _STAGE_DONE:
                return (view.dry_run_status or "NOT_RUN").upper()
            return "NOT RUN"
        if index == 2:
            if state == _STAGE_DONE:
                return "APPROVED"
            if view.status == "dry_run_completed":
                return "READY TO SUBMIT"
            return "AWAITING APPROVAL"
        if state == _STAGE_DONE:
            return "APPLIED"
        return "READY TO EXECUTE"

    @staticmethod
    def _status_severity(status: str) -> str:
        """Map a workflow status onto the semantic severity palette."""
        if status in ("executed",):
            return "low"
        if status in ("execution_failed", "rejected", "cancelled"):
            return "critical"
        if status in ("pending_approval", "approved", "dry_run_completed"):
            return "medium"
        return "info"

    @staticmethod
    def _set_stage_state(widget: QWidget, state: str) -> None:
        """Apply the ``stage_state`` dynamic property and repolish the widget."""
        if widget.property("stage_state") == state:
            return
        widget.setProperty("stage_state", state)
        style = widget.style()
        style.unpolish(widget)
        style.polish(widget)

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

        # Lifecycle stepper (top of page) + execution preview (first section)
        self._render_pipeline(view)
        self._detail_layout.addWidget(self._build_execution_preview(view))

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

        # Execution result (read-only record of what the executor did)
        if view.status in ("approved", "executed", "execution_failed"):
            exec_frame, exec_form = self._build_section("RESPONSE EXECUTION")
            self._detail_layout.addWidget(exec_frame)
            self._add_field(exec_form, "Action", view.action_label)
            self._add_field(exec_form, "Target", view.target)
            if view.status == "approved":
                self._add_field(exec_form, "Approval", "APPROVED")
                self._add_field(exec_form, "Execution", "READY")
            elif view.status == "executed":
                self._add_field(exec_form, "Status", "APPLIED")
                self._add_field(exec_form, "Firewall", view.execution_adapter or MISSING)
                verified = "VERIFIED" if view.execution_verified else "NOT VERIFIED"
                self._add_field(exec_form, "Verification", verified)
                changed = "YES" if view.execution_changed else "NO"
                self._add_field(exec_form, "Changed", changed)
                if view.execution_message:
                    self._add_field(exec_form, "Message", view.execution_message)
            else:
                self._add_field(exec_form, "Status", "FAILED")
                if view.execution_message:
                    self._add_field(exec_form, "Reason", view.execution_message)
                self._add_field(exec_form, "Verification", "NOT VERIFIED")

        # Controls (state-dependent) — kept above the trailing stretch so the
        # analyst never has to scroll to reach the next action.
        self._render_controls(view)

        self._detail_layout.addStretch(1)

    # -- Execution preview --------------------------------------------------

    @staticmethod
    def _action_code(action_label: str) -> str:
        """Map a display label (``Block IP``) onto its action code (``BLOCK_IP``)."""
        code = (action_label or "").strip().replace(" ", "_").upper()
        return code or MISSING

    @staticmethod
    def _adapter_label(view: ResponseRequestView) -> str:
        """Adapter that would perform this action (name after execution)."""
        if view.execution_adapter:
            return view.execution_adapter
        if ResponseCenterPage._action_code(view.action_label) == "BLOCK_IP":
            try:
                from aegis_response_engine.firewall.windows import WindowsFirewallAdapter

                return WindowsFirewallAdapter.__name__
            except Exception:  # pragma: no cover - engine always installed
                return "WindowsFirewallAdapter"
        return "NO ADAPTER"

    def _build_execution_preview(self, view: ResponseRequestView) -> QFrame:
        """Build the Execution Preview box (dry-run outcome before approval)."""
        frame = QFrame()
        frame.setObjectName("Card")
        outer = QVBoxLayout(frame)
        outer.setContentsMargins(14, 10, 14, 10)
        outer.setSpacing(6)

        heading = QLabel("EXECUTION PREVIEW")
        heading.setObjectName("CardTitle")
        outer.addWidget(heading)

        dry_status = (view.dry_run_status or "not_started").strip().lower()
        if dry_status not in _PREVIEW_BADGE_STATES:
            dry_status = "not_started"

        status_row = QHBoxLayout()
        status_row.setSpacing(10)
        badge = QLabel(dry_status.upper())
        badge.setObjectName("PreviewStatus")
        apply_severity_style(badge, _PREVIEW_BADGE_STATES[dry_status])
        status_row.addWidget(badge)

        mode = QLabel("SIMULATION ONLY" if dry_status != "not_started" else "PLANNED ACTION")
        mode.setObjectName("CardHint")
        status_row.addWidget(mode)
        status_row.addStretch(1)
        outer.addLayout(status_row)

        action_text = (
            f"Action: {self._action_code(view.action_label)} {view.target} "
            f"using {self._adapter_label(view)}"
        )
        action = QLabel(action_text)
        action.setObjectName("PreviewAction")
        action.setWordWrap(True)
        action.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        outer.addWidget(action)
        self._preview_action_text = action_text

        note = QLabel(_PREVIEW_NOTES[dry_status])
        note.setObjectName("PreviewNote")
        note.setWordWrap(True)
        outer.addWidget(note)
        self._preview_status_text = badge.text()
        self._preview_note_text = note.text()

        detail = QLabel(
            f"Policy: {(view.policy_decision or MISSING).upper()}"
            f"{f' · v{view.policy_version}' if view.policy_version else ''}  ·  "
            f"Risk: {view.risk_level.upper()} ({view.risk_score})",
        )
        detail.setObjectName("CardHint")
        detail.setWordWrap(True)
        outer.addWidget(detail)
        return frame

    def _render_controls(self, view: ResponseRequestView) -> None:
        """Add the state-dependent, high-contrast action controls."""
        status = view.status
        dry_status = (view.dry_run_status or "").strip().lower()
        hint = _CONTROL_HINTS.get(status, "")
        if status == "dry_run_completed" and dry_status != "would_apply":
            hint = (
                f"Dry run result is {dry_status.upper() or 'UNKNOWN'} — policy does "
                "not permit this action, so it cannot be submitted for approval."
            )
        self._controls_hint.setText(hint)

        if status in ("draft", "dry_run_ready"):
            self._controls_layout.addWidget(
                self._make_button(
                    "Run Dry Run",
                    "PrimaryButton",
                    lambda rid=view.request_id: self._on_dry_run(rid),
                ),
            )

        elif status == "dry_run_completed":
            row = QHBoxLayout()
            row.setSpacing(8)
            if dry_status == "would_apply":
                row.addWidget(
                    self._make_button(
                        "Submit for Approval",
                        "WarningButton",
                        lambda rid=view.request_id: self._on_submit_approval(rid),
                    ),
                )
            row.addWidget(
                self._make_button(
                    "Cancel Request",
                    "DangerButton",
                    lambda rid=view.request_id: self._on_cancel(rid),
                ),
            )
            row.addStretch(1)
            self._controls_layout.addLayout(row)

        elif status == "pending_approval":
            row = QHBoxLayout()
            row.setSpacing(8)
            row.addWidget(
                self._make_button(
                    "Approve Action",
                    "WarningButton",
                    lambda rid=view.request_id: self._on_approve(rid),
                ),
            )
            row.addWidget(
                self._make_button(
                    "Reject",
                    "DangerButton",
                    lambda rid=view.request_id: self._on_reject(rid),
                ),
            )
            row.addStretch(1)
            self._controls_layout.addLayout(row)

        elif status == "approved":
            if view.action_label == "Block IP":
                row = QHBoxLayout()
                row.setSpacing(8)
                row.addWidget(
                    self._make_button(
                        "Execute Response",
                        "CriticalButton",
                        lambda v=view: self._on_execute(v),
                    ),
                )
                row.addStretch(1)
                self._controls_layout.addLayout(row)
            else:
                info = QLabel("APPROVED\n\nExecution:\nNOT AVAILABLE IN THIS VERSION")
                info.setObjectName("FieldValue")
                info.setWordWrap(True)
                self._controls_layout.addWidget(info)

        elif status == "executed":
            info = QLabel(
                f"EXECUTED — {view.execution_adapter or 'Firewall'} · "
                f"{'VERIFIED' if view.execution_verified else 'NOT VERIFIED'} · "
                f"changed {'YES' if view.execution_changed else 'NO'}",
            )
            info.setObjectName("FieldValue")
            info.setWordWrap(True)
            self._controls_layout.addWidget(info)

        elif status == "execution_failed":
            info = QLabel(
                f"EXECUTION FAILED — {view.execution_message or 'no detail available'}",
            )
            info.setObjectName("FieldValue")
            info.setWordWrap(True)
            self._controls_layout.addWidget(info)

        elif status in ("rejected", "cancelled"):
            info = QLabel(f"{status.upper()} — this request will not be executed.")
            info.setObjectName("FieldValue")
            info.setWordWrap(True)
            self._controls_layout.addWidget(info)

        self._detail_layout.addWidget(self._controls_container)

    @staticmethod
    def _make_button(
        text: str,
        object_name: str,
        slot: Callable[[], None],
    ) -> QPushButton:
        """Create a state-coloured action button."""
        button = QPushButton(text)
        button.setObjectName(object_name)
        button.clicked.connect(lambda checked=False, cb=slot: cb())
        return button

    def _on_dry_run(self, request_id: str) -> None:
        """Run the dry run and, when it would apply, submit for approval."""
        manager = self._manager_provider()
        manager.run_dry_run(request_id)
        view = None
        getter = getattr(manager, "get", None)
        if getter is not None:
            view = getter(request_id)
        if view is None or view.dry_run_status == "would_apply":
            manager.request_approval(request_id)
        self.refresh()
        self._re_select(request_id)

    def _on_submit_approval(self, request_id: str) -> None:
        """Move a completed dry run into the approval queue."""
        manager = self._manager_provider()
        manager.request_approval(request_id)
        self.refresh()
        self._re_select(request_id)

    def _on_cancel(self, request_id: str) -> None:
        """Cancel a request that has not been approved yet."""
        manager = self._manager_provider()
        manager.cancel(request_id)
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
        self._empty_layout(self._detail_layout)
        self._empty_layout(self._controls_layout)
        pipeline = getattr(self, "_pipeline_card", None)
        if pipeline is not None:
            pipeline.setVisible(False)
        self._detail_hint.setText("Select a response request to inspect its workflow details.")
        self._detail_hint.setVisible(True)

    @staticmethod
    def _empty_layout(layout: QLayout) -> None:
        """Detach every widget (also inside nested row layouts) from ``layout``."""
        while layout.count():
            item = layout.takeAt(0)
            if item is None:
                break
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                continue
            nested = item.layout()
            if nested is not None:
                ResponseCenterPage._empty_layout(nested)

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

    def pipeline_shown(self) -> bool:
        """Whether the lifecycle stepper is currently displayed."""
        return not self._pipeline_card.isHidden()

    def pipeline_stage_titles(self) -> tuple[str, ...]:
        return tuple(label.text() for label in self._stage_titles)

    def pipeline_stage_states(self) -> tuple[str, ...]:
        """Visual state (done/active/future/error) for each stepper stage."""
        return tuple(str(frame.property("stage_state") or "") for frame in self._stage_frames)

    def pipeline_stage_texts(self) -> tuple[str, ...]:
        """State text (CREATED / WOULD_APPLY / AWAITING APPROVAL ...) per stage."""
        return tuple(label.text() for label in self._stage_states)

    def pipeline_meta_text(self) -> str:
        return self._pipeline_meta.text()

    def pipeline_status_text(self) -> str:
        return self._pipeline_status_badge.text()

    def preview_action_text(self) -> str:
        """The execution-preview action line for the selected request."""
        return self._preview_action_text

    def preview_status_text(self) -> str:
        """Dry-run badge text (``WOULD_APPLY``, ``BLOCKED``, ``NOT_STARTED``...)."""
        return self._preview_status_text

    def preview_note_text(self) -> str:
        """Analyst-facing note shown under the preview action line."""
        return self._preview_note_text

    def control_hint_text(self) -> str:
        return self._controls_hint.text()

    def control_button_texts(self) -> tuple[str, ...]:
        """Labels of the buttons currently offered for the selected request."""
        buttons = self._controls_container.findChildren(QPushButton)
        return tuple(button.text() for button in buttons)


__all__ = [
    "PIPELINE_STAGES",
    "AuditTableModel",
    "RequestTableModel",
    "ResponseCenterPage",
]
