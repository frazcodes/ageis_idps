"""Focused tests for the Response Center execution pipeline (Step 37).

Covers the four-stage lifecycle stepper, the execution-preview box and the
state-dependent high-contrast controls of the Response Center page.  Nothing
here touches a firewall, host, process or file: every state is rendered from a
plain read-only :class:`ResponseRequestView`.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest

pytest.importorskip("PySide6", reason="desktop extra not installed")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QPushButton, QTableView

from aegis_desktop.app import create_application
from aegis_desktop.pages.response_center import (
    PIPELINE_STAGES,
    ResponseCenterPage,
)
from aegis_desktop.services.response_workflow import (
    ResponseRequestView,
    ResponseWorkflowManager,
    get_audit_history,
)

_TS = datetime(2026, 6, 1, 10, 0, 0, tzinfo=UTC)


def _view(
    status: str = "draft",
    *,
    dry_run_status: str = "not_started",
    action_label: str = "Block IP",
    target: str = "192.168.1.55",
) -> ResponseRequestView:
    return ResponseRequestView(
        request_id="RR-pipeline",
        action_label=action_label,
        target=target,
        risk_level="high",
        risk_score=82,
        policy_decision="requires_approval",
        policy_version="1.0.0",
        dry_run_status=dry_run_status,
        approval_status=status,
        status=status,
        created_at=_TS,
        updated_at=_TS,
        source_finding_ids=("AEGIS-NET-007:flow-1",),
        incident_id="INC-9",
        reason="Lateral movement observed",
        rejection_reason=None,
    )


def _page() -> ResponseCenterPage:
    app = create_application([])
    assert app is not None
    manager = ResponseWorkflowManager()
    page = ResponseCenterPage(manager_provider=lambda: manager)
    page.refresh()
    return page


# --- 1. Pipeline is hidden until a request is selected ----------------------


def test_pipeline_hidden_without_selection() -> None:
    page = _page()
    page._clear_detail()
    assert page.pipeline_shown() is False


# --- 2. Stage titles are the four lifecycle stages --------------------------


def test_pipeline_stage_titles() -> None:
    page = _page()
    assert page.pipeline_stage_titles() == (
        "1. DRAFT",
        "2. DRY RUN",
        "3. PENDING APPROVAL",
        "4. EXECUTED",
    )
    assert PIPELINE_STAGES == ("DRAFT", "DRY RUN", "PENDING APPROVAL", "EXECUTED")


# --- 3. Stage states per workflow status ------------------------------------


@pytest.mark.parametrize(
    ("status", "dry_run", "expected"),
    [
        ("draft", "not_started", ("active", "future", "future", "future")),
        ("dry_run_completed", "would_apply", ("done", "done", "active", "future")),
        ("pending_approval", "would_apply", ("done", "done", "active", "future")),
        ("approved", "would_apply", ("done", "done", "done", "active")),
        ("executed", "would_apply", ("done", "done", "done", "done")),
        ("execution_failed", "would_apply", ("done", "done", "done", "error")),
        ("rejected", "would_apply", ("done", "done", "error", "future")),
    ],
)
def test_pipeline_stage_states(status: str, dry_run: str, expected: tuple[str, ...]) -> None:
    page = _page()
    page._render_detail(_view(status, dry_run_status=dry_run))
    assert page.pipeline_shown() is True
    assert page.pipeline_stage_states() == expected
    assert page.pipeline_status_text() == status.upper()


# --- 4. Future stages are visibly locked ------------------------------------


def test_future_stages_are_locked() -> None:
    page = _page()
    page._render_detail(_view("draft"))
    texts = page.pipeline_stage_texts()
    assert texts[0] == "CREATED"
    assert texts[1:] == ("LOCKED", "LOCKED", "LOCKED")


def test_approved_pipeline_shows_ready_to_execute() -> None:
    page = _page()
    page._render_detail(_view("approved", dry_run_status="would_apply"))
    assert page.pipeline_stage_texts() == (
        "COMPLETE",
        "WOULD_APPLY",
        "APPROVED",
        "READY TO EXECUTE",
    )


# --- 5. Execution preview ---------------------------------------------------


def test_execution_preview_action_line() -> None:
    page = _page()
    page._render_detail(_view("draft"))
    preview = page.preview_action_text()
    assert preview == "Action: BLOCK_IP 192.168.1.55 using WindowsFirewallAdapter"


def test_execution_preview_shows_would_apply() -> None:
    page = _page()
    page._render_detail(_view("pending_approval", dry_run_status="would_apply"))
    assert "WOULD_APPLY" in page.preview_status_text()
    assert "Nothing has been modified" in page.preview_note_text()


def test_execution_preview_blocked_is_flagged() -> None:
    page = _page()
    page._render_detail(_view("dry_run_completed", dry_run_status="blocked"))
    assert "BLOCKED" in page.preview_status_text()
    assert "Execution is not possible" in page.preview_note_text()


# --- 6. High-contrast state controls ---------------------------------------


def _buttons(page: ResponseCenterPage) -> dict[str, str]:
    """Map button label -> QSS object name for the current control block."""
    return {
        button.text(): button.objectName()
        for button in page._controls_container.findChildren(QPushButton)
    }


def test_draft_control_is_blue_run_dry_run() -> None:
    page = _page()
    page._render_detail(_view("draft"))
    assert _buttons(page) == {"Run Dry Run": "PrimaryButton"}


def test_pending_control_is_amber_approve() -> None:
    page = _page()
    page._render_detail(_view("pending_approval", dry_run_status="would_apply"))
    buttons = _buttons(page)
    assert buttons["Approve Action"] == "WarningButton"
    assert buttons["Reject"] == "DangerButton"


def test_approved_control_is_red_execute() -> None:
    page = _page()
    page._render_detail(_view("approved", dry_run_status="would_apply"))
    buttons = _buttons(page)
    assert buttons == {"Execute Response": "CriticalButton"}


def test_terminal_states_offer_no_actions() -> None:
    for status in ("executed", "execution_failed", "rejected", "cancelled"):
        page = _page()
        page._render_detail(_view(status, dry_run_status="would_apply"))
        assert _buttons(page) == {}, status


# --- 7. Execute button lives inside the detail layout -----------------------


def test_execute_button_is_reachable_from_detail_layout() -> None:
    page = _page()
    page._render_detail(_view("approved", dry_run_status="would_apply"))
    found = False
    for index in range(page._detail_layout.count()):
        item = page._detail_layout.itemAt(index)
        widget = item.widget() if item is not None else None
        if widget is None:
            continue
        for button in widget.findChildren(QPushButton):
            if "Execute" in button.text():
                found = True
    assert found is True


# --- 8. Audit log stays read-only at the bottom -----------------------------


def test_audit_log_is_read_only() -> None:
    page = _page()
    audit = page.audit_table_view
    assert isinstance(audit, QTableView)
    assert audit.editTriggers() == QTableView.EditTrigger.NoEditTriggers
    assert page.audit_row_count() == len(get_audit_history().all_records())
    assert page.audit_column_headers()[0] == "Audit ID"
    assert page.audit_column_headers()[-1] == "Time"


# --- 9. Re-rendering the same request does not duplicate controls -----------


def test_rerender_does_not_duplicate_controls() -> None:
    page = _page()
    view = _view("pending_approval", dry_run_status="would_apply")
    page._render_detail(view)
    page._render_detail(view)
    page._render_detail(view)
    assert _buttons(page) == {"Approve Action": "WarningButton", "Reject": "DangerButton"}
    assert page._detail_layout.count() >= 3
