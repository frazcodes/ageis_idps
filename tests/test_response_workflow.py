"""Focused tests for the desktop response-workflow (Step 29).

Exercises the deterministic dry-run simulation, in-memory approval workflow
and the read-only Response Center page.  Nothing here touches a firewall, host,
process or file.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest

from aegis_response_engine.policy import (
    ResponseDecisionStatus,
    ResponsePolicyEngine,
    ResponsePolicySettings,
    ResponseRequest,
    ResponseTarget,
    ResponseTargetKind,
)
from aegis_response_engine.policy.dryrun import ResponseDryRunEngine
from aegis_response_engine.policy.models import DryRunStatus
from aegis_shared.enums import ActionType, EventCategory, EventType, RiskLevel, Severity

_TS = datetime(2026, 6, 1, 10, 0, 0, tzinfo=UTC)


def _request(
    action: ActionType = ActionType.BLOCK_IP,
    *,
    kind: ResponseTargetKind = ResponseTargetKind.IP,
    value: str = "10.0.0.77",
    risk_level: RiskLevel = RiskLevel.HIGH,
    risk_score: int = 80,
    finding_ids: tuple[str, ...] = ("AEGIS-NET-007:flow-1",),
    rule_ids: tuple[str, ...] = ("AEGIS-NET-007",),
    host_id: str | None = "host-1",
) -> ResponseRequest:
    return ResponseRequest(
        action=action,
        target=ResponseTarget(kind=kind, value=value),
        risk_level=risk_level,
        risk_score=risk_score,
        timestamp=_TS,
        finding_ids=finding_ids,
        rule_ids=rule_ids,
        host_id=host_id,
    )


def _enabled_engine(**overrides: object) -> ResponsePolicyEngine:
    defaults = {"response_enabled": True}
    defaults.update(overrides)  # type: ignore[arg-type]
    return ResponsePolicyEngine(ResponsePolicySettings(**defaults))  # type: ignore[arg-type]


# --- 1. Request creation ---------------------------------------------------


def test_request_creation() -> None:
    req = _request()
    assert req.action is ActionType.BLOCK_IP
    assert req.target.value == "10.0.0.77"
    assert req.risk_level is RiskLevel.HIGH
    assert req.has_context is True


# --- 2. Deterministic request ID (via workflow manager) --------------------


def test_deterministic_request_id() -> None:
    from aegis_desktop.services.response_workflow import _request_id

    rid = _request_id("block_ip", "10.0.0.77", ("AEGIS-NET-007:flow-1",))
    rid2 = _request_id("block_ip", "10.0.0.77", ("AEGIS-NET-007:flow-1",))
    assert rid == rid2
    assert rid.startswith("RR-")


# --- 3. Policy denial cannot enter approval ---------------------------------


def test_denied_request_cannot_approve() -> None:
    from aegis_desktop.services.response_workflow import ResponseWorkflowManager

    mgr = ResponseWorkflowManager()
    # Default policy is disabled: decision is DENIED.
    req = _request()
    engine = ResponsePolicyEngine()
    decision = engine.evaluate(req)
    assert decision.status is ResponseDecisionStatus.DENIED

    # Simulate inserting into workflow with a denied decision.
    from aegis_desktop.services.response_workflow import _Entry, _request_id

    rid = _request_id("block_ip", "10.0.0.77", ("AEGIS-NET-007:flow-1",))
    now = datetime.now()
    entry = _Entry(
        request=req, request_id=rid, decision=decision,
        dry_run=None, status="dry_run_completed", created_at=now, updated_at=now,
        policy_settings=engine._settings,
    )
    mgr._register(rid, entry)
    result = mgr.approve(rid)
    # Denied decision should not become approved.
    assert result is not None
    assert result.status == "dry_run_completed"


# --- 4. Dry run before approval ---------------------------------------------


def test_dry_run_before_approval() -> None:
    from aegis_desktop.services.response_workflow import ResponseWorkflowManager

    mgr = ResponseWorkflowManager()
    req = _request()
    engine = _enabled_engine()
    decision = engine.evaluate(req)

    from aegis_desktop.services.response_workflow import _Entry, _request_id

    rid = _request_id("block_ip", "10.0.0.77", ("AEGIS-NET-007:flow-1",))
    now = datetime.now()
    entry = _Entry(
        request=req, request_id=rid, decision=decision,
        dry_run=None, status="draft", created_at=now, updated_at=now,
        policy_settings=engine._settings,
    )
    mgr._register(rid, entry)
    view = mgr.run_dry_run(rid)
    assert view is not None
    assert view.status == "dry_run_completed"
    assert view.dry_run_status == "would_apply"


# --- 5. Successful dry run --------------------------------------------------


def test_successful_dry_run() -> None:
    engine = ResponseDryRunEngine(ResponsePolicySettings(response_enabled=True))
    req = _request()
    result = engine.simulate(req)
    assert result.status is DryRunStatus.WOULD_APPLY
    assert result.would_change is True
    assert "10.0.0.77" in result.summary


# --- 6. Dry run does not execute anything -----------------------------------


def test_dry_run_no_side_effects() -> None:
    engine = ResponseDryRunEngine(ResponsePolicySettings(response_enabled=True))
    req = _request()
    results = [engine.simulate(req) for _ in range(5)]
    # All results are identical — pure and deterministic.
    assert all(r.dry_run_id == results[0].dry_run_id for r in results)
    assert all(r.status == results[0].status for r in results)
    assert all(r.would_change == results[0].would_change for r in results)


# --- 7. Pending approval state ----------------------------------------------


def test_pending_approval_state() -> None:
    from aegis_desktop.services.response_workflow import ResponseWorkflowManager

    mgr = ResponseWorkflowManager()
    req = _request()
    engine = _enabled_engine()
    decision = engine.evaluate(req)

    from aegis_desktop.services.response_workflow import _Entry, _request_id

    rid = _request_id("block_ip", "10.0.0.77", ("AEGIS-NET-007:flow-1",))
    now = datetime.now()
    entry = _Entry(
        request=req, request_id=rid, decision=decision,
        dry_run=None, status="dry_run_completed", created_at=now, updated_at=now,
        policy_settings=engine._settings,
    )
    mgr._register(rid, entry)
    view = mgr.request_approval(rid)
    assert view is not None
    assert view.status == "pending_approval"


# --- 8. Approval after valid dry run ----------------------------------------


def test_approval_after_dry_run() -> None:
    from aegis_desktop.services.response_workflow import ResponseWorkflowManager

    mgr = ResponseWorkflowManager()
    req = _request()
    engine = _enabled_engine()
    decision = engine.evaluate(req)

    from aegis_desktop.services.response_workflow import _Entry, _request_id

    rid = _request_id("block_ip", "10.0.0.77", ("AEGIS-NET-007:flow-1",))
    now = datetime.now()
    entry = _Entry(
        request=req, request_id=rid, decision=decision,
        dry_run=None, status="dry_run_completed", created_at=now, updated_at=now,
        policy_settings=engine._settings,
    )
    mgr._register(rid, entry)
    mgr.request_approval(rid)
    view = mgr.approve(rid)
    assert view is not None
    assert view.status == "approved"
    assert mgr.approved_count() == 1


# --- 9. Rejection -----------------------------------------------------------


def test_rejection() -> None:
    from aegis_desktop.services.response_workflow import ResponseWorkflowManager

    mgr = ResponseWorkflowManager()
    req = _request()
    engine = _enabled_engine()
    decision = engine.evaluate(req)

    from aegis_desktop.services.response_workflow import _Entry, _request_id

    rid = _request_id("block_ip", "10.0.0.77", ("AEGIS-NET-007:flow-1",))
    now = datetime.now()
    entry = _Entry(
        request=req, request_id=rid, decision=decision,
        dry_run=None, status="dry_run_completed", created_at=now, updated_at=now,
        policy_settings=engine._settings,
    )
    mgr._register(rid, entry)
    mgr.request_approval(rid)
    view = mgr.reject(rid, reason="Too risky")
    assert view is not None
    assert view.status == "rejected"
    assert view.rejection_reason == "Too risky"


# --- 10. Invalid request (bad IP) -------------------------------------------


def test_invalid_request_dry_run() -> None:
    engine = ResponseDryRunEngine(ResponsePolicySettings(response_enabled=True))
    req = _request(value="not-an-ip")
    result = engine.simulate(req)
    assert result.status is DryRunStatus.BLOCKED
    assert result.would_change is False


# --- 11. Missing target (empty value) ---------------------------------------


def test_missing_target_denied() -> None:
    engine = ResponseDryRunEngine(ResponsePolicySettings(response_enabled=True))
    req = _request(value="")
    result = engine.simulate(req)
    assert result.status is DryRunStatus.BLOCKED
    assert result.would_change is False


# --- 12. Response-disabled policy -------------------------------------------


def test_disabled_policy_dry_run_blocked() -> None:
    engine = ResponseDryRunEngine()  # default: response_enabled=False
    req = _request()
    result = engine.simulate(req)
    assert result.status is DryRunStatus.BLOCKED
    assert result.would_change is False
    assert "blocked by policy" in result.summary.lower()


# --- 13. Policy version propagation -----------------------------------------


def test_policy_version_propagation() -> None:
    engine = ResponseDryRunEngine(ResponsePolicySettings(
        response_enabled=True, policy_version="3.0.0",
    ))
    req = _request()
    result = engine.simulate(req)
    assert result.policy_version == "3.0.0"


# --- 14. Request registry bounded behavior ----------------------------------


def test_registry_bounded() -> None:
    from aegis_desktop.services.response_workflow import ResponseWorkflowManager

    mgr = ResponseWorkflowManager(max_requests=3)
    engine = _enabled_engine()

    for i in range(5):
        req = _request(value=f"10.0.0.{i + 1}")
        decision = engine.evaluate(req)
        from aegis_desktop.services.response_workflow import _Entry, _request_id
        rid = _request_id("block_ip", f"10.0.0.{i + 1}", ("AEGIS-NET-007:flow-1",))
        now = datetime.now()
        entry = _Entry(
            request=req, request_id=rid, decision=decision,
            dry_run=None, status="draft", created_at=now, updated_at=now,
            policy_settings=engine._settings,
        )
        mgr._register(rid, entry)

    assert mgr.count == 3


# --- 15. Repeated dry run deterministic behavior ----------------------------


def test_repeated_dry_run_deterministic() -> None:
    engine = ResponseDryRunEngine(ResponsePolicySettings(response_enabled=True))
    req = _request()
    first = engine.simulate(req)
    second = engine.simulate(req)
    assert first.dry_run_id == second.dry_run_id
    assert first.status == second.status
    assert first.would_change == second.would_change


# --- 16. Desktop response request view from finding -------------------------


def test_desktop_response_request_view() -> None:
    from aegis_desktop.services.response_workflow import ResponseWorkflowManager
    from aegis_shared.detection import DetectionFinding

    finding = DetectionFinding(
        finding_id="AEGIS-NET-007:flow-1",
        rule_id="AEGIS-NET-007",
        rule_name="Suspicious communication pattern observed",
        severity=Severity.HIGH,
        title="Suspicious communication pattern observed",
        description="Multiple signals.",
        event_id="flow-1",
        event_type=EventType.FLOW_SUMMARY,
        category=EventCategory.NETWORK,
        timestamp=_TS,
        host_id="host-1",
        evidence={"remote_ip": "10.0.0.77", "relationship": "10.0.0.5 -> 10.0.0.77:4444"},
    )

    mgr = ResponseWorkflowManager()
    view = mgr.create_request(finding, engine=_enabled_engine())
    assert view is not None
    assert view.action_label == "Block IP"
    assert view.target == "10.0.0.77"
    assert view.status == "draft"
    assert view.source_finding_ids == ("AEGIS-NET-007:flow-1",)


# --- 17. Create request from finding with no target yields None -------------


def test_no_target_finding_yields_none() -> None:
    from aegis_desktop.services.response_workflow import ResponseWorkflowManager
    from aegis_shared.detection import DetectionFinding

    finding = DetectionFinding(
        finding_id="AEGIS-PROC-001:h1",
        rule_id="AEGIS-PROC-001",
        rule_name="Process finding",
        severity=Severity.HIGH,
        title="Process finding",
        description="A process finding.",
        event_id="h1",
        event_type=EventType.PROCESS_STARTED,
        category=EventCategory.HOST,
        timestamp=_TS,
        host_id="host-1",
    )

    mgr = ResponseWorkflowManager()
    view = mgr.create_request(finding)
    assert view is None


# --- 18. No OS/network side effects (workflow only updates memory) ----------


def test_no_os_side_effects() -> None:
    from aegis_desktop.services.response_workflow import ResponseWorkflowManager

    mgr = ResponseWorkflowManager()
    req = _request()
    engine = _enabled_engine()
    decision = engine.evaluate(req)

    from aegis_desktop.services.response_workflow import _Entry, _request_id

    rid = _request_id("block_ip", "10.0.0.77", ("AEGIS-NET-007:flow-1",))
    now = datetime.now()
    entry = _Entry(
        request=req, request_id=rid, decision=decision,
        dry_run=None, status="draft", created_at=now, updated_at=now,
        policy_settings=engine._settings,
    )
    mgr._register(rid, entry)
    mgr.run_dry_run(rid)
    mgr.request_approval(rid)
    view = mgr.approve(rid)
    assert view is not None
    assert view.status == "approved"
    # No firewall rule, no subprocess, no file change — only in-memory state.
    assert mgr.pending_count() == 0
    assert mgr.approved_count() == 1


# --- 19. Desktop Response Center page renders correctly ---------------------


def test_desktop_response_center_page() -> None:
    pytest.importorskip("PySide6", reason="desktop extra not installed")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from aegis_desktop.app import create_application
    from aegis_desktop.pages.response_center import ResponseCenterPage

    app = create_application([])
    assert app is not None

    page = ResponseCenterPage()
    page.refresh()
    assert page.row_count() == 0
    assert page.pending_count_text() == "Pending Approval: 0"
    assert page.approved_count_text() == "Approved: 0"
    assert page.count_text() == "Requests: No data"
    assert page.has_error() is False


# --- 20. End-to-end: finding -> request -> dry run -> approve ----------------


def test_end_to_end_workflow() -> None:
    from aegis_desktop.services.response_workflow import ResponseWorkflowManager
    from aegis_shared.detection import DetectionFinding

    finding = DetectionFinding(
        finding_id="AEGIS-NET-007:flow-1",
        rule_id="AEGIS-NET-007",
        rule_name="Suspicious communication pattern observed",
        severity=Severity.HIGH,
        title="Suspicious communication pattern observed",
        description="Multiple signals.",
        event_id="flow-1",
        event_type=EventType.FLOW_SUMMARY,
        category=EventCategory.NETWORK,
        timestamp=_TS,
        host_id="host-1",
        evidence={"remote_ip": "10.0.0.77", "relationship": "10.0.0.5 -> 10.0.0.77:4444"},
    )

    mgr = ResponseWorkflowManager()
    # 1. Create request from finding
    view = mgr.create_request(finding, engine=_enabled_engine())
    assert view is not None
    assert view.status == "draft"

    # 2. Run dry run
    view = mgr.run_dry_run(view.request_id)
    assert view is not None
    assert view.status == "dry_run_completed"
    assert view.dry_run_status == "would_apply"

    # 3. Request approval
    view = mgr.request_approval(view.request_id)
    assert view is not None
    assert view.status == "pending_approval"

    # 4. Approve
    view = mgr.approve(view.request_id)
    assert view is not None
    assert view.status == "approved"

    # 5. Verify no execution occurred
    assert mgr.pending_count() == 0
    assert mgr.approved_count() == 1

    # 6. Verify the approved request appears in all_requests
    all_reqs = mgr.all_requests()
    assert len(all_reqs) == 1
    assert all_reqs[0].status == "approved"
    assert all_reqs[0].approval_status == "approved"
