"""Focused tests for the response audit trail (Step 31).

Exercises ResponseAuditRecord, ResponseAuditHistory, integration with the
desktop workflow manager, and the Response Center audit table.  Uses mocks
for OS-level firewall operations so tests never depend on the real firewall.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from aegis_response_engine.audit.history import MAX_AUDIT_RECORDS, ResponseAuditHistory
from aegis_response_engine.audit.models import ResponseAuditRecord, VerificationStatus
from aegis_response_engine.executors.executor import ResponseExecutor
from aegis_response_engine.firewall.base import FirewallAdapter
from aegis_response_engine.firewall.models import FirewallActionResult, FirewallActionStatus
from aegis_response_engine.policy.models import (
    ResponseRequest,
    ResponseTarget,
    ResponseTargetKind,
)
from aegis_shared.enums import ActionType, RiskLevel

_TS = datetime(2026, 6, 1, 10, 0, 0, tzinfo=UTC)


def _block_request(
    ip: str = "10.0.0.77",
    *,
    finding_ids: tuple[str, ...] = ("AEGIS-NET-007:flow-1",),
) -> ResponseRequest:
    return ResponseRequest(
        action=ActionType.BLOCK_IP,
        target=ResponseTarget(kind=ResponseTargetKind.IP, value=ip),
        risk_level=RiskLevel.HIGH,
        risk_score=80,
        timestamp=_TS,
        finding_ids=finding_ids,
        rule_ids=("AEGIS-NET-007",),
        host_id="host-1",
    )


def _audit_record(
    request_id: str = "RR-test",
    *,
    audit_id: str = "AR-001",
    action: str = "block_ip",
    target: str = "10.0.0.77",
    execution_status: str = "applied",
) -> ResponseAuditRecord:
    return ResponseAuditRecord(
        audit_id=audit_id,
        request_id=request_id,
        action=action,
        target=target,
        source_type="detection",
        source_id="AEGIS-NET-007:flow-1",
        policy_decision="requires_approval",
        workflow_status_before="approved",
        workflow_status_after="executed",
        dry_run_status="would_apply",
        execution_status=execution_status,
        verification_status=VerificationStatus.VERIFIED,
        adapter="Windows Firewall",
        changed=True,
        message="Rule created",
        timestamp=_TS,
    )


# --- 1. ResponseAuditRecord is frozen ---------------------------------------


def test_audit_record_frozen() -> None:
    record = _audit_record()
    with pytest.raises(AttributeError):
        record.audit_id = "AR-changed"  # type: ignore[misc]


# --- 2. ResponseAuditRecord field values -------------------------------------


def test_audit_record_fields() -> None:
    record = _audit_record()
    assert record.audit_id == "AR-001"
    assert record.request_id == "RR-test"
    assert record.action == "block_ip"
    assert record.target == "10.0.0.77"
    assert record.source_type == "detection"
    assert record.execution_status == "applied"
    assert record.verification_status == VerificationStatus.VERIFIED
    assert record.changed is True
    assert record.adapter == "Windows Firewall"
    assert record.message == "Rule created"
    assert record.timestamp == _TS


# --- 3. VerificationStatus enum values --------------------------------------


def test_verification_status_values() -> None:
    assert VerificationStatus.VERIFIED == "verified"
    assert VerificationStatus.NOT_VERIFIED == "not_verified"
    assert VerificationStatus.VERIFICATION_FAILED == "verification_failed"
    assert VerificationStatus.NOT_APPLICABLE == "not_applicable"


# --- 4. ResponseAuditHistory empty store -------------------------------------


def test_audit_history_empty() -> None:
    history = ResponseAuditHistory()
    assert history.count == 0
    assert history.all_records() == ()


# --- 5. ResponseAuditHistory add single record -------------------------------


def test_audit_history_add_single() -> None:
    history = ResponseAuditHistory()
    record = _audit_record()
    history.add(record)
    assert history.count == 1
    all_records = history.all_records()
    assert len(all_records) == 1
    assert all_records[0] is record


# --- 6. ResponseAuditHistory newest first ordering ---------------------------


def test_audit_history_newest_first() -> None:
    history = ResponseAuditHistory()
    r1 = _audit_record(audit_id="AR-001")
    r2 = _audit_record(audit_id="AR-002")
    r3 = _audit_record(audit_id="AR-003")
    history.add(r1)
    history.add(r2)
    history.add(r3)
    all_records = history.all_records()
    assert all_records[0] is r3
    assert all_records[1] is r2
    assert all_records[2] is r1


# --- 7. ResponseAuditHistory bounded eviction --------------------------------


def test_audit_history_bounded_eviction() -> None:
    history = ResponseAuditHistory(max_records=3)
    records = [_audit_record(audit_id=f"AR-{i:03d}") for i in range(5)]
    for r in records:
        history.add(r)
    assert history.count == 3
    all_records = history.all_records()
    assert len(all_records) == 3
    # Oldest two (AR-000, AR-001) evicted; newest three remain
    assert all_records[0].audit_id == "AR-004"
    assert all_records[1].audit_id == "AR-003"
    assert all_records[2].audit_id == "AR-002"


# --- 8. ResponseAuditHistory records_for_request -----------------------------


def test_audit_history_records_for_request() -> None:
    history = ResponseAuditHistory()
    r1 = _audit_record(request_id="RR-aaa")
    r2 = _audit_record(request_id="RR-bbb")
    r3 = _audit_record(request_id="RR-aaa")
    history.add(r1)
    history.add(r2)
    history.add(r3)
    aaa_records = history.records_for_request("RR-aaa")
    assert len(aaa_records) == 2
    assert aaa_records[0] is r3  # newest first
    assert aaa_records[1] is r1


# --- 9. ResponseAuditHistory records_for_request empty -----------------------


def test_audit_history_records_for_request_empty() -> None:
    history = ResponseAuditHistory()
    history.add(_audit_record(request_id="RR-aaa"))
    assert history.records_for_request("RR-nonexistent") == ()


# --- 10. ResponseAuditHistory clear ------------------------------------------


def test_audit_history_clear() -> None:
    history = ResponseAuditHistory()
    history.add(_audit_record())
    history.add(_audit_record())
    assert history.count == 2
    history.clear()
    assert history.count == 0
    assert history.all_records() == ()


# --- 11. Default MAX_AUDIT_RECORDS is 512 -----------------------------------


def test_default_max_is_512() -> None:
    assert MAX_AUDIT_RECORDS == 512


# --- 12. Audit record with incident source -----------------------------------


def test_audit_record_incident_source() -> None:
    record = ResponseAuditRecord(
        audit_id="AR-inc",
        request_id="RR-inc",
        action="block_ip",
        target="10.0.0.1",
        source_type="incident",
        source_id="INC-001",
        policy_decision="allowed",
        workflow_status_before="approved",
        workflow_status_after="executed",
        dry_run_status="would_apply",
        execution_status="applied",
        verification_status=VerificationStatus.NOT_VERIFIED,
        adapter="Windows Firewall",
        changed=False,
        message="Already exists",
        timestamp=_TS,
    )
    assert record.source_type == "incident"
    assert record.source_id == "INC-001"
    assert record.verification_status == VerificationStatus.NOT_VERIFIED


# --- 13. Audit record with manual source -------------------------------------


def test_audit_record_manual_source() -> None:
    record = ResponseAuditRecord(
        audit_id="AR-man",
        request_id="RR-man",
        action="block_ip",
        target="10.0.0.2",
        source_type="manual",
        source_id="operator",
        policy_decision="allowed",
        workflow_status_before="approved",
        workflow_status_after="executed",
        dry_run_status="not_started",
        execution_status="failed",
        verification_status=VerificationStatus.NOT_APPLICABLE,
        adapter="Windows Firewall",
        changed=False,
        message="Permission denied",
        timestamp=_TS,
    )
    assert record.source_type == "manual"
    assert record.execution_status == "failed"


# --- 14. Workflow manager execute creates audit record -----------------------


def test_workflow_execute_creates_audit_record() -> None:
    from aegis_desktop.services.response_workflow import (
        ResponseWorkflowManager,
        _Entry,
        get_audit_history,
    )

    mock_adapter = MagicMock(spec=FirewallAdapter)
    mock_adapter.block_ip.return_value = FirewallActionResult(
        action="block_ip",
        target="10.0.0.77",
        status=FirewallActionStatus.APPLIED,
        message="Rule created",
        changed=True,
        verified=True,
        adapter="Mock",
        timestamp=datetime.now(),
    )
    executor = ResponseExecutor(adapter=mock_adapter)

    mgr = ResponseWorkflowManager()
    req = _block_request()
    from aegis_response_engine.policy import ResponsePolicyEngine, ResponsePolicySettings

    engine = ResponsePolicyEngine(ResponsePolicySettings(response_enabled=True))
    decision = engine.evaluate(req)

    rid = "RR-audit-test"
    now = datetime.now()
    entry = _Entry(
        request=req,
        request_id=rid,
        decision=decision,
        dry_run=MagicMock(status="would_apply"),
        status="approved",
        created_at=now,
        updated_at=now,
        policy_settings=ResponsePolicySettings(response_enabled=True),
    )
    mgr._register(rid, entry)

    # Clear any pre-existing audit records
    history = get_audit_history()
    history.clear()

    mgr.execute(rid, executor=executor)

    records = history.records_for_request(rid)
    assert len(records) == 1
    record = records[0]
    assert record.request_id == rid
    assert record.action == "block_ip"
    assert record.target == "10.0.0.77"
    assert record.execution_status == "applied"
    assert record.verification_status == VerificationStatus.VERIFIED
    assert record.changed is True
    assert record.workflow_status_before == "approved"
    assert record.workflow_status_after == "executed"
    assert record.source_type == "detection"
    assert record.source_id == "AEGIS-NET-007:flow-1"


# --- 15. Workflow manager execute failure creates audit record ----------------


def test_workflow_execute_failure_creates_audit_record() -> None:
    from aegis_desktop.services.response_workflow import (
        ResponseWorkflowManager,
        _Entry,
        get_audit_history,
    )

    mock_adapter = MagicMock(spec=FirewallAdapter)
    mock_adapter.block_ip.return_value = FirewallActionResult(
        action="block_ip",
        target="10.0.0.77",
        status=FirewallActionStatus.FAILED,
        message="Elevation required",
        changed=False,
        verified=False,
        adapter="Mock",
        timestamp=datetime.now(),
    )
    executor = ResponseExecutor(adapter=mock_adapter)

    mgr = ResponseWorkflowManager()
    req = _block_request()
    from aegis_response_engine.policy import ResponsePolicyEngine, ResponsePolicySettings

    engine = ResponsePolicyEngine(ResponsePolicySettings(response_enabled=True))
    decision = engine.evaluate(req)

    rid = "RR-audit-fail"
    now = datetime.now()
    entry = _Entry(
        request=req,
        request_id=rid,
        decision=decision,
        dry_run=MagicMock(status="would_apply"),
        status="approved",
        created_at=now,
        updated_at=now,
        policy_settings=ResponsePolicySettings(response_enabled=True),
    )
    mgr._register(rid, entry)

    history = get_audit_history()
    history.clear()

    mgr.execute(rid, executor=executor)

    records = history.records_for_request(rid)
    assert len(records) == 1
    record = records[0]
    assert record.execution_status == "failed"
    assert record.verification_status == VerificationStatus.NOT_VERIFIED
    assert record.workflow_status_after == "execution_failed"


# --- 16. Workflow manager non-approved does not create audit record ----------


def test_workflow_non_approved_no_audit() -> None:
    from aegis_desktop.services.response_workflow import (
        ResponseWorkflowManager,
        _Entry,
        get_audit_history,
    )

    mgr = ResponseWorkflowManager()
    req = _block_request()
    from aegis_response_engine.policy import ResponsePolicyEngine, ResponsePolicySettings

    engine = ResponsePolicyEngine(ResponsePolicySettings(response_enabled=True))
    decision = engine.evaluate(req)

    rid = "RR-no-audit"
    now = datetime.now()
    entry = _Entry(
        request=req,
        request_id=rid,
        decision=decision,
        dry_run=None,
        status="draft",
        created_at=now,
        updated_at=now,
    )
    mgr._register(rid, entry)

    history = get_audit_history()
    initial_count = history.count

    mgr.execute(rid)

    assert history.count == initial_count


# --- 17. Desktop Response Center audit table model ---------------------------


def test_desktop_audit_table_model() -> None:
    pytest.importorskip("PySide6", reason="desktop extra not installed")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from aegis_desktop.app import create_application
    from aegis_desktop.pages.response_center import AuditTableModel

    app = create_application([])
    assert app is not None

    model = AuditTableModel()
    assert model.rowCount() == 0
    assert model.columnCount() == 12  # 12 audit columns

    r1 = _audit_record(audit_id="AR-001")
    r2 = _audit_record(audit_id="AR-002")
    model.set_rows((r1, r2))
    assert model.rowCount() == 2


# --- 18. Desktop Response Center audit column headers ------------------------


def test_desktop_audit_column_headers() -> None:
    pytest.importorskip("PySide6", reason="desktop extra not installed")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from aegis_desktop.app import create_application
    from aegis_desktop.pages.response_center import ResponseCenterPage

    app = create_application([])
    assert app is not None

    page = ResponseCenterPage()
    headers = page.audit_column_headers()
    assert len(headers) == 12
    assert headers[0] == "Audit ID"
    assert headers[11] == "Time"


# --- 19. Desktop Response Center audit table accessible after init -----------


def test_desktop_audit_table_after_init() -> None:
    pytest.importorskip("PySide6", reason="desktop extra not installed")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from aegis_desktop.app import create_application
    from aegis_desktop.pages.response_center import ResponseCenterPage

    app = create_application([])
    assert app is not None

    page = ResponseCenterPage()
    assert page.audit_row_count() == 0
    assert page.audit_model is not None
    assert page.audit_table_view is not None


# --- 20. Audit record with failed verification -------------------------------


def test_audit_record_failed_verification() -> None:
    record = ResponseAuditRecord(
        audit_id="AR-fv",
        request_id="RR-fv",
        action="block_ip",
        target="10.0.0.5",
        source_type="detection",
        source_id="finding-1",
        policy_decision="requires_approval",
        workflow_status_before="approved",
        workflow_status_after="executed",
        dry_run_status="would_apply",
        execution_status="applied",
        verification_status=VerificationStatus.VERIFICATION_FAILED,
        adapter="Windows Firewall",
        changed=True,
        message="Applied but verification failed",
        timestamp=_TS,
    )
    assert record.verification_status == VerificationStatus.VERIFICATION_FAILED
    assert record.execution_status == "applied"
