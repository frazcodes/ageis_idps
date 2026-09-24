"""Focused tests for the response policy engine (Step 28).

Exercises the deterministic, non-executing :class:`ResponsePolicyEngine` and the
read-only desktop response-policy preview. Nothing here touches a firewall, host,
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
from aegis_shared.enums import ActionType, EventCategory, EventType, RiskLevel, Severity

_TS = datetime(2026, 6, 1, 10, 0, 0, tzinfo=UTC)


def _request(
    action: ActionType = ActionType.BLOCK_IP,
    *,
    kind: ResponseTargetKind = ResponseTargetKind.IP,
    value: str = "203.0.113.30",
    risk_level: RiskLevel = RiskLevel.HIGH,
    risk_score: int = 80,
    finding_ids: tuple[str, ...] = ("AEGIS-NET-007:e1",),
    rule_ids: tuple[str, ...] = ("AEGIS-NET-007",),
    host_id: str | None = "host-1",
    protocol: str | None = None,
) -> ResponseRequest:
    return ResponseRequest(
        action=action,
        target=ResponseTarget(kind=kind, value=value, protocol=protocol),
        risk_level=risk_level,
        risk_score=risk_score,
        timestamp=_TS,
        finding_ids=finding_ids,
        rule_ids=rule_ids,
        host_id=host_id,
    )


def _engine(**overrides: object) -> ResponsePolicyEngine:
    return ResponsePolicyEngine(ResponsePolicySettings(**overrides))  # type: ignore[arg-type]


# --- 1. Safe default policy: response disabled ------------------------------


def test_safe_default_policy_denies() -> None:
    decision = ResponsePolicyEngine().evaluate(_request())
    assert decision.status is ResponseDecisionStatus.DENIED
    assert "disabled by policy" in decision.reason
    assert decision.required_approval is True
    assert decision.dry_run_required is True


# --- 2/3. Approval and dry run required -------------------------------------


def test_enabled_policy_requires_approval_and_dry_run() -> None:
    decision = _engine(response_enabled=True).evaluate(_request(risk_level=RiskLevel.HIGH))
    assert decision.status is ResponseDecisionStatus.REQUIRES_APPROVAL
    assert decision.required_approval is True
    assert decision.dry_run_required is True
    assert "approval" in decision.reason


# --- 4. Valid BLOCK_IP target -----------------------------------------------


def test_valid_block_ip_target() -> None:
    decision = _engine(response_enabled=True).evaluate(_request(value="203.0.113.30"))
    assert decision.status is ResponseDecisionStatus.REQUIRES_APPROVAL
    assert decision.target.value == "203.0.113.30"


# --- 5. Invalid BLOCK_IP target ---------------------------------------------


def test_invalid_block_ip_target_denied() -> None:
    engine = _engine(response_enabled=True)
    for bad in ("", "not-an-ip", "10.0.0.1; rm -rf /", "999.999.999.999"):
        decision = engine.evaluate(_request(value=bad))
        assert decision.status is ResponseDecisionStatus.DENIED
        assert "not a valid IP address" in decision.reason


# --- 6. IPv6 BLOCK_IP validation --------------------------------------------


def test_ipv6_block_ip_valid() -> None:
    decision = _engine(response_enabled=True).evaluate(_request(value="2001:db8::1"))
    assert decision.status is ResponseDecisionStatus.REQUIRES_APPROVAL
    assert decision.target.value == "2001:db8::1"


# --- 7. Invalid port validation ---------------------------------------------


def test_invalid_port_denied() -> None:
    engine = _engine(response_enabled=True)
    for bad in ("0", "70000", "not-a-port"):
        decision = engine.evaluate(
            _request(
                ActionType.BLOCK_PORT,
                kind=ResponseTargetKind.PORT,
                value=bad,
            )
        )
        assert decision.status is ResponseDecisionStatus.DENIED
        assert "port" in decision.reason


# --- 8. Low risk denied by threshold ----------------------------------------


def test_low_risk_denied_by_threshold() -> None:
    decision = _engine(response_enabled=True).evaluate(_request(risk_level=RiskLevel.LOW))
    assert decision.status is ResponseDecisionStatus.DENIED
    assert "threshold" in decision.reason


# --- 9. High risk requires approval -----------------------------------------


def test_high_risk_requires_approval() -> None:
    decision = _engine(response_enabled=True).evaluate(_request(risk_level=RiskLevel.HIGH))
    assert decision.status is ResponseDecisionStatus.REQUIRES_APPROVAL


# --- 10. Missing context denied ---------------------------------------------


def test_missing_context_denied() -> None:
    decision = _engine(response_enabled=True).evaluate(
        _request(finding_ids=(), rule_ids=(), host_id=None)
    )
    assert decision.status is ResponseDecisionStatus.DENIED
    assert "context" in decision.reason


# --- 11. Deterministic decision ID ------------------------------------------


def test_deterministic_decision_id() -> None:
    engine = _engine(response_enabled=True)
    first = engine.evaluate(_request())
    second = engine.evaluate(_request())
    assert first.decision_id == second.decision_id
    assert first.decision_id.startswith("RD-")


# --- 12. Policy version included --------------------------------------------


def test_policy_version_included() -> None:
    decision = _engine(response_enabled=True, policy_version="2.1.0").evaluate(_request())
    assert decision.policy_version == "2.1.0"


# --- 13. Human-readable reasons ---------------------------------------------


def test_reasons_are_human_readable() -> None:
    reasons = {
        ResponsePolicyEngine().evaluate(_request()).reason,
        _engine(response_enabled=True).evaluate(_request(risk_level=RiskLevel.LOW)).reason,
        _engine(response_enabled=True).evaluate(_request(value="bad")).reason,
        _engine(response_enabled=True).evaluate(_request(finding_ids=(), rule_ids=())).reason,
    }
    for reason in reasons:
        assert reason.startswith("Action")
        assert "policy" in reason or "target" in reason or "risk" in reason or "context" in reason


# --- 14. No side effects (safe to call repeatedly) --------------------------


def test_no_side_effects_and_repeatable() -> None:
    engine = _engine(response_enabled=True)
    request = _request()
    decisions = [engine.evaluate(request) for _ in range(3)]
    assert all(d == decisions[0] for d in decisions)
    # Nothing was executed: the decision is data only.
    assert decisions[0].is_actionable is True


# --- 15. ALLOWED when controls are explicitly relaxed -----------------------


def test_allowed_when_controls_relaxed() -> None:
    decision = _engine(
        response_enabled=True, approval_required=False, dry_run_required=False
    ).evaluate(_request(risk_level=RiskLevel.HIGH))
    assert decision.status is ResponseDecisionStatus.ALLOWED
    assert decision.required_approval is False
    assert decision.dry_run_required is False


# --- 16. Target-kind mismatch and unsupported action ------------------------


def test_target_kind_mismatch_denied() -> None:
    decision = _engine(response_enabled=True).evaluate(
        _request(ActionType.BLOCK_IP, kind=ResponseTargetKind.HOST, value="host-1")
    )
    assert decision.status is ResponseDecisionStatus.DENIED
    assert "target" in decision.reason


def test_unsupported_action_not_applicable() -> None:
    decision = _engine(response_enabled=True).evaluate(_request(ActionType.NOTIFY))
    assert decision.status is ResponseDecisionStatus.NOT_APPLICABLE


# --- 17. Desktop response-policy preview ------------------------------------


def test_desktop_response_policy_preview() -> None:
    from aegis_desktop.services.response_policy import collect_response_policy_view
    from aegis_shared.detection import DetectionFinding

    finding = DetectionFinding(
        finding_id="AEGIS-NET-007:flow-1",
        rule_id="AEGIS-NET-007",
        rule_name="Suspicious communication pattern observed",
        severity=Severity.HIGH,
        title="Suspicious communication pattern observed",
        description="Multiple independent signals.",
        event_id="flow-1",
        event_type=EventType.FLOW_SUMMARY,
        category=EventCategory.NETWORK,
        timestamp=_TS,
        host_id="host-1",
        evidence={"relationship": "10.0.0.5 -> 10.0.0.77:4444", "remote_ip": "10.0.0.77"},
    )

    # Default policy is fail-closed: the preview shows an explicit DENIED state.
    view = collect_response_policy_view(finding)
    assert view is not None
    assert view.recommended_action == "block_ip"
    assert view.action_label == "Block IP"
    assert view.target == "10.0.0.77"
    assert view.status == "denied"
    assert view.required_approval is True
    assert view.dry_run_required is True
    assert view.policy_version == "1.0.0"

    # With an explicitly enabled policy the preview requires approval.
    enabled = _engine(response_enabled=True)
    enabled_view = collect_response_policy_view(finding, engine=enabled)
    assert enabled_view is not None
    assert enabled_view.status == "requires_approval"

    # Findings without a usable target expose no recommendation.
    no_target = DetectionFinding(
        finding_id="AEGIS-PROC-001:h1",
        rule_id="AEGIS-PROC-001",
        rule_name="Process launched from configured path",
        severity=Severity.HIGH,
        title="Process finding",
        description="A process finding.",
        event_id="h1",
        event_type=EventType.PROCESS_STARTED,
        category=EventCategory.HOST,
        timestamp=_TS,
        host_id="host-1",
    )
    assert collect_response_policy_view(no_target) is None


# --- 18. Desktop investigation renders the response policy ------------------


def test_desktop_investigation_renders_response_policy() -> None:
    pytest.importorskip("PySide6", reason="desktop extra not installed")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from aegis_desktop.app import create_application
    from aegis_desktop.pages.detections import DetectionsPage
    from aegis_desktop.services.detections import (
        DetectionPosture,
        FindingRow,
        FindingSnapshotView,
        collect_investigation_view,
        evidence_summary,
    )
    from aegis_shared.detection import DetectionFinding

    app = create_application([])
    assert app is not None

    finding = DetectionFinding(
        finding_id="AEGIS-NET-007:flow-1",
        rule_id="AEGIS-NET-007",
        rule_name="Suspicious communication pattern observed",
        severity=Severity.HIGH,
        title="Suspicious communication pattern observed",
        description="Multiple independent signals.",
        event_id="flow-1",
        event_type=EventType.FLOW_SUMMARY,
        category=EventCategory.NETWORK,
        timestamp=_TS,
        host_id="host-1",
        evidence={"remote_ip": "10.0.0.77", "relationship": "10.0.0.5 -> 10.0.0.77:4444"},
    )
    view = collect_investigation_view(
        finding,
        event_details_lookup=lambda _eid: None,
        response_policy_lookup=lambda _f: __import__(
            "aegis_desktop.services.response_policy",
            fromlist=["collect_response_policy_view"],
        ).collect_response_policy_view(_f, engine=_engine(response_enabled=True)),
    )
    assert view.response_policy is not None

    snapshot = FindingSnapshotView(
        available=True,
        error=None,
        collected_at=_TS,
        posture=DetectionPosture(running=True, enabled=True, rule_count=6, findings=1),
        rows=(
            FindingRow(
                timestamp=_TS,
                finding_id=finding.finding_id,
                rule_id=finding.rule_id,
                severity=finding.severity.value,
                title=finding.title,
                event_id=finding.event_id,
                event_type=finding.event_type.value,
                category=finding.category.value,
                host_id=finding.host_id,
                description=finding.description,
                evidence_summary=evidence_summary(dict(finding.evidence)),
                tags=tuple(finding.tags),
            ),
        ),
        findings=(finding,),
    )
    page = DetectionsPage(provider=lambda: snapshot, investigation_provider=lambda _f: view)
    page.refresh()
    page.show_detail_for(page.row_at(0))

    keys = page.detail_keys()
    values = page.detail_values()
    assert "Recommended Action" in keys
    assert "Decision" in keys
    assert "REQUIRES_APPROVAL" in values
    assert "Block IP" in values
    assert "10.0.0.77" in values
