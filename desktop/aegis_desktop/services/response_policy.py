"""Response-policy adapter: policy decision -> UI-friendly, read-only data.

Strictly read-only and non-executing. It builds a response request from a real
finding (only when the finding actually carries a usable target) and asks the
deterministic :class:`~aegis_response_engine.policy.ResponsePolicyEngine` whether
the action is permitted. No firewall, host, process or file is touched and no
button executes anything.

Imports of the response engine are lazy so opening the application loads no
response subsystem.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from aegis_shared.logging import get_logger

if TYPE_CHECKING:  # pragma: no cover - typing only
    from aegis_shared.detection import DetectionFinding

logger = get_logger(__name__)

#: Existing severity names mapped onto the existing risk-level vocabulary.
_SEVERITY_TO_RISK: dict[str, str] = {
    "info": "informational",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


@dataclass(frozen=True)
class ResponsePolicyView:
    """Read-only view of a response-policy decision (never executes)."""

    available: bool
    recommended_action: str | None
    action_label: str | None
    target: str | None
    status: str
    reason: str
    risk_level: str
    risk_score: int
    required_approval: bool
    dry_run_required: bool
    policy_version: str
    decision_id: str


def _recommend(finding: DetectionFinding) -> tuple[object, object] | None:
    """Return ``(action, target)`` when the finding exposes a usable target."""
    from aegis_response_engine.policy import ResponseTarget, ResponseTargetKind
    from aegis_shared.enums import ActionType

    evidence = dict(finding.evidence)
    if finding.rule_id == "AEGIS-NET-007":
        remote = evidence.get("remote_ip")
        if remote:
            target = ResponseTarget(kind=ResponseTargetKind.IP, value=remote)
            return ActionType.BLOCK_IP, target
    if (
        finding.rule_id == "AEGIS-IOC-001"
        and evidence.get("indicator_type") == "ip"
        and evidence.get("observed_value")
    ):
        target = ResponseTarget(kind=ResponseTargetKind.IP, value=evidence["observed_value"])
        return ActionType.BLOCK_IP, target
    return None


def collect_response_policy_view(
    finding: DetectionFinding,
    *,
    risk_level: str | None = None,
    risk_score: int | None = None,
    timestamp: datetime | None = None,
    engine: object | None = None,
) -> ResponsePolicyView | None:
    """Evaluate the response policy for ``finding`` (read-only, no execution).

    Returns ``None`` when no response action is recommended for the finding.
    """
    try:
        recommendation = _recommend(finding)
    except Exception as exc:
        logger.warning("Response recommendation failed: %s", exc)
        return None
    if recommendation is None:
        return None
    action, target = recommendation

    from aegis_response_engine.policy import (
        ACTION_LABELS,
        ResponseDecisionStatus,
        ResponsePolicyEngine,
        ResponseRequest,
        get_response_policy_settings,
    )
    from aegis_shared.enums import RiskLevel

    level_text = risk_level or _SEVERITY_TO_RISK.get(finding.severity.value, "informational")
    try:
        level = RiskLevel(level_text)
    except ValueError:
        level = RiskLevel.INFORMATIONAL

    request = ResponseRequest(
        action=action,  # type: ignore[arg-type]
        target=target,  # type: ignore[arg-type]
        risk_level=level,
        risk_score=int(risk_score or 0),
        timestamp=timestamp or finding.timestamp,
        finding_ids=(finding.finding_id,),
        rule_ids=(finding.rule_id,),
        host_id=finding.host_id,
    )
    resolved_engine = engine or ResponsePolicyEngine(get_response_policy_settings())
    decision = resolved_engine.evaluate(request)  # type: ignore[attr-defined]
    if decision.status is ResponseDecisionStatus.NOT_APPLICABLE:
        return None

    return ResponsePolicyView(
        available=True,
        recommended_action=decision.action.value,
        action_label=ACTION_LABELS.get(decision.action, decision.action.value),
        target=decision.target.value,
        status=decision.status.value,
        reason=decision.reason,
        risk_level=decision.risk_level.value,
        risk_score=decision.risk_score,
        required_approval=decision.required_approval,
        dry_run_required=decision.dry_run_required,
        policy_version=decision.policy_version,
        decision_id=decision.decision_id,
    )


__all__ = ["ResponsePolicyView", "collect_response_policy_view"]
