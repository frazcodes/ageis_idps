"""The deterministic, explainable response policy engine.

Answers: *given a finding/incident and a requested action, is that action allowed
by the configured Aegis response policy?* It is **pure and side-effect free**: it
never touches a firewall, host, process or file, never performs I/O and never
executes anything. Calling it repeatedly is safe.

The engine is fail-closed: when the policy is disabled or a decision is
ambiguous, the action is denied. ``ALLOWED`` means "permitted to proceed to the
future response workflow", never "act now".
"""

from __future__ import annotations

import hashlib
import ipaddress
from datetime import datetime

from aegis_response_engine.policy.config import ResponsePolicySettings
from aegis_response_engine.policy.models import (
    ResponseDecision,
    ResponseDecisionStatus,
    ResponseRequest,
    ResponseTarget,
    ResponseTargetKind,
)
from aegis_shared.enums import ActionType, RiskLevel

#: Ordering of the existing risk levels (no new scale, just an index).
_RISK_RANK: dict[RiskLevel, int] = {
    RiskLevel.INFORMATIONAL: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}

#: Which target kind each supported action requires.
_ACTION_TARGET: dict[ActionType, ResponseTargetKind] = {
    ActionType.BLOCK_IP: ResponseTargetKind.IP,
    ActionType.UNBLOCK_IP: ResponseTargetKind.IP,
    ActionType.BLOCK_PORT: ResponseTargetKind.PORT,
    ActionType.HOST_ISOLATE: ResponseTargetKind.HOST,
    ActionType.KILL_PROCESS: ResponseTargetKind.PROCESS,
    ActionType.QUARANTINE_FILE: ResponseTargetKind.FILE,
}

#: Human-readable action labels for reasons and the UI.
ACTION_LABELS: dict[ActionType, str] = {
    ActionType.BLOCK_IP: "Block IP",
    ActionType.UNBLOCK_IP: "Unblock IP",
    ActionType.BLOCK_PORT: "Block port",
    ActionType.HOST_ISOLATE: "Isolate host",
    ActionType.KILL_PROCESS: "Terminate process",
    ActionType.QUARANTINE_FILE: "Quarantine file",
}

_UNSAFE_PATH_CHARS = frozenset(";|&$`\n\r\t")


def _validate_target(request: ResponseRequest) -> str | None:
    """Return a human-readable reason when the target is invalid, else ``None``."""
    action = request.action
    target = request.target
    value = target.value.strip()

    if action in (ActionType.BLOCK_IP, ActionType.UNBLOCK_IP):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return "Action denied because the response target is not a valid IP address."
        return None

    if action is ActionType.BLOCK_PORT:
        try:
            port = int(value)
        except (TypeError, ValueError):
            return "Action denied because the response target port is not an integer."
        if not 1 <= port <= 65535:
            return "Action denied because the response target port is out of range (1-65535)."
        if target.protocol and target.protocol.strip().lower() not in {"tcp", "udp"}:
            return "Action denied because the response target protocol is unsupported."
        return None

    if action is ActionType.HOST_ISOLATE:
        if not value:
            return "Action denied because the response target host identifier is missing."
        return None

    if action is ActionType.KILL_PROCESS:
        try:
            pid = int(value)
        except (TypeError, ValueError):
            return "Action denied because the response target pid is not an integer."
        if pid < 0:
            return "Action denied because the response target pid is invalid."
        if not request.host_id:
            return "Action denied because the response target host context is missing."
        return None

    if action is ActionType.QUARANTINE_FILE:
        if not value:
            return "Action denied because the response target file path or hash is missing."
        if any(char in value for char in _UNSAFE_PATH_CHARS):
            return "Action denied because the response target contains unsafe characters."
        return None

    return None


def _decision_id(request: ResponseRequest) -> str:
    """Deterministic decision identity (stable for the same request)."""
    payload = (
        f"{request.action.value}|{request.target.kind.value}|{request.target.value}|"
        f"{'|'.join(sorted(request.finding_ids))}|{request.incident_id or '-'}"
    )
    return f"RD-{hashlib.sha1(payload.encode(), usedforsecurity=False).hexdigest()[:16]}"


class ResponsePolicyEngine:
    """Evaluate response requests against the configured policy (no execution)."""

    def __init__(self, settings: ResponsePolicySettings | None = None) -> None:
        self._settings = settings or ResponsePolicySettings()

    @property
    def settings(self) -> ResponsePolicySettings:
        """The policy this engine evaluates with."""
        return self._settings

    @property
    def policy_version(self) -> str:
        """The deterministic policy version stamped on decisions."""
        return self._settings.policy_version

    def evaluate(self, request: ResponseRequest) -> ResponseDecision:
        """Return the deterministic decision for ``request`` (never executes)."""
        expected = _ACTION_TARGET.get(request.action)
        if expected is None:
            return self._build(
                request,
                ResponseDecisionStatus.NOT_APPLICABLE,
                "No response action is applicable for the observed context.",
            )
        if request.target.kind is not expected:
            return self._build(
                request,
                ResponseDecisionStatus.DENIED,
                f"Action denied because {ACTION_LABELS[request.action]} requires a "
                f"{expected.value} target.",
            )

        invalid = _validate_target(request)
        if invalid is not None:
            return self._build(request, ResponseDecisionStatus.DENIED, invalid)

        if not request.has_context:
            return self._build(
                request,
                ResponseDecisionStatus.DENIED,
                "Action denied because no finding or incident context is available.",
            )

        if not self._settings.response_enabled:
            return self._build(
                request,
                ResponseDecisionStatus.DENIED,
                "Action denied because response execution is disabled by policy.",
            )

        if (
            self._settings.allowed_actions
            and request.action.value not in self._settings.allowed_actions
        ):
            return self._build(
                request,
                ResponseDecisionStatus.DENIED,
                "Action denied because it is not permitted by the configured response policy.",
            )

        if (
            _RISK_RANK[request.risk_level] < _RISK_RANK[self._settings.min_risk_level]
            or request.risk_score < self._settings.min_risk_score
        ):
            return self._build(
                request,
                ResponseDecisionStatus.DENIED,
                "Action denied because the observed risk level does not meet the "
                "configured response threshold.",
            )

        if self._settings.approval_required or self._settings.dry_run_required:
            return self._build(
                request,
                ResponseDecisionStatus.REQUIRES_APPROVAL,
                "Action satisfies the configured response policy but requires "
                "administrator approval and dry run.",
            )

        return self._build(
            request,
            ResponseDecisionStatus.ALLOWED,
            "Action is permitted by the configured response policy.",
        )

    def _build(
        self,
        request: ResponseRequest,
        status: ResponseDecisionStatus,
        reason: str,
    ) -> ResponseDecision:
        return ResponseDecision(
            decision_id=_decision_id(request),
            action=request.action,
            status=status,
            target=request.target,
            reason=reason,
            risk_level=request.risk_level,
            risk_score=request.risk_score,
            required_approval=self._settings.approval_required,
            dry_run_required=self._settings.dry_run_required,
            policy_version=self._settings.policy_version,
            timestamp=request.timestamp,
            finding_ids=request.finding_ids,
            incident_id=request.incident_id,
            rule_ids=request.rule_ids,
        )


def build_request(
    *,
    action: ActionType,
    target: ResponseTarget,
    risk_level: object,
    risk_score: int,
    timestamp: datetime,
    finding_ids: tuple[str, ...] = (),
    rule_ids: tuple[str, ...] = (),
    host_id: str | None = None,
    incident_id: str | None = None,
) -> ResponseRequest:
    """Convenience builder mirroring the :class:`ResponseRequest` fields."""
    return ResponseRequest(
        action=action,
        target=target,
        risk_level=risk_level,  # type: ignore[arg-type]
        risk_score=risk_score,
        timestamp=timestamp,
        finding_ids=finding_ids,
        rule_ids=rule_ids,
        host_id=host_id,
        incident_id=incident_id,
    )


__all__ = ["ACTION_LABELS", "ResponsePolicyEngine", "build_request"]
