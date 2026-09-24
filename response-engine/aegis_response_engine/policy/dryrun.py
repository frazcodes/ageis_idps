"""Deterministic, side-effect-free dry-run simulation.

Receives a :class:`ResponseRequest`, validates it, reuses the
:class:`ResponsePolicyEngine`, and returns a :class:`DryRunResult` describing
what *would* happen.  No firewall, host, process or file is ever touched.
"""

from __future__ import annotations

import hashlib
from datetime import datetime

from aegis_response_engine.policy.config import ResponsePolicySettings
from aegis_response_engine.policy.engine import ACTION_LABELS, ResponsePolicyEngine
from aegis_response_engine.policy.models import (
    DryRunResult,
    DryRunStatus,
    ResponseDecisionStatus,
    ResponseRequest,
)


def _dry_run_id(request: ResponseRequest, policy_version: str) -> str:
    """Deterministic dry-run identity (stable for the same request)."""
    payload = (
        f"DR|{request.action.value}|{request.target.kind.value}|{request.target.value}|"
        f"{policy_version}|{'|'.join(sorted(request.finding_ids))}|"
        f"{request.incident_id or '-'}"
    )
    return f"DR-{hashlib.sha1(payload.encode(), usedforsecurity=False).hexdigest()[:16]}"


def _build_summary(action_label: str, target_value: str, would_apply: bool) -> str:
    """Human-readable dry-run summary."""
    if would_apply:
        return (
            f"Dry run complete. {action_label} against {target_value} would be "
            f"applied upon execution."
        )
    return f"Dry run complete. {action_label} against {target_value} is blocked by policy."


class ResponseDryRunEngine:
    """Pure dry-run simulation.  Calling it never modifies anything."""

    def __init__(self, settings: ResponsePolicySettings | None = None) -> None:
        self._settings = settings or ResponsePolicySettings()
        self._policy_engine = ResponsePolicyEngine(self._settings)

    @property
    def settings(self) -> ResponsePolicySettings:
        """The policy settings used for this engine."""
        return self._settings

    def simulate(self, request: ResponseRequest) -> DryRunResult:
        """Return a deterministic dry-run result for ``request``.

        This never modifies the OS, network or any state.
        """
        decision = self._policy_engine.evaluate(request)
        action_label = ACTION_LABELS.get(request.action, request.action.value)

        if decision.status is ResponseDecisionStatus.NOT_APPLICABLE:
            return DryRunResult(
                dry_run_id=_dry_run_id(request, self._settings.policy_version),
                request_id=decision.decision_id,
                action=request.action,
                target=request.target,
                status=DryRunStatus.INVALID,
                summary="No response action is applicable for the observed context.",
                would_change=False,
                policy_version=self._settings.policy_version,
                timestamp=datetime.now(),
            )

        if decision.status is ResponseDecisionStatus.DENIED:
            return DryRunResult(
                dry_run_id=_dry_run_id(request, self._settings.policy_version),
                request_id=decision.decision_id,
                action=request.action,
                target=request.target,
                status=DryRunStatus.BLOCKED,
                summary=_build_summary(action_label, request.target.value, False),
                would_change=False,
                policy_version=self._settings.policy_version,
                timestamp=datetime.now(),
            )

        # ALLOWED or REQUIRES_APPROVAL: the action would be applied.
        return DryRunResult(
            dry_run_id=_dry_run_id(request, self._settings.policy_version),
            request_id=decision.decision_id,
            action=request.action,
            target=request.target,
            status=DryRunStatus.WOULD_APPLY,
            summary=_build_summary(action_label, request.target.value, True),
            would_change=True,
            policy_version=self._settings.policy_version,
            timestamp=datetime.now(),
        )


__all__ = ["ResponseDryRunEngine"]
