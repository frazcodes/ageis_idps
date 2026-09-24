"""Response policy evaluation.

Decides whether a proposed action is permitted, based on the observed risk and
finding/incident context. Policy is the only thing that may authorise an action;
a risk score never does, and an IOC match is evidence - never automatic
permission to block.

This package **never executes** anything: it produces a
:class:`~aegis_response_engine.policy.models.ResponseDecision` only.
"""

from __future__ import annotations

from aegis_response_engine.policy.config import (
    ResponsePolicySettings,
    get_response_policy_settings,
)
from aegis_response_engine.policy.engine import (
    ACTION_LABELS,
    ResponsePolicyEngine,
    build_request,
)
from aegis_response_engine.policy.models import (
    DryRunResult,
    DryRunStatus,
    ResponseDecision,
    ResponseDecisionStatus,
    ResponseRequest,
    ResponseTarget,
    ResponseTargetKind,
    ResponseWorkflowState,
    ResponseWorkflowStatus,
)

__all__ = [
    "ACTION_LABELS",
    "DryRunResult",
    "DryRunStatus",
    "ResponseDecision",
    "ResponseDecisionStatus",
    "ResponsePolicyEngine",
    "ResponsePolicySettings",
    "ResponseRequest",
    "ResponseTarget",
    "ResponseTargetKind",
    "ResponseWorkflowState",
    "ResponseWorkflowStatus",
    "build_request",
    "get_response_policy_settings",
]
