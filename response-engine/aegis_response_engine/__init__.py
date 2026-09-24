"""Aegis IDPS response (IPS) engine.

Controlled, policy-gated response actions. Nothing in this package executes a
firewall, process or file command in the foundation: the default mode is
``monitor``, which records decisions without acting on them.
"""

from __future__ import annotations

from aegis_response_engine.audit import (
    ResponseAuditHistory,
    ResponseAuditRecord,
    VerificationStatus,
)
from aegis_response_engine.config import ResponseEngineSettings, get_response_settings
from aegis_response_engine.executors import ExecutionResult, ResponseExecutor
from aegis_response_engine.firewall import (
    FirewallActionResult,
    FirewallActionStatus,
    FirewallAdapter,
    WindowsFirewallAdapter,
)
from aegis_response_engine.policy import (
    ACTION_LABELS,
    DryRunResult,
    DryRunStatus,
    ResponseDecision,
    ResponseDecisionStatus,
    ResponsePolicyEngine,
    ResponsePolicySettings,
    ResponseRequest,
    ResponseTarget,
    ResponseTargetKind,
    ResponseWorkflowState,
    ResponseWorkflowStatus,
    build_request,
    get_response_policy_settings,
)

__all__ = [
    "ACTION_LABELS",
    "DryRunResult",
    "DryRunStatus",
    "ExecutionResult",
    "FirewallActionResult",
    "FirewallActionStatus",
    "FirewallAdapter",
    "ResponseAuditHistory",
    "ResponseAuditRecord",
    "ResponseDecision",
    "ResponseDecisionStatus",
    "ResponseEngineSettings",
    "ResponseExecutor",
    "ResponsePolicyEngine",
    "ResponsePolicySettings",
    "ResponseRequest",
    "ResponseTarget",
    "ResponseTargetKind",
    "ResponseWorkflowState",
    "ResponseWorkflowStatus",
    "VerificationStatus",
    "WindowsFirewallAdapter",
    "build_request",
    "get_response_policy_settings",
    "get_response_settings",
]
