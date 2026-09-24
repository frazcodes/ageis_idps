"""Immutable response-policy value objects.

A :class:`ResponseRequest` asks whether an action is permitted; a
:class:`ResponseDecision` records the deterministic policy outcome. These models
describe **possible** actions and decisions only - nothing here executes,
blocks or modifies anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from aegis_shared.enums import ActionType, RiskLevel


class ResponseDecisionStatus(StrEnum):
    """The outcome of evaluating a response request against policy."""

    ALLOWED = "allowed"
    DENIED = "denied"
    REQUIRES_APPROVAL = "requires_approval"
    NOT_APPLICABLE = "not_applicable"


class ResponseTargetKind(StrEnum):
    """The kind of target a response action applies to."""

    IP = "ip"
    PORT = "port"
    HOST = "host"
    PROCESS = "process"
    FILE = "file"


@dataclass(frozen=True)
class ResponseTarget:
    """The object a response action would apply to (metadata only)."""

    kind: ResponseTargetKind
    value: str
    #: Optional transport protocol for port targets (``tcp`` / ``udp``).
    protocol: str | None = None


@dataclass(frozen=True)
class ResponseRequest:
    """A request to evaluate whether an action is permitted by policy."""

    action: ActionType
    target: ResponseTarget
    risk_level: RiskLevel
    risk_score: int
    timestamp: datetime
    finding_ids: tuple[str, ...] = ()
    rule_ids: tuple[str, ...] = ()
    host_id: str | None = None
    incident_id: str | None = None

    @property
    def has_context(self) -> bool:
        """Whether there is any finding/incident context justifying a response."""
        return bool(self.finding_ids or self.rule_ids or self.incident_id)


@dataclass(frozen=True)
class ResponseDecision:
    """The deterministic policy outcome for one :class:`ResponseRequest`.

    A decision never executes anything. ``ALLOWED`` means "permitted to proceed
    to the future response workflow", not "act now".
    """

    decision_id: str
    action: ActionType
    status: ResponseDecisionStatus
    target: ResponseTarget
    reason: str
    risk_level: RiskLevel
    risk_score: int
    required_approval: bool
    dry_run_required: bool
    policy_version: str
    timestamp: datetime
    finding_ids: tuple[str, ...] = ()
    incident_id: str | None = None
    rule_ids: tuple[str, ...] = field(default=())

    @property
    def is_actionable(self) -> bool:
        """Whether a future workflow could proceed (allowed or awaiting approval)."""
        return self.status in (
            ResponseDecisionStatus.ALLOWED,
            ResponseDecisionStatus.REQUIRES_APPROVAL,
        )


class DryRunStatus(StrEnum):
    """Deterministic status of a dry-run simulation."""

    READY = "ready"
    WOULD_APPLY = "would_apply"
    BLOCKED = "blocked"
    INVALID = "invalid"


@dataclass(frozen=True)
class DryRunResult:
    """A pure simulation result. Nothing is executed, modified or blocked.

    The dry run is deterministic: given the same request and policy settings it
    always returns the same result.
    """

    dry_run_id: str
    request_id: str
    action: ActionType
    target: ResponseTarget
    status: DryRunStatus
    summary: str
    would_change: bool
    policy_version: str
    timestamp: datetime


class ResponseWorkflowStatus(StrEnum):
    """Lifecycle status of a response request within the desktop workflow."""

    DRAFT = "draft"
    DRY_RUN_READY = "dry_run_ready"
    DRY_RUN_COMPLETED = "dry_run_completed"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class ResponseWorkflowState:
    """Immutable snapshot of one response request's workflow state."""

    request: ResponseRequest
    request_id: str
    decision: ResponseDecision | None
    dry_run: DryRunResult | None
    status: ResponseWorkflowStatus
    created_at: datetime
    updated_at: datetime
    approval_reason: str | None = None
    rejection_reason: str | None = None


__all__ = [
    "DryRunResult",
    "DryRunStatus",
    "ResponseDecision",
    "ResponseDecisionStatus",
    "ResponseRequest",
    "ResponseTarget",
    "ResponseTargetKind",
    "ResponseWorkflowState",
    "ResponseWorkflowStatus",
]
