"""Response executor: controlled execution of approved response actions.

Receives an approved workflow entry, validates all guards, selects the
appropriate firewall adapter, executes the action and returns a deterministic
result.  The executor never makes policy decisions, creates findings or
calculates risk.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from aegis_response_engine.firewall.base import FirewallAdapter
from aegis_response_engine.firewall.models import FirewallActionResult, FirewallActionStatus
from aegis_response_engine.firewall.windows import WindowsFirewallAdapter
from aegis_response_engine.policy.models import (
    ResponseRequest,
    ResponseTargetKind,
    ResponseWorkflowStatus,
)
from aegis_shared.enums import ActionType
from aegis_shared.logging import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class ExecutionResult:
    """Deterministic result of one response-execution attempt."""

    request_id: str
    action: str
    target: str
    success: bool
    message: str
    firewall_result: FirewallActionResult | None
    timestamp: datetime
    adapter_name: str = ""


class ResponseExecutor:
    """Controlled execution of approved BLOCK_IP actions.

    All guards are checked before execution.  If any guard fails, execution
    does not happen and a clear failure result is returned.
    """

    def __init__(self, adapter: FirewallAdapter | None = None) -> None:
        self._adapter = adapter or WindowsFirewallAdapter()

    @property
    def adapter(self) -> FirewallAdapter:
        """The firewall adapter used for execution."""
        return self._adapter

    def execute(
        self,
        request: ResponseRequest,
        *,
        request_id: str,
        decision_status: object | None = None,
        dry_run_status: object | None = None,
        workflow_status: str,
    ) -> ExecutionResult:
        """Execute an approved response request.

        Returns a deterministic result.  Only ``BLOCK_IP`` is supported in
        Step 30; all other actions are rejected.
        """
        now = datetime.now()

        # Guard 1: action must be BLOCK_IP
        if request.action is not ActionType.BLOCK_IP:
            return ExecutionResult(
                request_id=request_id,
                action=request.action.value,
                target=request.target.value,
                success=False,
                message="Execution denied: action is not supported by Step 30.",
                firewall_result=None,
                timestamp=now,
                adapter_name=self._adapter.adapter_name,
            )

        # Guard 2: workflow must be APPROVED
        if workflow_status != ResponseWorkflowStatus.APPROVED:
            return ExecutionResult(
                request_id=request_id,
                action=request.action.value,
                target=request.target.value,
                success=False,
                message=f"Execution denied: workflow is not approved (current: {workflow_status}).",
                firewall_result=None,
                timestamp=now,
                adapter_name=self._adapter.adapter_name,
            )

        # Guard 3: policy decision must permit the action
        if decision_status is not None:
            ds = str(getattr(decision_status, "value", decision_status))
            if ds not in ("requires_approval", "allowed"):
                return ExecutionResult(
                    request_id=request_id,
                    action=request.action.value,
                    target=request.target.value,
                    success=False,
                    message=f"Execution denied: policy decision is {ds}.",
                    firewall_result=None,
                    timestamp=now,
                    adapter_name=self._adapter.adapter_name,
                )

        # Guard 4: dry run must have completed successfully
        if dry_run_status is not None:
            drs = str(getattr(dry_run_status, "value", dry_run_status))
            if drs not in ("would_apply",):
                return ExecutionResult(
                    request_id=request_id,
                    action=request.action.value,
                    target=request.target.value,
                    success=False,
                    message=f"Execution denied: dry run status is {drs}.",
                    firewall_result=None,
                    timestamp=now,
                    adapter_name=self._adapter.adapter_name,
                )

        # Guard 5: target must be valid IP
        if request.target.kind is not ResponseTargetKind.IP:
            return ExecutionResult(
                request_id=request_id,
                action=request.action.value,
                target=request.target.value,
                success=False,
                message="Execution denied: target is not a valid IP address.",
                firewall_result=None,
                timestamp=now,
                adapter_name=self._adapter.adapter_name,
            )

        # All guards passed — execute
        logger.info(
            "Executing BLOCK_IP for %s (request %s)",
            request.target.value,
            request_id,
        )
        fw_result = self._adapter.block_ip(request.target.value)

        return ExecutionResult(
            request_id=request_id,
            action=request.action.value,
            target=request.target.value,
            success=fw_result.status in (
                FirewallActionStatus.APPLIED,
                FirewallActionStatus.ALREADY_APPLIED,
            ),
            message=fw_result.message,
            firewall_result=fw_result,
            timestamp=now,
            adapter_name=self._adapter.adapter_name,
        )


__all__ = ["ExecutionResult", "ResponseExecutor"]
