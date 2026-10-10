"""Desktop response-workflow state manager.

Provides the in-memory, bounded response-request registry and the
approval/rejection workflow that the Response Center page uses.  Every
operation is deterministic and side-effect free: clicking *Approve* only
updates the workflow status to ``APPROVED`` — nothing is executed, blocked or
modified on the host.

Imports of the response engine are lazy so opening the application loads no
response subsystem.
"""

from __future__ import annotations

import hashlib as _hl
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

from aegis_shared.logging import get_logger

if TYPE_CHECKING:  # pragma: no cover - typing only
    from aegis_desktop.services.detections import DetectionFinding
    from aegis_response_engine.audit.history import ResponseAuditHistory

logger = get_logger(__name__)

#: Default bound for the response-request registry.
MAX_RESPONSE_REQUESTS: int = 256


def _request_id(action: object, target_value: str, finding_ids: tuple[str, ...]) -> str:
    """Deterministic short request identity."""
    import hashlib as _hl

    payload = f"REQ|{action}|{target_value}|{'|'.join(sorted(finding_ids))}"
    return f"RR-{_hl.sha1(payload.encode(), usedforsecurity=False).hexdigest()[:12]}"


@dataclass(frozen=True)
class ResponseRequestView:
    """Read-only UI representation of one response-request workflow entry."""

    request_id: str
    action_label: str
    target: str
    risk_level: str
    risk_score: int
    policy_decision: str
    policy_version: str
    dry_run_status: str
    approval_status: str
    status: str
    created_at: datetime
    updated_at: datetime
    source_finding_ids: tuple[str, ...]
    incident_id: str | None
    reason: str
    rejection_reason: str | None
    execution_status: str = ""
    execution_message: str = ""
    execution_verified: bool = False
    execution_changed: bool = False
    execution_adapter: str = ""


@dataclass
class _Entry:
    """Internal mutable bookkeeping for one workflow request."""

    request: object  # ResponseRequest
    request_id: str
    decision: object | None  # ResponseDecision
    dry_run: object | None  # DryRunResult
    status: str  # ResponseWorkflowStatus value
    created_at: datetime
    updated_at: datetime
    rejection_reason: str | None = None
    policy_settings: object | None = None  # ResponsePolicySettings used for the decision
    execution_result: object | None = None  # ExecutionResult


class ResponseWorkflowManager:
    """In-memory, bounded response-request workflow registry."""

    def __init__(self, max_requests: int = MAX_RESPONSE_REQUESTS) -> None:
        self._max_requests = max_requests
        self._entries: dict[str, _Entry] = {}
        self._order: list[str] = []  # oldest first

    @property
    def count(self) -> int:
        """Current number of tracked requests."""
        return len(self._entries)

    def all_requests(self) -> tuple[ResponseRequestView, ...]:
        """Return all tracked requests as read-only views, newest first."""
        views: list[ResponseRequestView] = []
        for rid in reversed(self._order):
            entry = self._entries.get(rid)
            if entry is not None:
                views.append(self._to_view(entry))
        return tuple(views)

    def get(self, request_id: str) -> ResponseRequestView | None:
        """Return a read-only view for ``request_id`` or ``None``."""
        entry = self._entries.get(request_id)
        if entry is None:
            return None
        return self._to_view(entry)

    def pending_count(self) -> int:
        """Number of requests in ``pending_approval`` status."""
        return sum(
            1
            for e in self._entries.values()
            if e.status == "pending_approval"
        )

    def actionable_count(self) -> int:
        """Requests still awaiting operator action.

        Everything except the terminal statuses (``executed``, ``rejected`` and
        ``cancelled``) counts: a fresh ``draft`` is work someone still has to
        do — dry run, approval or execution — which is what the dashboard's
        Action Center reports.
        """
        return sum(
            1
            for e in self._entries.values()
            if e.status not in ("executed", "rejected", "cancelled")
        )

    def clear(self) -> None:
        """Drop every tracked request (test isolation and reset paths).

        The audit history is append-only and is deliberately left untouched.
        """
        self._entries.clear()
        self._order.clear()

    def approved_count(self) -> int:
        """Number of requests in ``approved`` status."""
        return sum(
            1
            for e in self._entries.values()
            if e.status == "approved"
        )

    def executed_count(self) -> int:
        """Number of requests in ``executed`` status."""
        return sum(
            1
            for e in self._entries.values()
            if e.status == "executed"
        )

    def create_request(
        self,
        finding: DetectionFinding,
        *,
        engine: object | None = None,
    ) -> ResponseRequestView | None:
        """Create a workflow entry from a real detection finding.

        Returns ``None`` when no response action is recommended for the finding.
        """
        try:
            from aegis_desktop.services.response_policy import collect_response_policy_view
            from aegis_response_engine.policy import (
                ResponsePolicyEngine,
                get_response_policy_settings,
            )

            policy_view = collect_response_policy_view(finding, engine=engine)
            if policy_view is None or not policy_view.available:
                return None

            resolved_engine = engine or ResponsePolicyEngine(get_response_policy_settings())
            # Rebuild the request through the same path the policy engine sees.
            from aegis_desktop.services.response_policy import _recommend
            from aegis_response_engine.policy import ResponseRequest
            from aegis_shared.enums import RiskLevel

            recommendation = _recommend(finding)
            if recommendation is None:
                return None
            action, target = recommendation

            risk_level_text = policy_view.risk_level
            try:
                level = RiskLevel(risk_level_text)
            except ValueError:
                level = RiskLevel.INFORMATIONAL

            request = ResponseRequest(
                action=action,  # type: ignore[arg-type]
                target=target,  # type: ignore[arg-type]
                risk_level=level,
                risk_score=policy_view.risk_score,
                timestamp=finding.timestamp,
                finding_ids=(finding.finding_id,),
                rule_ids=(finding.rule_id,),
                host_id=finding.host_id,
            )
            decision = resolved_engine.evaluate(request)  # type: ignore[attr-defined]

            rec_action = str(getattr(action, "value", action))
            rec_target = str(getattr(target, "value", target))
            rid = _request_id(
                policy_view.recommended_action or rec_action,
                policy_view.target or rec_target,
                (finding.finding_id,),
            )

            now = datetime.now()
            policy_settings = getattr(resolved_engine, "_settings", None)
            entry = _Entry(
                request=request,
                request_id=rid,
                decision=decision,
                dry_run=None,
                status="draft",
                created_at=now,
                updated_at=now,
                policy_settings=policy_settings,
            )
            self._register(rid, entry)
            return self._to_view(entry)

        except Exception as exc:
            logger.warning("Failed to create response request: %s", exc)
            return None

    def create_request_from_incident(
        self,
        incident_id: str,
        *,
        action_label: str,
        target_value: str,
        target_kind: str,
        risk_level: str,
        risk_score: int,
        finding_ids: tuple[str, ...] = (),
        engine: object | None = None,
    ) -> ResponseRequestView | None:
        """Create a workflow entry from an incident context.

        ``engine`` overrides the process-wide policy engine (mirrors
        :meth:`create_request`); the default stays the fail-closed global
        settings.
        """
        from aegis_response_engine.policy import (
            ResponsePolicyEngine,
            ResponseRequest,
            ResponseTarget,
            ResponseTargetKind,
            get_response_policy_settings,
        )
        from aegis_shared.enums import ActionType, RiskLevel

        _kind_map = {
            "ip": ResponseTargetKind.IP,
            "port": ResponseTargetKind.PORT,
            "host": ResponseTargetKind.HOST,
            "process": ResponseTargetKind.PROCESS,
            "file": ResponseTargetKind.FILE,
        }
        _action_map = {
            "block_ip": ActionType.BLOCK_IP,
            "unblock_ip": ActionType.UNBLOCK_IP,
            "block_port": ActionType.BLOCK_PORT,
            "host_isolate": ActionType.HOST_ISOLATE,
            "kill_process": ActionType.KILL_PROCESS,
            "quarantine_file": ActionType.QUARANTINE_FILE,
        }

        action = _action_map.get(action_label.lower().replace(" ", "_"))
        kind = _kind_map.get(target_kind.lower())
        if action is None or kind is None:
            return None

        try:
            level = RiskLevel(risk_level.lower())
        except ValueError:
            level = RiskLevel.INFORMATIONAL

        target = ResponseTarget(kind=kind, value=target_value)
        request = ResponseRequest(
            action=action,
            target=target,
            risk_level=level,
            risk_score=risk_score,
            timestamp=datetime.now(),
            finding_ids=finding_ids,
            incident_id=incident_id,
        )

        resolved_engine: Any = engine or ResponsePolicyEngine(get_response_policy_settings())
        decision = resolved_engine.evaluate(request)

        rid = _request_id(action_label, target_value, finding_ids)
        now = datetime.now()
        policy_settings = getattr(resolved_engine, "_settings", None)
        entry = _Entry(
            request=request,
            request_id=rid,
            decision=decision,
            dry_run=None,
            status="draft",
            created_at=now,
            updated_at=now,
            policy_settings=policy_settings,
        )
        self._register(rid, entry)
        return self._to_view(entry)

    def run_dry_run(self, request_id: str) -> ResponseRequestView | None:
        """Execute a deterministic dry run for ``request_id``.

        Returns the updated view or ``None`` if the request is unknown.
        """
        entry = self._entries.get(request_id)
        if entry is None:
            return None
        if entry.status not in ("draft", "dry_run_ready"):
            return self._to_view(entry)

        try:
            from aegis_response_engine.policy.dryrun import ResponseDryRunEngine

            settings = entry.policy_settings
            if settings is None:
                from aegis_response_engine.policy.config import ResponsePolicySettings
                settings = ResponsePolicySettings()
            engine = ResponseDryRunEngine(settings)  # type: ignore[arg-type]
            result = engine.simulate(entry.request)  # type: ignore[arg-type]
        except Exception as exc:
            logger.warning("Dry run failed for %s: %s", request_id, exc)
            return self._to_view(entry)

        entry.dry_run = result
        entry.status = "dry_run_completed"
        entry.updated_at = datetime.now()
        return self._to_view(entry)

    def request_approval(self, request_id: str) -> ResponseRequestView | None:
        """Move a completed dry-run request into pending-approval status."""
        entry = self._entries.get(request_id)
        if entry is None:
            return None
        if entry.status != "dry_run_completed":
            return self._to_view(entry)

        decision = entry.decision
        if decision is not None:
            d_status = getattr(decision, "status", None)
            if d_status is not None:
                decision_status = str(getattr(d_status, "value", d_status))
                if decision_status == "denied":
                    return self._to_view(entry)

        entry.status = "pending_approval"
        entry.updated_at = datetime.now()
        return self._to_view(entry)

    def approve(self, request_id: str) -> ResponseRequestView | None:
        """Approve a pending request.

        This only marks the workflow as approved — it does NOT execute any
        firewall, process or file action.
        """
        entry = self._entries.get(request_id)
        if entry is None:
            return None
        if entry.status != "pending_approval":
            return self._to_view(entry)

        decision = entry.decision
        if decision is not None:
            d_status = getattr(decision, "status", None)
            if d_status is not None:
                decision_status = str(getattr(d_status, "value", d_status))
                if decision_status == "denied":
                    return self._to_view(entry)

        entry.status = "approved"
        entry.updated_at = datetime.now()
        return self._to_view(entry)

    def reject(self, request_id: str, reason: str = "") -> ResponseRequestView | None:
        """Reject a pending request."""
        entry = self._entries.get(request_id)
        if entry is None:
            return None
        if entry.status != "pending_approval":
            return self._to_view(entry)

        entry.status = "rejected"
        entry.rejection_reason = reason or None
        entry.updated_at = datetime.now()
        return self._to_view(entry)

    def cancel(self, request_id: str) -> ResponseRequestView | None:
        """Cancel a request in any pre-approved state."""
        entry = self._entries.get(request_id)
        if entry is None:
            return None
        if entry.status in ("approved", "rejected", "cancelled"):
            return self._to_view(entry)

        entry.status = "cancelled"
        entry.updated_at = datetime.now()
        return self._to_view(entry)

    def fast_track_containment(self, request_id: str) -> ResponseRequestView | None:
        """One-click fast-track workflow: executes dry run, validates policy, and approves.

        Moves a request from draft/ready through dry run and approval in a single pass.
        Returns the updated view in 'approved' status (or blocked if policy forbids).
        """
        entry = self._entries.get(request_id)
        if entry is None:
            return None

        # Step 1: Run dry run if still in pre-dry-run state
        if entry.status in ("draft", "dry_run_ready"):
            v = self.run_dry_run(request_id)
            if v is None:
                return None
            if (v.dry_run_status or "").lower() != "would_apply":
                return v

        # Step 2: Request approval if dry run completed
        if entry.status == "dry_run_completed":
            v = self.request_approval(request_id)
            if v is None:
                return None

        # Step 3: Approve if pending approval
        if entry.status == "pending_approval":
            return self.approve(request_id)

        return self._to_view(entry)

    def direct_contain_ip(
        self,
        ip_address: str,
        *,
        reason: str = "Emergency Direct Containment",
        risk_level: str = "critical",
        risk_score: int = 95,
        engine: object | None = None,
    ) -> ResponseRequestView | None:
        """Create and prime an emergency IP containment request for execution."""
        req_view = self.create_request_from_incident(
            incident_id="RAPID-CONTAIN",
            action_label="block_ip",
            target_value=ip_address,
            target_kind="ip",
            risk_level=risk_level,
            risk_score=risk_score,
            engine=engine,
        )
        if req_view is None:
            return None
        return self.fast_track_containment(req_view.request_id)

    def execute(
        self,
        request_id: str,
        *,
        executor: object | None = None,
    ) -> ResponseRequestView | None:
        """Execute an approved request through the ResponseExecutor.

        Only approved requests with valid BLOCK_IP targets are executed.
        Returns the updated view with execution result.
        """
        entry = self._entries.get(request_id)
        if entry is None:
            return None
        if entry.status != "approved":
            return self._to_view(entry)

        workflow_status_before = entry.status

        try:
            from aegis_response_engine.executors.executor import ResponseExecutor

            resolved_executor = executor or ResponseExecutor()
            request = entry.request
            decision = entry.decision
            dry_run = entry.dry_run

            decision_status = None
            if decision is not None:
                decision_status = getattr(decision, "status", None)

            dry_run_status = None
            if dry_run is not None:
                dry_run_status = getattr(dry_run, "status", None)

            result = resolved_executor.execute(  # type: ignore[attr-defined]
                request,
                request_id=request_id,
                decision_status=decision_status,
                dry_run_status=dry_run_status,
                workflow_status=entry.status,
            )

            entry.execution_result = result
            if getattr(result, "success", False):
                entry.status = "executed"
            else:
                entry.status = "execution_failed"
            entry.updated_at = datetime.now()

            self._record_audit(entry, request_id, workflow_status_before)
        except Exception as exc:
            logger.warning("Execution failed for %s: %s", request_id, exc)

        return self._to_view(entry)

    def _record_audit(
        self,
        entry: _Entry,
        request_id: str,
        workflow_status_before: str,
    ) -> None:
        """Create and store an audit record for an execution attempt."""
        try:
            from aegis_response_engine.audit.models import (
                ResponseAuditRecord,
                VerificationStatus,
            )
        except Exception:
            return

        request = entry.request
        execution_result = entry.execution_result

        action = str(getattr(request, "action", ""))
        target_value = str(getattr(request, "target", ""))
        if hasattr(request, "target") and hasattr(request.target, "value"):
            target_value = request.target.value

        finding_ids = tuple(getattr(request, "finding_ids", ()))
        incident_id = getattr(request, "incident_id", None)
        if finding_ids:
            source_type = "detection"
            source_id = finding_ids[0]
        elif incident_id:
            source_type = "incident"
            source_id = incident_id
        else:
            source_type = "manual"
            source_id = "operator"

        decision = entry.decision
        policy_decision = ""
        if decision is not None:
            ds = getattr(decision, "status", None)
            if ds is not None:
                policy_decision = str(getattr(ds, "value", ds))

        dry_run_status = "not_started"
        if entry.dry_run is not None:
            ds = getattr(entry.dry_run, "status", None)
            if ds is not None:
                dry_run_status = str(getattr(ds, "value", ds))

        execution_status = "not_attempted"
        verification_status = VerificationStatus.NOT_APPLICABLE
        adapter_name = ""
        changed = False
        message = ""
        if execution_result is not None:
            if getattr(execution_result, "success", False):
                execution_status = "applied"
            else:
                execution_status = "failed"
            adapter_name = str(getattr(execution_result, "adapter_name", ""))
            message = str(getattr(execution_result, "message", ""))
            fw = getattr(execution_result, "firewall_result", None)
            if fw is not None:
                changed = bool(getattr(fw, "changed", False))
                verified = bool(getattr(fw, "verified", False))
                if verified:
                    verification_status = VerificationStatus.VERIFIED
                else:
                    verification_status = VerificationStatus.NOT_VERIFIED

        raw = f"{request_id}|{datetime.now().isoformat()}"
        audit_id = f"AR-{_hl.sha1(raw.encode(), usedforsecurity=False).hexdigest()[:12]}"

        record = ResponseAuditRecord(
            audit_id=audit_id,
            request_id=request_id,
            action=action,
            target=target_value,
            source_type=source_type,
            source_id=source_id,
            policy_decision=policy_decision,
            workflow_status_before=workflow_status_before,
            workflow_status_after=entry.status,
            dry_run_status=dry_run_status,
            execution_status=execution_status,
            verification_status=verification_status,
            adapter=adapter_name,
            changed=changed,
            message=message,
            timestamp=datetime.now(),
        )
        get_audit_history().add(record)

    # -- internal helpers --------------------------------------------------

    def _register(self, rid: str, entry: _Entry) -> None:
        """Insert or replace an entry, evicting the oldest when at capacity."""
        if rid in self._entries:
            self._order.remove(rid)
        elif len(self._entries) >= self._max_requests:
            oldest = self._order.pop(0)
            self._entries.pop(oldest, None)
        self._entries[rid] = entry
        self._order.append(rid)

    def _to_view(self, entry: _Entry) -> ResponseRequestView:
        from aegis_response_engine.policy.engine import ACTION_LABELS
        from aegis_shared.enums import ActionType

        request = entry.request
        action_val = getattr(request, "action", None)
        action_label = None
        if isinstance(action_val, ActionType):
            action_label = ACTION_LABELS.get(action_val)
        if not action_label:
            action_label = str(getattr(action_val, "value", action_val or "unknown"))
        target_value = str(getattr(request, "target", ""))
        if hasattr(request, "target") and hasattr(request.target, "value"):
            target_value = request.target.value

        risk_level = str(getattr(request, "risk_level", ""))
        if hasattr(request, "risk_level") and hasattr(request.risk_level, "value"):
            risk_level = request.risk_level.value

        decision_status = ""
        if entry.decision is not None:
            ds = getattr(entry.decision, "status", None)
            if ds is not None:
                decision_status = str(getattr(ds, "value", ds))

        dry_run_status = "not_started"
        if entry.dry_run is not None:
            ds = getattr(entry.dry_run, "status", None)
            if ds is not None:
                dry_run_status = str(getattr(ds, "value", ds))

        policy_version = ""
        if entry.decision is not None:
            policy_version = str(getattr(entry.decision, "policy_version", ""))

        finding_ids = tuple(getattr(request, "finding_ids", ()))
        incident_id = getattr(request, "incident_id", None)

        reason = ""
        if entry.decision is not None:
            reason = str(getattr(entry.decision, "reason", ""))

        return ResponseRequestView(
            request_id=entry.request_id,
            action_label=action_label,
            target=target_value,
            risk_level=risk_level,
            risk_score=getattr(request, "risk_score", 0),
            policy_decision=decision_status,
            policy_version=policy_version,
            dry_run_status=dry_run_status,
            approval_status=entry.status,
            status=entry.status,
            created_at=entry.created_at,
            updated_at=entry.updated_at,
            source_finding_ids=finding_ids,
            incident_id=incident_id,
            reason=reason,
            rejection_reason=entry.rejection_reason,
            execution_status=self._extract_execution_status(entry),
            execution_message=self._extract_execution_message(entry),
            execution_verified=self._extract_execution_verified(entry),
            execution_changed=self._extract_execution_changed(entry),
            execution_adapter=self._extract_execution_adapter(entry),
        )

    @staticmethod
    def _extract_execution_status(entry: _Entry) -> str:
        result = entry.execution_result
        if result is None:
            return ""
        status = getattr(result, "success", None)
        if status is True:
            return "applied"
        if status is False:
            return "failed"
        return ""

    @staticmethod
    def _extract_execution_message(entry: _Entry) -> str:
        result = entry.execution_result
        if result is None:
            return ""
        return str(getattr(result, "message", ""))

    @staticmethod
    def _extract_execution_verified(entry: _Entry) -> bool:
        result = entry.execution_result
        if result is None:
            return False
        fw = getattr(result, "firewall_result", None)
        if fw is None:
            return False
        return bool(getattr(fw, "verified", False))

    @staticmethod
    def _extract_execution_changed(entry: _Entry) -> bool:
        result = entry.execution_result
        if result is None:
            return False
        fw = getattr(result, "firewall_result", None)
        if fw is None:
            return False
        return bool(getattr(fw, "changed", False))

    @staticmethod
    def _extract_execution_adapter(entry: _Entry) -> str:
        result = entry.execution_result
        if result is None:
            return ""
        return str(getattr(result, "adapter_name", ""))


# ---------------------------------------------------------------------------
# Module-level singletons (used by all desktop pages)
# ---------------------------------------------------------------------------
_workflow_manager: ResponseWorkflowManager | None = None
_audit_history: ResponseAuditHistory | None = None


def get_workflow_manager() -> ResponseWorkflowManager:
    """Return the process-wide response workflow manager."""
    global _workflow_manager
    if _workflow_manager is None:
        _workflow_manager = ResponseWorkflowManager()
    return _workflow_manager


def get_audit_history() -> ResponseAuditHistory:
    """Return the process-wide response audit history."""
    global _audit_history
    if _audit_history is None:
        from aegis_response_engine.audit.history import ResponseAuditHistory

        _audit_history = ResponseAuditHistory()
    return _audit_history


__all__ = [
    "ResponseRequestView",
    "ResponseWorkflowManager",
    "get_audit_history",
    "get_workflow_manager",
]
