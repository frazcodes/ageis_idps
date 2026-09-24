"""Immutable audit-record value objects.

A :class:`ResponseAuditRecord` captures a single point-in-time snapshot of a
response-request lifecycle event (execution success, failure, verification).
Records are append-only and never mutated.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class VerificationStatus(StrEnum):
    """Post-execution verification outcome."""

    VERIFIED = "verified"
    NOT_VERIFIED = "not_verified"
    VERIFICATION_FAILED = "verification_failed"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True)
class ResponseAuditRecord:
    """Immutable audit record for one response-action lifecycle event.

    Every field is frozen at creation time.  The record captures the full
    context needed for forensic review and compliance auditing.
    """

    audit_id: str
    request_id: str
    action: str
    target: str
    source_type: str  # "detection" | "incident" | "manual"
    source_id: str  # finding_id, incident_id, or operator name
    policy_decision: str
    workflow_status_before: str
    workflow_status_after: str
    dry_run_status: str
    execution_status: str  # "applied" | "failed" | "not_attempted"
    verification_status: str  # VerificationStatus value
    adapter: str
    changed: bool
    message: str
    timestamp: datetime


__all__ = ["ResponseAuditRecord", "VerificationStatus"]
