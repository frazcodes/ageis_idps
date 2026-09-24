"""Deterministic schema/data validation for events entering a pipeline.

This is **not** threat detection. It only checks that an event is structurally
sound and internally consistent, so malformed data cannot propagate to a future
exporter or backend. The canonical :class:`SecurityEvent` already validates on
construction; this layer additionally defends against events built via
``model_construct`` or deserialised from an untrusted source and against semantic
gaps the base model does not enforce:

* empty ``event_id``
* malformed or incompatible ``schema_version``
* missing ``event_type`` / ``category`` or a mismatch between them
* naive (timezone-less) ``timestamp``
* an event type whose required context block is absent

It covers every canonical event type, host and network alike, so both the host
and network pipelines share one validator.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from aegis_shared.enums import EventCategory, EventType
from aegis_shared.events import SecurityEvent
from aegis_shared.version import EVENT_SCHEMA_VERSION

_SCHEMA_VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")

#: Events within the same MAJOR schema version are considered compatible.
_CURRENT_MAJOR = EVENT_SCHEMA_VERSION.split(".", 1)[0]

#: Event type -> context attribute that must be present.
_REQUIRED_CONTEXT: dict[EventType, str] = {
    EventType.PROCESS_STARTED: "process",
    EventType.PROCESS_STOPPED: "process",
    EventType.PORT_LISTENING: "socket",
    EventType.PORT_CLOSED: "socket",
    EventType.FILE_CREATED: "file",
    EventType.FILE_MODIFIED: "file",
    EventType.FILE_DELETED: "file",
    EventType.NETWORK_PACKET_OBSERVED: "network",
    EventType.FLOW_SUMMARY: "network",
}


class ValidationIssue(BaseModel):
    """A single reason an event failed validation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    field: str
    message: str


class ValidationResult(BaseModel):
    """The outcome of validating one event."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    valid: bool
    issues: tuple[ValidationIssue, ...] = ()

    def summary(self) -> str | None:
        """A compact, deterministic reason string, or ``None`` when valid."""
        if self.valid:
            return None
        return "; ".join(f"{issue.field}: {issue.message}" for issue in self.issues)


def validate_event(event: SecurityEvent) -> ValidationResult:
    """Validate a canonical event for pipeline admission.

    Deterministic: the same event always yields the same result, and issues are
    ordered by the checks below.
    """
    if not isinstance(event, SecurityEvent):
        return ValidationResult(
            valid=False,
            issues=(ValidationIssue(field="event", message="not a SecurityEvent"),),
        )

    issues: list[ValidationIssue] = []

    event_id = getattr(event, "event_id", None)
    if not isinstance(event_id, str) or not event_id.strip():
        issues.append(ValidationIssue(field="event_id", message="must be a non-empty string"))

    version = getattr(event, "schema_version", None)
    if not isinstance(version, str) or not _SCHEMA_VERSION_PATTERN.match(version):
        issues.append(
            ValidationIssue(field="schema_version", message="must match MAJOR.MINOR.PATCH")
        )
    elif version.split(".", 1)[0] != _CURRENT_MAJOR:
        issues.append(
            ValidationIssue(
                field="schema_version",
                message=f"unsupported major version (expected {_CURRENT_MAJOR}.x.x)",
            )
        )

    event_type = getattr(event, "event_type", None)
    if not isinstance(event_type, EventType):
        issues.append(ValidationIssue(field="event_type", message="must be a known EventType"))
    else:
        expected_category = EventCategory(event_type.value.split(".", 1)[0])
        category = getattr(event, "category", None)
        if not isinstance(category, EventCategory):
            issues.append(
                ValidationIssue(field="category", message="must be a known EventCategory")
            )
        elif category is not expected_category:
            issues.append(
                ValidationIssue(
                    field="category",
                    message=f"{category.value!r} does not match event_type {event_type.value!r}",
                )
            )

        required = _REQUIRED_CONTEXT.get(event_type)
        if required is not None and getattr(event, required, None) is None:
            issues.append(
                ValidationIssue(
                    field=required,
                    message=f"required context missing for {event_type.value}",
                )
            )

    timestamp = getattr(event, "timestamp", None)
    if not _is_aware(timestamp):
        issues.append(
            ValidationIssue(field="timestamp", message="must be a timezone-aware datetime")
        )

    return ValidationResult(valid=not issues, issues=tuple(issues))


def _is_aware(value: Any) -> bool:
    if not isinstance(value, datetime):
        return False
    return value.tzinfo is not None and value.tzinfo.utcoffset(value) is not None


def is_valid(event: SecurityEvent) -> bool:
    """Convenience predicate: whether ``event`` would be admitted."""
    return validate_event(event).valid


__all__ = ["ValidationIssue", "ValidationResult", "is_valid", "validate_event"]
