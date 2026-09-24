"""Immutable firewall-action result models.

A :class:`FirewallActionResult` records the deterministic outcome of one
firewall operation (block, unblock, verify).  Nothing here executes commands;
it only describes what happened or would happen.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class FirewallActionStatus(StrEnum):
    """Outcome of a single firewall action."""

    APPLIED = "applied"
    ALREADY_APPLIED = "already_applied"
    FAILED = "failed"
    NOT_SUPPORTED = "not_supported"
    INVALID_TARGET = "invalid_target"


@dataclass(frozen=True)
class FirewallActionResult:
    """Deterministic result of one firewall operation (no side effects)."""

    action: str
    target: str
    status: FirewallActionStatus
    message: str
    changed: bool
    verified: bool
    adapter: str
    timestamp: datetime
    rule_name: str = ""
    command: str = ""


__all__ = ["FirewallActionResult", "FirewallActionStatus"]
