"""Abstract firewall adapter base class.

Platform-specific adapters (Windows, Linux) implement the concrete operations.
The adapter abstraction ensures the response executor never directly calls OS
commands; all firewall interaction flows through this interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from aegis_response_engine.firewall.models import FirewallActionResult


class FirewallAdapter(ABC):
    """Abstract base for platform-specific firewall adapters."""

    @property
    @abstractmethod
    def adapter_name(self) -> str:
        """Human-readable adapter identifier (e.g. ``Windows Firewall``)."""

    @abstractmethod
    def block_ip(self, ip: str, *, timeout: float = 30.0) -> FirewallActionResult:
        """Block inbound network traffic from ``ip``.

        Returns a deterministic result describing the outcome.  May be called
        repeatedly; must be idempotent.
        """

    @abstractmethod
    def unblock_ip(self, ip: str, *, timeout: float = 30.0) -> FirewallActionResult:
        """Remove a previously created Aegis block rule for ``ip``."""

    @abstractmethod
    def is_blocked(self, ip: str, *, timeout: float = 30.0) -> FirewallActionResult:
        """Verify whether ``ip`` is currently blocked by an Aegis rule."""


__all__ = ["FirewallAdapter"]
