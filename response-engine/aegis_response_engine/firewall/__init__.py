"""Firewall adapter abstraction.

Platform-specific adapters implement the concrete OS operations (Windows
Firewall, iptables/nftables, cloud APIs).  The response executor never calls
OS commands directly; all firewall interaction flows through this interface.
"""

from __future__ import annotations

from aegis_response_engine.firewall.base import FirewallAdapter
from aegis_response_engine.firewall.models import FirewallActionResult, FirewallActionStatus
from aegis_response_engine.firewall.windows import WindowsFirewallAdapter

__all__ = [
    "FirewallActionResult",
    "FirewallActionStatus",
    "FirewallAdapter",
    "WindowsFirewallAdapter",
]
