"""Aegis IDPS endpoint agent.

Host-side collector that runs on Windows and Linux endpoints and will report
:class:`aegis_shared.events.SecurityEvent` records to the central backend.

Implemented today: read-only :mod:`aegis_agent.inventory` (system facts and
stable host identity). All monitoring features remain disabled by default and
nothing runs until explicitly enabled in configuration.
"""

from __future__ import annotations

from aegis_agent.config import AgentSettings, get_agent_settings

__all__ = ["AgentSettings", "get_agent_settings"]
