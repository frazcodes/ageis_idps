"""Read-only local listening-port monitoring.

Public API
----------
* :func:`collect_port_snapshot` / :class:`PortCollector` - enumerate endpoints.
* :class:`PortRecord` / :class:`PortSnapshot` / :class:`PortChanges` - models.
* :class:`PortMonitor` - snapshot diffing (``start``/``snapshot``/``poll``/``stop``).
* :func:`changes_to_events` - map changes onto ``aegis_shared`` ``SecurityEvent``.
* :func:`format_endpoint` - unambiguous endpoint formatting.

The monitor is read-only: it never binds, closes or modifies a socket, never
requests elevation, and never touches a firewall. Prevention belongs to the
future Response Engine, not here.
"""

from __future__ import annotations

from aegis_agent.monitors.port.addressing import format_endpoint
from aegis_agent.monitors.port.collector import PortCollector, collect_port_snapshot
from aegis_agent.monitors.port.events import build_port_event, changes_to_events
from aegis_agent.monitors.port.models import (
    PortChanges,
    PortIdentity,
    PortRecord,
    PortSnapshot,
)
from aegis_agent.monitors.port.monitor import PortMonitor

__all__ = [
    "PortChanges",
    "PortCollector",
    "PortIdentity",
    "PortMonitor",
    "PortRecord",
    "PortSnapshot",
    "build_port_event",
    "changes_to_events",
    "collect_port_snapshot",
    "format_endpoint",
]
