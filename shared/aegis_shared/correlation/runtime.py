"""A tiny registry for the current security incidents.

The integrated runtime forms incidents as part of its bounded poll cycle; this
registry lets it publish the current in-memory incidents so that read-only
observers - such as the desktop Incidents page - can inspect them without
creating a second store or a database.

Publishing or reading incidents has no side effects: it never starts monitoring,
capture, evaluation, scoring, correlation or response.
"""

from __future__ import annotations

from aegis_shared.correlation.models import HostNetworkCorrelation, SecurityIncident

_active: tuple[SecurityIncident, ...] | None = None
_active_host_network: tuple[HostNetworkCorrelation, ...] | None = None


def set_active_incidents(incidents: tuple[SecurityIncident, ...] | None) -> None:
    """Publish (or clear) the current incidents for read-only observers."""
    global _active
    _active = tuple(incidents) if incidents is not None else None


def get_active_incidents() -> tuple[SecurityIncident, ...]:
    """Return the published incidents, or an empty tuple when none are published."""
    return _active or ()


def clear_active_incidents() -> None:
    """Clear the published incidents. Observers will show no incidents."""
    global _active
    _active = None


def set_active_host_network_correlations(
    correlations: tuple[HostNetworkCorrelation, ...] | None,
) -> None:
    """Publish (or clear) the current host/network correlations for observers."""
    global _active_host_network
    _active_host_network = tuple(correlations) if correlations is not None else None


def get_active_host_network_correlations() -> tuple[HostNetworkCorrelation, ...]:
    """Return the published host/network correlations, or an empty tuple."""
    return _active_host_network or ()


def clear_active_host_network_correlations() -> None:
    """Clear the published host/network correlations."""
    global _active_host_network
    _active_host_network = None


__all__ = [
    "clear_active_host_network_correlations",
    "clear_active_incidents",
    "get_active_host_network_correlations",
    "get_active_incidents",
    "set_active_host_network_correlations",
    "set_active_incidents",
]
