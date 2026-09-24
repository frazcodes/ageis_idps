"""Deterministic correlation of related security activity into incidents.

This layer groups existing findings/events/risk assessments that belong to the
same host within a bounded time window into a :class:`SecurityIncident`. It
introduces no new detection, scoring or response: it reuses the existing
contracts and remains evidence-based and explainable.

**Correlated activity != confirmed compromise.**
"""

from __future__ import annotations

from aegis_shared.correlation.config import (
    CorrelationSettings,
    get_correlation_settings,
)
from aegis_shared.correlation.engine import IncidentCorrelator
from aegis_shared.correlation.host_network import HostNetworkCorrelator
from aegis_shared.correlation.models import HostNetworkCorrelation, SecurityIncident
from aegis_shared.correlation.runtime import (
    clear_active_host_network_correlations,
    clear_active_incidents,
    get_active_host_network_correlations,
    get_active_incidents,
    set_active_host_network_correlations,
    set_active_incidents,
)

__all__ = [
    "CorrelationSettings",
    "HostNetworkCorrelation",
    "HostNetworkCorrelator",
    "IncidentCorrelator",
    "SecurityIncident",
    "clear_active_host_network_correlations",
    "clear_active_incidents",
    "get_active_host_network_correlations",
    "get_active_incidents",
    "get_correlation_settings",
    "set_active_host_network_correlations",
    "set_active_incidents",
]
