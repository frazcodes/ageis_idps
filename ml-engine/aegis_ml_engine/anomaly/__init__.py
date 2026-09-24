"""Anomaly detection for host and network behavioral features.

Exposes :class:`NetworkAnomalyModel` (flow features) and
:class:`HostAnomalyModel` (host behavior features), both wrapping a deterministic
Isolation Forest with an explicit fit/score lifecycle.
"""

from __future__ import annotations

from aegis_ml_engine.anomaly.host_model import (
    HostAnomalyModel,
    HostAnomalyResult,
    host_anomaly_to_signal,
)
from aegis_ml_engine.anomaly.model import (
    AnomalyResult,
    NetworkAnomalyModel,
    anomaly_to_signal,
)

__all__ = [
    "AnomalyResult",
    "HostAnomalyModel",
    "HostAnomalyResult",
    "NetworkAnomalyModel",
    "anomaly_to_signal",
    "host_anomaly_to_signal",
]
