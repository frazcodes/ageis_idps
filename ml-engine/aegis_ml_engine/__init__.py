"""Aegis IDPS ML engine.

Anomaly detection and risk scoring. The package defines feature extraction,
model training and scoring boundaries.
"""

from __future__ import annotations

from aegis_ml_engine.anomaly import (
    AnomalyResult,
    HostAnomalyModel,
    HostAnomalyResult,
    NetworkAnomalyModel,
    anomaly_to_signal,
    host_anomaly_to_signal,
)
from aegis_ml_engine.config import MLEngineSettings, get_ml_settings
from aegis_ml_engine.features import (
    HostBehaviorFeatures,
    NetworkBehaviorFeatures,
    extract_batch,
    extract_flow_features,
    extract_host_features,
)

__all__ = [
    "AnomalyResult",
    "HostAnomalyModel",
    "HostAnomalyResult",
    "HostBehaviorFeatures",
    "MLEngineSettings",
    "NetworkAnomalyModel",
    "NetworkBehaviorFeatures",
    "anomaly_to_signal",
    "extract_batch",
    "extract_flow_features",
    "extract_host_features",
    "get_ml_settings",
    "host_anomaly_to_signal",
]
