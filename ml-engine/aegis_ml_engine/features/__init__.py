"""Feature extraction for anomaly detection.

Converts host and network events into fixed-length numeric vectors consumed by
anomaly detectors. Feature definitions are versioned alongside the model that
was trained on them.
"""

from __future__ import annotations

from aegis_ml_engine.features.flow_features import (
    NetworkBehaviorFeatures,
    extract_batch,
    extract_flow_features,
)
from aegis_ml_engine.features.host_features import (
    HostBehaviorFeatures,
    extract_host_features,
)

__all__ = [
    "HostBehaviorFeatures",
    "NetworkBehaviorFeatures",
    "extract_batch",
    "extract_flow_features",
    "extract_host_features",
]
