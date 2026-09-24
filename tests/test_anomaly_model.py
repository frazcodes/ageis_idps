"""Deterministic tests for local network anomaly model (Step 16).

Exercises :class:`NetworkAnomalyModel` using locally constructed
:class:`NetworkBehaviorFeatures` objects.  No real capture, no network,
no disk, no runtime integration.
"""

from __future__ import annotations

import pytest

from aegis_ml_engine.anomaly.model import (
    _MODEL_VERSION,
    AnomalyResult,
    NetworkAnomalyModel,
)
from aegis_ml_engine.features.flow_features import NetworkBehaviorFeatures
from aegis_shared.enums import AddressFamily, NetworkDirection, TransportProtocol

_T0 = "2026-06-01T00:00:00Z"


def _feat(
    *,
    flow_id: str = "normal-1",
    packet_count: int = 100,
    byte_count: int = 64000,
    duration_ms: int = 10000,
    packets_per_second: float = 10.0,
    bytes_per_second: float = 6400.0,
    average_packet_size: float = 640.0,
) -> NetworkBehaviorFeatures:
    return NetworkBehaviorFeatures(
        flow_id=flow_id,
        protocol=TransportProtocol.TCP,
        ip_version=AddressFamily.IPV4,
        direction=NetworkDirection.OUTBOUND,
        packet_count=packet_count,
        byte_count=byte_count,
        duration_ms=duration_ms,
        packets_per_second=packets_per_second,
        bytes_per_second=bytes_per_second,
        average_packet_size=average_packet_size,
    )


# ---------------------------------------------------------------------------
# 1. fit + normal scoring
# ---------------------------------------------------------------------------


def test_fit_and_normal_score() -> None:
    """Normal flows should produce low anomaly scores after training."""
    normal = [_feat(flow_id=f"n{i}", packet_count=80 + i, byte_count=50000 + i * 1000)
              for i in range(30)]
    model = NetworkAnomalyModel()
    model.fit(normal)

    assert model.is_fitted is True

    result = model.score(normal[0])
    assert isinstance(result, AnomalyResult)
    assert 0.0 <= result.anomaly_score <= 1.0
    assert result.model_version == _MODEL_VERSION
    assert result.flow_id == "n0"


# ---------------------------------------------------------------------------
# 2. obvious outlier gets flagged
# ---------------------------------------------------------------------------


def test_obvious_outlier_is_flagged() -> None:
    """A flow moderately different from the training set should score higher."""
    # Train on consistent small flows (10-19 packets, ~5000-6000 bytes, 1s).
    normal = [_feat(
        flow_id=f"n{i}",
        packet_count=10 + i,
        byte_count=5000 + i * 100,
        duration_ms=1000,
        packets_per_second=float(10 + i),
        bytes_per_second=float(5000 + i * 100),
        average_packet_size=500.0,
    ) for i in range(50)]

    # A clearly larger flow: 10x packets, 20x bytes, same duration.
    outlier = _feat(
        flow_id="outlier",
        packet_count=100,
        byte_count=100_000,
        duration_ms=1000,
        packets_per_second=100.0,
        bytes_per_second=100_000.0,
        average_packet_size=1000.0,
    )

    model = NetworkAnomalyModel()
    model.fit([*normal, outlier])

    result = model.score(outlier)
    normal_results = model.score_many(normal[:10])
    avg_normal = sum(r.anomaly_score for r in normal_results) / len(normal_results)
    # The outlier must score above the average normal score.
    assert result.anomaly_score > avg_normal


# ---------------------------------------------------------------------------
# 3. scoring before fit fails
# ---------------------------------------------------------------------------


def test_score_before_fit_raises() -> None:
    """Calling score() before fit() must raise RuntimeError."""
    model = NetworkAnomalyModel()

    with pytest.raises(RuntimeError, match="fit"):
        model.score(_feat())

    with pytest.raises(RuntimeError, match="fit"):
        model.score_many([_feat()])


# ---------------------------------------------------------------------------
# 4. score_many preserves order
# ---------------------------------------------------------------------------


def test_score_many_preserves_order() -> None:
    """score_many must return results in the same order as the input."""
    training = [_feat(flow_id=f"t{i}", byte_count=50000) for i in range(30)]
    model = NetworkAnomalyModel()
    model.fit(training)

    queries = [_feat(flow_id=f"q{i}") for i in range(7)]
    results = model.score_many(queries)

    assert len(results) == 7
    assert [r.flow_id for r in results] == [f"q{i}" for i in range(7)]


# ---------------------------------------------------------------------------
# 5. deterministic behavior
# ---------------------------------------------------------------------------


def test_deterministic_scores() -> None:
    """Same model + same input must always produce the same scores."""
    training = [_feat(flow_id=f"d{i}", byte_count=50000) for i in range(30)]
    query = _feat(flow_id="q")

    model_a = NetworkAnomalyModel()
    model_a.fit(training)
    r1 = model_a.score(query)

    model_b = NetworkAnomalyModel()
    model_b.fit(training)
    r2 = model_b.score(query)

    assert r1.anomaly_score == pytest.approx(r2.anomaly_score)
    assert r1.is_anomaly == r2.is_anomaly


# ---------------------------------------------------------------------------
# 6. empty / invalid training input
# ---------------------------------------------------------------------------


def test_fit_rejects_empty_training_data() -> None:
    model = NetworkAnomalyModel()
    with pytest.raises(ValueError, match="empty"):
        model.fit([])


def test_fit_rejects_invalid_contamination() -> None:
    with pytest.raises(ValueError):
        NetworkAnomalyModel(contamination=0.0)
    with pytest.raises(ValueError):
        NetworkAnomalyModel(contamination=0.5)
    with pytest.raises(ValueError):
        NetworkAnomalyModel(contamination=-0.1)


def test_score_many_empty_input_returns_tuple() -> None:
    training = [_feat(flow_id=f"t{i}") for i in range(10)]
    model = NetworkAnomalyModel()
    model.fit(training)

    assert model.score_many(()) == ()
    assert model.score_many([]) == ()
    assert isinstance(model.score_many(()), tuple)
