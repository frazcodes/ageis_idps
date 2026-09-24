"""Local anomaly detection for network behavioral features.

Wraps :class:`sklearn.ensemble.IsolationForest` with a minimal, deterministic
interface tailored to the six numeric fields produced by
:class:`~aegis_ml_engine.features.flow_features.NetworkBehaviorFeatures`.

This module is **pure** — it performs no I/O, starts no threads, mutates no
input, and persists nothing to disk.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np
from sklearn.ensemble import IsolationForest  # type: ignore[import-untyped]

from aegis_ml_engine.features.flow_features import NetworkBehaviorFeatures
from aegis_shared.risk.models import AnomalySignal

_MODEL_VERSION = "1.0.0"

# Numeric fields fed to the model, in fixed order.
_FEATURE_COLUMNS: tuple[str, ...] = (
    "packet_count",
    "byte_count",
    "duration_ms",
    "packets_per_second",
    "bytes_per_second",
    "average_packet_size",
)

_RANDOM_STATE = 42


def _to_row(feat: NetworkBehaviorFeatures) -> list[float]:
    return [
        float(feat.packet_count),
        float(feat.byte_count),
        float(feat.duration_ms),
        feat.packets_per_second,
        feat.bytes_per_second,
        feat.average_packet_size,
    ]


@dataclass(frozen=True)
class AnomalyResult:
    """Immutable result of a single anomaly-score evaluation."""

    flow_id: str
    anomaly_score: float
    is_anomaly: bool
    model_version: str


class NetworkAnomalyModel:
    """Lightweight Isolation Forest anomaly detector for network flows.

    Usage::

        model = NetworkAnomalyModel()
        model.fit(features)
        result = model.score(features[0])
        results = model.score_many(features)
    """

    def __init__(self, contamination: float = 0.05) -> None:
        if not (0.0 < contamination < 0.5):
            raise ValueError("contamination must be in (0.0, 0.5)")
        self._contamination = contamination
        self._model: IsolationForest | None = None
        self._is_fitted: bool = False

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def fit(self, features: Sequence[NetworkBehaviorFeatures]) -> None:
        """Train the Isolation Forest on normal-flow features.

        Parameters
        ----------
        features:
            Non-empty sequence of :class:`NetworkBehaviorFeatures`.

        Raises
        ------
        ValueError
            If *features* is empty.
        """
        if not features:
            raise ValueError("Training data must not be empty.")

        x = np.array([_to_row(f) for f in features], dtype=np.float64)

        self._model = IsolationForest(
            contamination=self._contamination,
            random_state=_RANDOM_STATE,
            n_estimators=100,
        )
        self._model.fit(x)
        self._is_fitted = True

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def _check_fitted(self) -> None:
        if not self._is_fitted or self._model is None:
            raise RuntimeError("Model has not been trained. Call fit() first.")

    def score(self, feature: NetworkBehaviorFeatures) -> AnomalyResult:
        """Score a single flow against the trained baseline.

        The raw Isolation Forest ``decision_function`` is rescaled to a
        **0-1** range where **higher means more anomalous**:

        ``anomaly_score = 1 / (1 + decision_function)``

        Returns
        -------
        AnomalyResult
            Frozen result with ``anomaly_score``, ``is_anomaly``,
            ``model_version``, and ``flow_id``.

        Raises
        ------
        RuntimeError
            If called before :meth:`fit`.
        """
        self._check_fitted()

        row = np.array([_to_row(feature)], dtype=np.float64)
        raw = float(self._model.decision_function(row)[0])  # type: ignore[union-attr]

        # decision_function returns higher values for inliers.
        # Map to 0-1 where 1 = most anomalous.
        score = 1.0 / (1.0 + raw)
        # Clamp to [0, 1] for safety (raw can be negative for strong outliers).
        score = max(0.0, min(1.0, score))

        return AnomalyResult(
            flow_id=feature.flow_id,
            anomaly_score=score,
            is_anomaly=score > 0.5,
            model_version=_MODEL_VERSION,
        )

    def score_many(self, features: Sequence[NetworkBehaviorFeatures]) -> tuple[AnomalyResult, ...]:
        """Score multiple flows, preserving input order.

        Returns an empty tuple for empty input.
        """
        if not features:
            return ()

        self._check_fitted()

        rows = np.array([_to_row(f) for f in features], dtype=np.float64)
        raw_scores = self._model.decision_function(rows)  # type: ignore[union-attr]

        results: list[AnomalyResult] = []
        for feat, raw in zip(features, raw_scores, strict=True):
            score = 1.0 / (1.0 + float(raw))
            score = max(0.0, min(1.0, score))
            results.append(
                AnomalyResult(
                    flow_id=feat.flow_id,
                    anomaly_score=score,
                    is_anomaly=score > 0.5,
                    model_version=_MODEL_VERSION,
                )
            )

        return tuple(results)

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def is_fitted(self) -> bool:
        """Whether :meth:`fit` has been called successfully."""
        return self._is_fitted

    @property
    def model_version(self) -> str:
        return _MODEL_VERSION

    @property
    def contamination(self) -> float:
        return self._contamination


def anomaly_to_signal(result: AnomalyResult) -> AnomalySignal:
    """Convert an :class:`AnomalyResult` to an :class:`AnomalySignal`.

    The signal carries the score and model version in the format expected by
    the risk engine's ``anomaly`` field.
    """
    return AnomalySignal(
        source="network_anomaly",
        score=result.anomaly_score,
        confidence=1.0,
        model_version=result.model_version,
    )


__all__ = [
    "_FEATURE_COLUMNS",
    "_MODEL_VERSION",
    "AnomalyResult",
    "NetworkAnomalyModel",
    "anomaly_to_signal",
]
