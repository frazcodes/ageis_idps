"""Local anomaly detection for host behavioral features.

Mirrors :mod:`aegis_ml_engine.anomaly.model` (the network anomaly model) but
operates on the ten numeric fields produced by
:class:`~aegis_ml_engine.features.host_features.HostBehaviorFeatures`.

Only aggregate behavioral counts are used - no process names, command lines,
file paths, hashes, usernames or file contents ever reach the model.

This module is **pure**: it performs no I/O, starts no threads, mutates no
input, and persists nothing to disk. The model lifecycle is explicit:
``UNFITTED -> FITTED`` via :meth:`HostAnomalyModel.fit`.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np
from sklearn.ensemble import IsolationForest  # type: ignore[import-untyped]

from aegis_ml_engine.features.host_features import HostBehaviorFeatures
from aegis_shared.risk.models import AnomalySignal

_MODEL_VERSION = "1.0.0"

#: Numeric behavioral fields fed to the model, in fixed order.
_FEATURE_COLUMNS: tuple[str, ...] = (
    "process_count",
    "listening_port_count",
    "file_change_count",
    "new_process_count",
    "terminated_process_count",
    "new_listening_port_count",
    "removed_listening_port_count",
    "file_created_count",
    "file_modified_count",
    "file_deleted_count",
)

_RANDOM_STATE = 42


def _to_row(feat: HostBehaviorFeatures) -> list[float]:
    return [float(getattr(feat, name)) for name in _FEATURE_COLUMNS]


@dataclass(frozen=True)
class HostAnomalyResult:
    """Immutable result of a single host anomaly-score evaluation."""

    host_id: str | None
    anomaly_score: float
    is_anomaly: bool
    model_version: str


class HostAnomalyModel:
    """Lightweight Isolation Forest anomaly detector for host behavior.

    Usage::

        model = HostAnomalyModel()
        model.fit(baseline_features)   # UNFITTED -> FITTED
        result = model.score(features)  # only after fit
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

    def fit(self, features: Sequence[HostBehaviorFeatures]) -> None:
        """Train the Isolation Forest on baseline host features.

        Raises:
            ValueError: if *features* is empty.
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

    @staticmethod
    def _normalize(raw: float) -> float:
        score = 1.0 / (1.0 + raw)
        return max(0.0, min(1.0, score))

    def score(self, feature: HostBehaviorFeatures) -> HostAnomalyResult:
        """Score one host observation against the trained baseline.

        The raw Isolation Forest ``decision_function`` is rescaled to a 0-1
        range where higher means more anomalous.

        Raises:
            RuntimeError: if called before :meth:`fit`.
        """
        self._check_fitted()
        row = np.array([_to_row(feature)], dtype=np.float64)
        raw = float(self._model.decision_function(row)[0])  # type: ignore[union-attr]
        return HostAnomalyResult(
            host_id=feature.host_id,
            anomaly_score=self._normalize(raw),
            is_anomaly=self._normalize(raw) > 0.5,
            model_version=_MODEL_VERSION,
        )

    def score_many(
        self, features: Sequence[HostBehaviorFeatures]
    ) -> tuple[HostAnomalyResult, ...]:
        """Score many host observations, preserving input order.

        Returns an empty tuple for empty input.
        """
        if not features:
            return ()
        self._check_fitted()
        rows = np.array([_to_row(f) for f in features], dtype=np.float64)
        raw_scores = self._model.decision_function(rows)  # type: ignore[union-attr]

        results: list[HostAnomalyResult] = []
        for feat, raw in zip(features, raw_scores, strict=True):
            score = self._normalize(float(raw))
            results.append(
                HostAnomalyResult(
                    host_id=feat.host_id,
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


def host_anomaly_to_signal(result: HostAnomalyResult) -> AnomalySignal:
    """Convert a :class:`HostAnomalyResult` to an :class:`AnomalySignal`."""
    return AnomalySignal(
        source="host_behavior",
        score=result.anomaly_score,
        confidence=1.0,
        model_version=result.model_version,
        reason="host behavior differs from the learned baseline",
    )


__all__ = [
    "_FEATURE_COLUMNS",
    "_MODEL_VERSION",
    "HostAnomalyModel",
    "HostAnomalyResult",
    "host_anomaly_to_signal",
]
