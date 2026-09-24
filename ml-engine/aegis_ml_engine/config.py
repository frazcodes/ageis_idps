"""Configuration for the Aegis ML engine."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import SettingsConfigDict

from aegis_shared.config import AegisSettings


class MLEngineSettings(AegisSettings):
    """Settings for the anomaly detection engine."""

    model_config = SettingsConfigDict(
        env_prefix="AEGIS_ML_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    model_dir: str = Field(
        default="ml-engine/aegis_ml_engine/artifacts",
        description="Directory holding serialised model artifacts.",
    )
    contamination: float = Field(
        default=0.05,
        gt=0.0,
        lt=0.5,
        description="Expected proportion of outliers (anomaly-detection prior).",
    )
    risk_threshold: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="Score above which an observation is treated as high risk.",
    )
    host_baseline_min_observations: int = Field(
        default=20,
        ge=2,
        description=(
            "Minimum number of host behavior observations collected before the "
            "host anomaly model is fitted. Prevents training on a single sample."
        ),
    )


@lru_cache(maxsize=1)
def get_ml_settings() -> MLEngineSettings:
    """Return the process-wide ML settings (loaded once)."""
    return MLEngineSettings()


__all__ = ["MLEngineSettings", "get_ml_settings"]
