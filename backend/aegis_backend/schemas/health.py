"""Schema for the health endpoint."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict


class HealthResponse(BaseModel):
    """Result of a successful liveness probe."""

    model_config = ConfigDict(frozen=True)

    status: Literal["ok"]
    service: str
    version: str


__all__ = ["HealthResponse"]
