"""Pydantic request/response models for the HTTP API.

Transport schemas live here and stay decoupled from both the shared event
contracts and the SQLAlchemy ORM models.
"""

from __future__ import annotations

from aegis_backend.schemas.health import HealthResponse

__all__ = ["HealthResponse"]
