"""Aggregate router for API v1."""

from __future__ import annotations

from fastapi import APIRouter

from aegis_backend.api.v1 import health

router = APIRouter()
router.include_router(health.router)

__all__ = ["router"]
