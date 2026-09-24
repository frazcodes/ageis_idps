"""Root API router.

Versioned sub-routers are mounted here so the URL surface is declared in one place.
"""

from __future__ import annotations

from fastapi import APIRouter

from aegis_backend.api.v1.router import router as v1_router

api_router = APIRouter()
api_router.include_router(v1_router, prefix="/api/v1")

__all__ = ["api_router"]
