"""Health and readiness endpoints."""

from __future__ import annotations

from fastapi import APIRouter

from aegis_backend.schemas.health import HealthResponse
from aegis_shared.version import __version__

router = APIRouter(tags=["system"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Liveness probe",
    description="Returns basic process identity and version. Used by orchestrators and tests.",
)
def health() -> HealthResponse:
    """Report that the API process is up."""
    return HealthResponse(status="ok", service="aegis-backend", version=__version__)


__all__ = ["router"]
