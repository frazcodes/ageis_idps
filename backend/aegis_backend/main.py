"""FastAPI application entry point for the Aegis IDPS backend.

Run locally with::

    uvicorn aegis_backend.main:app --reload
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from aegis_backend.api.router import api_router
from aegis_backend.config import BackendSettings, get_backend_settings
from aegis_shared.config import get_settings
from aegis_shared.logging import configure_logging
from aegis_shared.version import __version__


def create_app(settings: BackendSettings | None = None) -> FastAPI:
    """Build and configure the FastAPI application.

    Kept as a factory so tests can construct isolated app instances.
    """
    backend_settings = settings or get_backend_settings()
    global_settings = get_settings()

    configure_logging(
        level=global_settings.log_level,
        json_output=global_settings.log_json,
        service="aegis-backend",
    )

    app = FastAPI(
        title="Aegis IDPS API",
        version=__version__,
        description=(
            "Central API for the Aegis IDPS platform. Detection and response logic "
            "is intentionally not implemented in this foundation."
        ),
        docs_url="/docs",
        redoc_url=None,
        openapi_url="/openapi.json",
    )

    if backend_settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=backend_settings.cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "DELETE"],
            allow_headers=["Authorization", "Content-Type"],
        )

    app.include_router(api_router)
    return app


app = create_app()
