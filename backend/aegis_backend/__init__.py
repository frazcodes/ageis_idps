"""Aegis IDPS central backend service.

FastAPI application that will eventually expose event ingestion, alert and
incident management, authentication/RBAC and the WebSocket feed consumed by the
SOC dashboard. No detection logic lives here - the backend stores, correlates and
serves what the sensors and engines produce.
"""

from __future__ import annotations

__all__: list[str] = []
