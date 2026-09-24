"""Smoke test for the backend API surface.

Skipped automatically when the optional backend dependencies are not installed.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi", reason="backend extra not installed")

from fastapi.testclient import TestClient

from aegis_backend.main import create_app


def test_health_endpoint() -> None:
    client = TestClient(create_app())
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "aegis-backend"
    assert body["version"]
