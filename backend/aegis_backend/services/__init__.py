"""Application service layer.

Business logic (event ingestion, alert lifecycle, correlation orchestration)
lives here so routers stay thin and logic stays unit-testable without HTTP.
"""

from __future__ import annotations

__all__: list[str] = []
