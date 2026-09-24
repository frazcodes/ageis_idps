"""SQLAlchemy ORM models.

Intentionally empty in this foundation. Domain tables (events, alerts, incidents,
assets, response actions, audit records) will be added together with Alembic
migrations; every model must inherit from :class:`aegis_backend.db.base.Base`.
"""

from __future__ import annotations

__all__: list[str] = []
