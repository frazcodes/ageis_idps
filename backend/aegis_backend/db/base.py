"""SQLAlchemy declarative base.

Concrete ORM models live in :mod:`aegis_backend.models` and must import ``Base``
from here so that Alembic and metadata creation see a single registry.
"""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Declarative base shared by every backend ORM model."""


__all__ = ["Base"]
