"""SQLAlchemy declarative base.

Model modules are imported at the bottom (via ``app.db.models``) so
``Base.metadata`` stays complete for Alembic autogeneration. Domain models for
scanning (scans, findings, registries, ...) arrive in later phases per
``docs/ARCHIVE.md`` §7.
"""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Typed declarative base shared by all ORM models."""


# Imported for the side effect of registering all tables on Base.metadata.
from app.db import models  # noqa: E402,F401
