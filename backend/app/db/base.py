"""SQLAlchemy declarative base.

Domain models (users, scans, findings, registries, ...) are introduced in later
phases per ``docs/PLAN.md`` §7. Phase 0 establishes only the typed base and the
shared metadata so Alembic has a target to compare migrations against.

Import model modules here as they are added so ``Base.metadata`` stays complete
for Alembic autogeneration.
"""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Typed declarative base shared by all ORM models."""
