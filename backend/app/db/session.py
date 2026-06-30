"""Database engine and session factory.

Provides a synchronous SQLAlchemy 2.0 engine over SQLite plus a FastAPI
dependency that yields a scoped session. The async scan worker (Phase 2) will
get its own session handling; Phase 0 only needs request-scoped access.
"""

from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings


def create_db_engine(settings: Settings | None = None) -> Engine:
    """Create a SQLAlchemy engine for the configured SQLite database.

    Args:
        settings: Optional settings override (defaults to the cached settings).

    Returns:
        A configured :class:`~sqlalchemy.Engine`.
    """
    settings = settings or get_settings()
    # check_same_thread=False so the engine can be shared across the worker and
    # request threads; SQLite write serialization is handled by the worker.
    return create_engine(
        settings.database_url,
        echo=False,
        future=True,
        connect_args={"check_same_thread": False},
    )


engine: Engine = create_db_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, class_=Session)


def get_db() -> Iterator[Session]:
    """Yield a request-scoped database session (FastAPI dependency)."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
