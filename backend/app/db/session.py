"""Database engine and session factory.

Provides a synchronous SQLAlchemy 2.0 engine over SQLite plus a FastAPI
dependency that yields a scoped session. The async scan worker (Phase 2) will
get its own session handling; Phase 0 only needs request-scoped access.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings

#: Milliseconds a writer waits on a locked database before erroring. The worker
#: (event-loop thread) and request handlers (threadpool) can write concurrently,
#: so a busy timeout lets a contended write retry instead of immediately raising
#: "database is locked".
_SQLITE_BUSY_TIMEOUT_MS = 5000

#: Connection-pool headroom above the concurrent-scan ceiling, reserved for the
#: request threadpool and the two schedulers. Scans no longer pin a connection
#: across their subprocess (CON-10), but the pool is still sized from
#: ``max_concurrent_scans`` as defense-in-depth so a burst of scan persistence
#: plus live requests can't exhaust it and 500 with "QueuePool limit reached".
_POOL_HEADROOM = 10


def _configure_sqlite(dbapi_connection: Any, _record: Any) -> None:
    """Apply per-connection SQLite pragmas for safe concurrent access.

    - WAL journaling lets readers run while a writer holds the lock.
    - ``busy_timeout`` makes contended writes wait rather than fail fast.
    - ``foreign_keys`` enforces the ON DELETE rules the models declare.
    """
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute(f"PRAGMA busy_timeout={_SQLITE_BUSY_TIMEOUT_MS}")
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()


def create_db_engine(settings: Settings | None = None) -> Engine:
    """Create a SQLAlchemy engine for the configured SQLite database.

    Args:
        settings: Optional settings override (defaults to the cached settings).

    Returns:
        A configured :class:`~sqlalchemy.Engine`.
    """
    settings = settings or get_settings()
    # check_same_thread=False so the engine can be shared across the worker and
    # request threads. Concurrent writes are made safe by the WAL + busy_timeout
    # pragmas applied on each new connection (see _configure_sqlite).
    #
    # Size the pool from max_concurrent_scans so persistence for every running
    # scan, plus concurrent request handlers and the schedulers, always has a
    # connection available (CON-10). The setting is capped (config.py), so this
    # stays bounded.
    pool_size = settings.max_concurrent_scans + _POOL_HEADROOM
    new_engine = create_engine(
        settings.database_url,
        echo=False,
        future=True,
        pool_size=pool_size,
        max_overflow=pool_size,
        connect_args={"check_same_thread": False},
    )
    event.listen(new_engine, "connect", _configure_sqlite)
    return new_engine


engine: Engine = create_db_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, class_=Session)


def get_db() -> Iterator[Session]:
    """Yield a request-scoped database session (FastAPI dependency)."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
