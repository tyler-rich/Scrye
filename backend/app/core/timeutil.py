"""Time helpers shared across the persistence layer.

Convention: **all database timestamps are naive UTC.** SQLite (via SQLAlchemy)
does not preserve timezone info, so storing naive-UTC consistently avoids
aware-vs-naive comparison bugs between freshly created values and values read
back from the database.
"""

from __future__ import annotations

from datetime import UTC, datetime


def utcnow() -> datetime:
    """Return the current time as a naive-UTC :class:`~datetime.datetime`."""
    return datetime.now(UTC).replace(tzinfo=None)
