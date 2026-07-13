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


def to_naive_utc(value: datetime | None) -> datetime | None:
    """Normalize an optional datetime to naive UTC (DB timestamps are naive UTC).

    Timezone-aware inputs are converted to UTC before their offset is dropped, so
    a client-supplied aware timestamp lands on the same instant the storage layer
    would have produced. Naive inputs are already assumed to be UTC and pass
    through unchanged.
    """
    if value is None:
        return None
    if value.tzinfo is not None:
        return value.astimezone(UTC).replace(tzinfo=None)
    return value
