"""Shared Pydantic field types for the API layer.

``UtcDatetime`` is the wire type for every timestamp a response model emits. DB
timestamps are stored naive-UTC (:mod:`app.core.timeutil`), and serializing them
as bare ISO-8601 (``2026-07-11T04:00:00``) leaves the timezone ambiguous — a
consumer that parses one as browser-local shifts every timestamp by its UTC
offset (APIR-5). This type appends an explicit ``Z`` in JSON output so the
instant is unambiguous, without changing storage (Python-mode dumps and DB binds
stay naive).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from pydantic import PlainSerializer


def _serialize_utc(value: datetime) -> str:
    """Render a naive-UTC datetime as ISO-8601 with an explicit ``Z``."""
    if value.tzinfo is not None:
        value = value.astimezone(UTC).replace(tzinfo=None)
    return value.isoformat() + "Z"


#: A ``datetime`` that serializes to JSON with an explicit UTC ``Z`` designator.
UtcDatetime = Annotated[
    datetime, PlainSerializer(_serialize_utc, return_type=str, when_used="json")
]
