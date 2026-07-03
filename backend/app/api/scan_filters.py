"""Shared scan-history filter parsing and query building (docs/PLAN.md §4.4).

The history view and the filtered-history export accept the same filter set, so
it lives here once as a FastAPI dependency (:func:`history_filters`) plus the
query-building logic (:meth:`HistoryFilters.apply`). Every filter is
non-sensitive metadata.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from fastapi import Query
from sqlalchemy import Select, exists

from app.db.models import (
    SEVERITY_RANK,
    Scan,
    Scanner,
    ScanStatus,
    ScanTag,
    Severity,
    TargetType,
)


def _to_naive_utc(value: datetime | None) -> datetime | None:
    """Normalize an optional datetime to naive UTC (DB timestamps are naive UTC)."""
    if value is None:
        return None
    if value.tzinfo is not None:
        return value.astimezone(UTC).replace(tzinfo=None)
    return value


def severities_at_or_above(threshold: Severity) -> list[Severity]:
    """Return every severity at or above ``threshold`` by rank."""
    floor = SEVERITY_RANK[threshold]
    return [sev for sev, rank in SEVERITY_RANK.items() if rank >= floor]


@dataclass
class HistoryFilters:
    """Parsed scan-history filter selections."""

    scanner: Scanner | None = None
    target_type: TargetType | None = None
    q: str | None = None
    status: ScanStatus | None = None
    created_from: datetime | None = None
    created_to: datetime | None = None
    initiator: str | None = None
    highest_severity: Severity | None = None
    min_severity: Severity | None = None
    tags: list[str] | None = None

    def apply(self, stmt: Select[tuple[Scan]]) -> Select[tuple[Scan]]:
        """Apply every active filter as a WHERE clause on a ``Scan`` select."""
        if self.scanner is not None:
            stmt = stmt.where(Scan.scanner == self.scanner)
        if self.target_type is not None:
            stmt = stmt.where(Scan.target_type == self.target_type)
        if self.q:
            like = f"%{self.q.strip()}%"
            stmt = stmt.where(Scan.target.ilike(like))
        if self.status is not None:
            stmt = stmt.where(Scan.status == self.status)
        created_from = _to_naive_utc(self.created_from)
        created_to = _to_naive_utc(self.created_to)
        if created_from is not None:
            stmt = stmt.where(Scan.created_at >= created_from)
        if created_to is not None:
            stmt = stmt.where(Scan.created_at <= created_to)
        if self.initiator:
            stmt = stmt.where(Scan.created_by_username == self.initiator)
        if self.highest_severity is not None:
            stmt = stmt.where(Scan.highest_severity == self.highest_severity)
        if self.min_severity is not None:
            stmt = stmt.where(Scan.highest_severity.in_(severities_at_or_above(self.min_severity)))
        for tag in self.tags or []:
            stmt = stmt.where(exists().where((ScanTag.scan_id == Scan.id) & (ScanTag.tag == tag)))
        return stmt

    def as_metadata(self) -> dict[str, Any]:
        """Return the active filters as a plain dict for export/echo purposes."""
        raw = {
            "scanner": self.scanner.value if self.scanner else None,
            "target_type": self.target_type.value if self.target_type else None,
            "q": self.q,
            "status": self.status.value if self.status else None,
            "created_from": (
                _to_naive_utc(self.created_from).isoformat() if self.created_from else None
            ),
            "created_to": _to_naive_utc(self.created_to).isoformat() if self.created_to else None,
            "initiator": self.initiator,
            "highest_severity": self.highest_severity.value if self.highest_severity else None,
            "min_severity": self.min_severity.value if self.min_severity else None,
            "tags": list(self.tags) if self.tags else None,
        }
        return {k: v for k, v in raw.items() if v not in (None, "", [])}


def history_filters(
    scanner: Scanner | None = Query(default=None, description="Filter by scanner engine."),
    target_type: TargetType | None = Query(default=None, description="Filter by target type."),
    q: str | None = Query(default=None, description="Full-text search on the target name."),
    scan_status: ScanStatus | None = Query(
        default=None, alias="status", description="Filter by scan status."
    ),
    created_from: datetime | None = Query(
        default=None, description="Only scans created at or after this time."
    ),
    created_to: datetime | None = Query(
        default=None, description="Only scans created at or before this time."
    ),
    initiator: str | None = Query(default=None, description="Filter by the initiating username."),
    highest_severity: Severity | None = Query(
        default=None, description="Scans whose highest severity equals this value."
    ),
    min_severity: Severity | None = Query(
        default=None, description="Scans containing a finding at or above this severity."
    ),
    tags: list[str] = Query(default=[], description="Scans carrying all of these tags."),
) -> HistoryFilters:
    """Collect scan-history filter query parameters into a :class:`HistoryFilters`."""
    cleaned_tags = [t.strip().lower() for t in tags if t.strip()]
    return HistoryFilters(
        scanner=scanner,
        target_type=target_type,
        q=q,
        status=scan_status,
        created_from=created_from,
        created_to=created_to,
        initiator=initiator,
        highest_severity=highest_severity,
        min_severity=min_severity,
        tags=cleaned_tags or None,
    )
