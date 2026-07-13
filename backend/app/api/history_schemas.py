"""API schemas for scan history, tags, diffs, and saved filter presets.

These carry only non-sensitive metadata: filter selections, free-form tags, and
finding summaries. No scan payload here holds secret material.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.api.scan_schemas import ScanOut
from app.api.schema_types import UtcDatetime

#: Maximum number of tags a single scan may carry.
MAX_TAGS_PER_SCAN = 20
#: Maximum length of a single tag.
MAX_TAG_LENGTH = 64


def _normalize_tags(raw: list[str]) -> list[str]:
    """Trim, lowercase, de-duplicate, and validate a list of tag strings."""
    seen: dict[str, None] = {}
    for item in raw:
        tag = item.strip().lower()
        if not tag:
            continue
        if len(tag) > MAX_TAG_LENGTH:
            raise ValueError(f"Tag '{tag[:16]}...' exceeds {MAX_TAG_LENGTH} characters.")
        seen[tag] = None
    tags = list(seen)
    if len(tags) > MAX_TAGS_PER_SCAN:
        raise ValueError(f"A scan may have at most {MAX_TAGS_PER_SCAN} tags.")
    return tags


class ScanHistoryPage(BaseModel):
    """A page of history results plus the total number of matches."""

    total: int
    items: list[ScanOut]


class FilterOptionsOut(BaseModel):
    """Distinct values used to populate the history filter controls."""

    initiators: list[str]
    tags: list[str]


class ScanTagsIn(BaseModel):
    """Request body to replace the full set of tags on a scan."""

    tags: list[str] = Field(default_factory=list)

    @field_validator("tags")
    @classmethod
    def _clean(cls, value: list[str]) -> list[str]:
        """Normalize and validate the incoming tags."""
        return _normalize_tags(value)


class DiffFindingOut(BaseModel):
    """A finding as it appears in a scan diff (a trimmed :class:`FindingOut`)."""

    model_config = ConfigDict(from_attributes=True)

    finding_class: str
    severity: str
    vuln_id: str | None
    pkg_name: str | None
    installed_version: str | None
    fixed_version: str | None
    title: str | None


class ScanDiffOut(BaseModel):
    """The diff between a base scan and a comparison scan of the same target."""

    base_scan_id: int
    compare_scan_id: int
    target: str
    scanner: str
    added: list[DiffFindingOut]
    removed: list[DiffFindingOut]
    unchanged_count: int
    added_count: int
    removed_count: int
    severity_delta: dict[str, int]


class FilterPresetIn(BaseModel):
    """Request body to create or update a saved filter preset."""

    name: str = Field(min_length=1, max_length=128)
    filters: dict[str, Any] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def _strip_name(cls, value: str) -> str:
        """Trim the preset name and reject an empty one."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("Preset name must not be empty.")
        return stripped


class FilterPresetOut(BaseModel):
    """Read view of a saved filter preset."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    filters: dict[str, Any]
    created_at: UtcDatetime
    updated_at: UtcDatetime


__all__ = [
    "DiffFindingOut",
    "FilterOptionsOut",
    "FilterPresetIn",
    "FilterPresetOut",
    "ScanDiffOut",
    "ScanHistoryPage",
    "ScanTagsIn",
]
