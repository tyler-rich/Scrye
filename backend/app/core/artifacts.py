"""Filesystem storage for raw scan artifacts.

Raw scanner output (and later SBOMs) is persisted verbatim as the source of
truth (docs/PLAN.md §4.3). Bytes live on disk under the configured artifacts
directory — one subdirectory per scan — while the database keeps metadata plus a
SHA-256 checksum. Keeping large blobs out of SQLite keeps the database small and
backups cheap.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from app.core.config import get_settings


@dataclass(frozen=True)
class StoredArtifact:
    """Metadata for a persisted artifact file."""

    relative_path: str
    size_bytes: int
    sha256: str


def _artifacts_root() -> Path:
    """Return the configured artifacts root directory."""
    return get_settings().artifacts_dir


def store_artifact(scan_id: int, filename: str, data: bytes) -> StoredArtifact:
    """Write ``data`` to ``<artifacts>/<scan_id>/<filename>`` and hash it.

    Args:
        scan_id: The owning scan's id (used as the subdirectory name).
        filename: The artifact file name (no path separators).
        data: The raw bytes to persist.

    Returns:
        A :class:`StoredArtifact` describing the written file. ``relative_path``
        is relative to the artifacts root so the database stays portable across
        hosts with different mount points.

    Raises:
        ValueError: If ``filename`` contains a path separator.
    """
    if "/" in filename or "\\" in filename:
        raise ValueError("Artifact filename must not contain a path separator.")

    scan_dir = _artifacts_root() / str(scan_id)
    scan_dir.mkdir(parents=True, exist_ok=True)
    path = scan_dir / filename
    path.write_bytes(data)

    return StoredArtifact(
        relative_path=f"{scan_id}/{filename}",
        size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
    )


def artifact_path(relative_path: str) -> Path:
    """Resolve a stored artifact's absolute path from its relative path.

    Guards against path traversal: the resolved path must stay within the
    artifacts root.

    Args:
        relative_path: The ``relative_path`` recorded on the artifact row.

    Returns:
        The absolute filesystem path.

    Raises:
        ValueError: If the path escapes the artifacts root.
    """
    root = _artifacts_root().resolve()
    resolved = (root / relative_path).resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError("Artifact path escapes the artifacts directory.")
    return resolved
