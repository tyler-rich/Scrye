"""On-disk storage for backup bundles.

Bundles live as individual files under the configured backups directory
(``SCRYE_BACKUPS_DIR``). Files are written with restrictive permissions since a
bundle is passphrase-protected but still sensitive. Read/delete reject anything
but a bare file name so a crafted path can't escape the directory.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from app.core.config import get_settings

#: File extension for a Scrye backup bundle.
BUNDLE_SUFFIX = ".scryebak"


class BackupStore:
    """Filesystem access to the backups directory."""

    def __init__(self, directory: Path | None = None) -> None:
        """Bind to a backups directory (defaults to the configured one)."""
        self.directory = directory or get_settings().backups_dir

    def _resolved(self, filename: str) -> Path:
        """Return the safe absolute path for ``filename`` within the directory.

        Raises:
            ValueError: If ``filename`` is not a bare name (contains a path
                separator or ``..``), i.e. attempts to escape the directory.
        """
        if filename != Path(filename).name or not filename.endswith(BUNDLE_SUFFIX):
            raise ValueError("Invalid backup file name.")
        return self.directory / filename

    def write(self, data: bytes, filename: str) -> Path:
        """Write bundle bytes to ``filename`` (0600) and return the path."""
        path = self._resolved(filename)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        with open(tmp, "wb", opener=lambda p, f: os.open(p, f, 0o600)) as handle:
            handle.write(data)
        os.replace(tmp, path)
        return path

    def read(self, filename: str) -> bytes:
        """Return the bytes of a stored bundle.

        Raises:
            FileNotFoundError: If the bundle does not exist.
        """
        return self._resolved(filename).read_bytes()

    def delete(self, filename: str) -> None:
        """Delete a stored bundle if present (missing files are ignored)."""
        self._resolved(filename).unlink(missing_ok=True)


def sha256_hex(data: bytes) -> str:
    """Return the hex SHA-256 of ``data``."""
    return hashlib.sha256(data).hexdigest()


def write_backup_file(data: bytes, filename: str, *, directory: Path | None = None) -> Path:
    """Write a bundle file via a :class:`BackupStore`."""
    return BackupStore(directory).write(data, filename)


def read_backup_file(filename: str, *, directory: Path | None = None) -> bytes:
    """Read a bundle file via a :class:`BackupStore`."""
    return BackupStore(directory).read(filename)


def delete_backup_file(filename: str, *, directory: Path | None = None) -> None:
    """Delete a bundle file via a :class:`BackupStore`."""
    BackupStore(directory).delete(filename)
