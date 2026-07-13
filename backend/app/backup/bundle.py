"""Portable, passphrase-protected backup & restore (docs/PLAN.md §8).

A backup is a **logical dump** of the database (one JSON record per row, per
table) rather than a raw SQLite file, which keeps it independent of the on-disk
format and lets restore re-insert into a freshly-migrated schema.

The portability trick (plan §8): every stored secret is master-key-encrypted, so
it cannot travel as-is to a host with a different master key. On backup each
secret is decrypted under the host master key and **re-wrapped** under a
passphrase-derived key; the whole inner dump is then encrypted under that same
passphrase key. On restore the reverse happens — secrets are re-wrapped under the
new host's master key — so a restore needs only the passphrase, never a
master-key transplant.

The set of secret columns is sourced from
:data:`app.core.secret_store.SECRET_COLUMNS`, so any new field-encrypted column
becomes portable the moment it is registered there.
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import DateTime, func, select, text
from sqlalchemy.orm import Session

from app import __version__
from app.core.crypto import SecretDecryptError, get_secret_cipher
from app.core.passphrase import (
    AAD_BUNDLE,
    SCRYPT_N,
    SCRYPT_P,
    SCRYPT_R,
    PassphraseKdfError,
    new_salt,
    passphrase_cipher,
)
from app.core.secret_store import SECRET_COLUMNS
from app.core.timeutil import utcnow
from app.db.base import Base

logger = logging.getLogger(__name__)

#: Bundle format identifier and version, stored in the envelope.
BUNDLE_FORMAT = "scrye-backup"
BUNDLE_FORMAT_VERSION = 1

#: Rows are inserted in chunks of this size on restore (one ``executemany`` per
#: chunk) rather than one statement per row, to keep restore linear and off the
#: pathological per-row-INSERT path (API-3).
_RESTORE_CHUNK_ROWS = 500

#: Findings-table size past which a backup logs a size warning. Bundles are held
#: in memory during build/restore (single-shot GCM), so very large instances
#: should be aware of the practical ceiling (API-3); the README documents it.
_FINDINGS_WARN_THRESHOLD = 250_000

#: Tables excluded from a backup: transient/host-specific state, raw-artifact
#: bookkeeping (the files themselves live on disk and don't travel in a bundle,
#: so their rows are omitted to avoid restoring dangling references — API-10),
#: and the backup bookkeeping itself.
_EXCLUDED_TABLES: frozenset[str] = frozenset(
    {"sessions", "oidc_login_flows", "artifacts", "backups", "alembic_version"}
)

#: Tables preserved (never cleared) on restore: the local backup catalogue and
#: the Alembic revision marker belong to the host, not the bundle.
_PRESERVE_ON_RESTORE: frozenset[str] = frozenset({"backups", "alembic_version"})

#: Map of ``(table, column)`` -> AAD for the field-encrypted secret columns.
_SECRET_MAP: dict[tuple[str, str], str] = {
    (table, column): aad for table, column, aad in SECRET_COLUMNS
}


class BackupError(RuntimeError):
    """Raised when a backup cannot be built or a restore cannot be applied."""


class RestoreConflictError(BackupError):
    """Raised when a restore is refused because scans are queued or running.

    Distinct from :class:`BackupError` so the API can answer 409 (conflict,
    retry later) rather than 400 (bad bundle). Raised from *inside* the restore
    write transaction — the endpoint's own pre-check happens before the upload
    is read, and a scan queued across that await must still abort the wipe
    (CON-3).
    """


@dataclass(frozen=True)
class RestoreSummary:
    """Non-sensitive summary of a completed restore."""

    tables: int
    rows: int
    app_version: str


def _schema_version(db: Session) -> str:
    """Return the current Alembic schema revision, or ``""`` if unmanaged."""
    try:
        value = db.execute(text("SELECT version_num FROM alembic_version")).scalar()
    except Exception:  # noqa: BLE001 - a missing table just means "unknown"
        return ""
    return str(value) if value else ""


def _backup_tables() -> list:
    """Return the metadata tables included in a backup, in FK-safe order."""
    return [t for t in Base.metadata.sorted_tables if t.name not in _EXCLUDED_TABLES]


def _warn_if_large(db: Session) -> None:
    """Log a warning when the findings table is large enough to strain a bundle.

    The bundle is assembled and encrypted in memory in a single pass (AES-GCM is
    single-shot), so an instance with a very large findings table should be aware
    of the practical size ceiling. This is advisory only — the backup still runs.
    """
    findings = Base.metadata.tables.get("findings")
    if findings is None:
        return
    try:
        count = db.execute(select(func.count()).select_from(findings)).scalar() or 0
    except Exception:  # noqa: BLE001 - a count failure must not block the backup
        return
    if count >= _FINDINGS_WARN_THRESHOLD:
        logger.warning(
            "Backup of a large database: %d findings rows. The bundle is built "
            "in memory; ensure the container memory limit accommodates it "
            "(see the README backup size guidance).",
            count,
        )


def build_bundle(db: Session, passphrase: str) -> bytes:
    """Build an encrypted backup bundle for the whole database.

    Args:
        db: Active database session (read-only use).
        passphrase: The user-supplied backup passphrase.

    Returns:
        The bundle bytes (a UTF-8 JSON envelope) ready to write to disk.

    Raises:
        BackupError: If a stored secret cannot be decrypted for re-wrapping.
    """
    if not passphrase:
        raise BackupError("A backup passphrase is required.")
    master = get_secret_cipher()
    salt = new_salt()
    pass_cipher = passphrase_cipher(passphrase, salt)

    _warn_if_large(db)

    tables: dict[str, dict] = {}
    for table in _backup_tables():
        rows: list[dict] = []
        # Stream rows from the driver instead of buffering the whole result set
        # in the DBAPI cursor before we start processing (API-3).
        for record in db.execute(select(table)).yield_per(_RESTORE_CHUNK_ROWS).mappings():
            row: dict = {}
            for column in table.columns:
                value = record[column.name]
                aad = _SECRET_MAP.get((table.name, column.name))
                if aad is not None and value:
                    try:
                        plaintext = master.decrypt(value, aad=aad)
                    except SecretDecryptError as exc:
                        raise BackupError(
                            f"Cannot re-wrap secret {table.name}.{column.name}: "
                            "it could not be decrypted under the current master key."
                        ) from exc
                    value = pass_cipher.encrypt(plaintext, aad=aad)
                elif isinstance(value, datetime):
                    value = value.isoformat()
                row[column.name] = value
            rows.append(row)
        tables[table.name] = {"rows": rows}

    inner = json.dumps({"tables": tables}, separators=(",", ":"))
    payload = pass_cipher.encrypt(inner, aad=AAD_BUNDLE)
    envelope = {
        "format": BUNDLE_FORMAT,
        "format_version": BUNDLE_FORMAT_VERSION,
        "app_version": __version__,
        "schema_version": _schema_version(db),
        "created_at": utcnow().isoformat(),
        "kdf": {
            "algo": "scrypt",
            "n": SCRYPT_N,
            "r": SCRYPT_R,
            "p": SCRYPT_P,
            "salt": base64.b64encode(salt).decode("ascii"),
        },
        "payload": payload,
    }
    return json.dumps(envelope).encode("utf-8")


def _load_envelope(data: bytes) -> dict:
    """Parse and validate the outer bundle envelope."""
    try:
        envelope = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise BackupError("Backup file is not a valid Scrye bundle.") from exc
    if not isinstance(envelope, dict) or envelope.get("format") != BUNDLE_FORMAT:
        raise BackupError("Backup file is not a Scrye backup bundle.")
    if envelope.get("format_version") != BUNDLE_FORMAT_VERSION:
        raise BackupError("Unsupported backup format version.")
    return envelope


def read_manifest(data: bytes) -> dict:
    """Return the bundle's non-secret manifest fields (for pre-restore display)."""
    envelope = _load_envelope(data)
    return {
        "app_version": envelope.get("app_version"),
        "schema_version": envelope.get("schema_version"),
        "created_at": envelope.get("created_at"),
    }


def restore_bundle(db: Session, data: bytes, passphrase: str) -> RestoreSummary:
    """Restore a backup bundle into the current database (destructive).

    Every managed table is cleared and repopulated from the bundle, with each
    secret re-wrapped under the host master key. The bundle's schema version must
    match the running schema (cross-version migration of a bundle is not
    supported in v1).

    Args:
        db: Active database session; the whole restore runs in its transaction.
        data: The uploaded bundle bytes.
        passphrase: The passphrase the bundle was created with.

    Returns:
        A :class:`RestoreSummary` describing what was imported.

    Raises:
        BackupError: On a bad passphrase, format/version mismatch, or corrupt data.
    """
    envelope = _load_envelope(data)
    current_schema = _schema_version(db)
    bundle_schema = envelope.get("schema_version") or ""
    # Fail closed: a versioned (migration-managed) installation must not restore a
    # bundle that records no schema version — its compatibility cannot be
    # confirmed, and restoring it could corrupt the database. (An unversioned DB,
    # e.g. a freshly metadata-created one, has nothing to compare against.)
    if current_schema and not bundle_schema:
        raise BackupError("Backup bundle does not record a schema version; refusing to restore.")
    if current_schema and bundle_schema and bundle_schema != current_schema:
        raise BackupError(
            "Backup schema version does not match this installation "
            f"({bundle_schema} vs {current_schema}); restore is not supported across versions."
        )

    kdf = envelope.get("kdf") or {}
    try:
        salt = base64.b64decode(kdf["salt"])
    except (KeyError, ValueError, TypeError) as exc:
        raise BackupError("Backup bundle is missing its key-derivation salt.") from exc
    # Honor the KDF parameters the bundle recorded rather than the current module
    # constants (item (g)): a bundle made under an older scrypt work factor must
    # still derive the same key and restore. Missing fields (older bundles) fall
    # back to the current defaults. The values are untrusted input: they are
    # parsed defensively here and bounds-checked in derive_key (SEC-2) before
    # any memory is committed to the derivation.
    try:
        kdf_n = int(kdf.get("n", SCRYPT_N))
        kdf_r = int(kdf.get("r", SCRYPT_R))
        kdf_p = int(kdf.get("p", SCRYPT_P))
    except (TypeError, ValueError) as exc:
        raise BackupError("Backup bundle key-derivation parameters are malformed.") from exc
    try:
        pass_cipher = passphrase_cipher(passphrase, salt, n=kdf_n, r=kdf_r, p=kdf_p)
    except PassphraseKdfError as exc:
        raise BackupError(str(exc)) from exc

    try:
        inner_json = pass_cipher.decrypt(envelope["payload"], aad=AAD_BUNDLE)
    except SecretDecryptError as exc:
        raise BackupError("Incorrect passphrase or corrupt backup bundle.") from exc
    try:
        inner = json.loads(inner_json)
        tables_data: dict = inner["tables"]
    except (ValueError, KeyError) as exc:
        raise BackupError("Backup bundle payload is malformed.") from exc

    master = get_secret_cipher()
    managed = _backup_tables()

    # Acquire the database write lock up front (pysqlite's legacy isolation
    # would otherwise defer BEGIN to the first DELETE) and re-check the
    # active-scan guard *inside* the write transaction. The endpoint checks the
    # same condition before reading the upload, but that is check-then-act
    # across a long await — a scan queued (or claimed) in that window must
    # abort the restore here, before anything is wiped (CON-3). Once BEGIN
    # IMMEDIATE succeeds no other writer can queue or claim a scan until this
    # transaction ends, so the check cannot go stale.
    db.execute(text("BEGIN IMMEDIATE"))
    scans = Base.metadata.tables["scans"]
    active = (
        db.execute(
            select(func.count()).select_from(scans).where(scans.c.status.in_(("queued", "running")))
        ).scalar()
        or 0
    )
    if active:
        raise RestoreConflictError(
            "A scan was queued or started while the restore was being uploaded; "
            "wait for it to finish before restoring."
        )

    # Clear every table except the host-owned catalogue/version marker, in
    # reverse FK order. Transient state (sessions, oidc_login_flows) and raw
    # artifact rows are cleared but not repopulated, so nothing dangles.
    for table in reversed(Base.metadata.sorted_tables):
        if table.name in _PRESERVE_ON_RESTORE:
            continue
        db.execute(table.delete())

    total_rows = 0
    for table in managed:
        payload_rows = (tables_data.get(table.name) or {}).get("rows", [])
        # Build the fully-typed value dicts, then insert in chunks with a single
        # executemany per chunk instead of one INSERT statement per row (API-3).
        chunk: list[dict] = []
        for row in payload_rows:
            values: dict = {}
            for column in table.columns:
                if column.name not in row:
                    continue
                value = row[column.name]
                aad = _SECRET_MAP.get((table.name, column.name))
                if aad is not None and value:
                    try:
                        plaintext = pass_cipher.decrypt(value, aad=aad)
                    except SecretDecryptError as exc:
                        raise BackupError(
                            f"Cannot restore secret {table.name}.{column.name}: "
                            "the bundle is corrupt or the passphrase is wrong."
                        ) from exc
                    value = master.encrypt(plaintext, aad=aad)
                elif isinstance(column.type, DateTime) and isinstance(value, str):
                    value = datetime.fromisoformat(value)
                values[column.name] = value
            chunk.append(values)
            if len(chunk) >= _RESTORE_CHUNK_ROWS:
                db.execute(table.insert(), chunk)
                total_rows += len(chunk)
                chunk = []
        if chunk:
            db.execute(table.insert(), chunk)
            total_rows += len(chunk)

    return RestoreSummary(
        tables=len(managed), rows=total_rows, app_version=str(envelope.get("app_version") or "")
    )
