"""Tests for the backup bundle: round-trip, portability, and scheduling.

The portability test proves the plan's §8 requirement — a bundle restores on a
host with a *different* master key, using only the passphrase — by swapping the
process cipher between backup and restore.
"""

from __future__ import annotations

import base64
import os

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.backup.bundle import BackupError, build_bundle, read_manifest, restore_bundle
from app.backup.scheduled import prune_scheduled, run_due_backup
from app.backup.store import BackupStore
from app.core import crypto
from app.core.secret_store import AAD_REGISTRY_SECRET, decrypt_secret, encrypt_secret
from app.core.timeutil import utcnow
from app.db.models import (
    BACKUP_SCHEDULE_ID,
    Backup,
    BackupKind,
    BackupSchedule,
    Registry,
    RegistryAuthType,
    Role,
    User,
)

PASSPHRASE = "correct-horse-battery-staple"


def _seed(db: Session) -> None:
    """Insert a user and a registry with an encrypted secret."""
    db.add(User(username="admin", password_hash="x", role=Role.ADMIN))
    registry = Registry(
        name="ghcr",
        registry_host="ghcr.io",
        auth_type=RegistryAuthType.TOKEN,
        secret_ciphertext=encrypt_secret("registry-token-value", aad=AAD_REGISTRY_SECRET),
        secret_updated_at=utcnow(),
    )
    db.add(registry)
    db.commit()


def _swap_master_key() -> None:
    """Replace the process master key with a fresh one (new-host simulation)."""
    key_file = crypto.get_settings().app_secret_key_file
    key_file.write_bytes(base64.b64encode(os.urandom(48)))
    crypto.reset_secret_cipher()


class TestBundleRoundTrip:
    def test_manifest_is_readable_without_passphrase(self, db: Session) -> None:
        _seed(db)
        data = build_bundle(db, PASSPHRASE)
        manifest = read_manifest(data)
        assert manifest["app_version"]
        # schema_version is present (empty here since tests use create_all, not
        # Alembic); it is populated under a migrated database.
        assert "schema_version" in manifest

    def test_wrong_passphrase_rejected(self, db: Session) -> None:
        _seed(db)
        data = build_bundle(db, PASSPHRASE)
        with pytest.raises(BackupError):
            restore_bundle(db, data, "not-the-passphrase")

    def test_restore_repopulates_and_preserves_secret(self, db: Session) -> None:
        _seed(db)
        data = build_bundle(db, PASSPHRASE)

        # Destroy live data, then restore from the bundle.
        db.query(Registry).delete()
        db.query(User).delete()
        db.commit()
        assert db.scalar(select(Registry)) is None

        summary = restore_bundle(db, data, PASSPHRASE)
        assert summary.rows >= 2
        registry = db.scalar(select(Registry).where(Registry.name == "ghcr"))
        assert registry is not None
        # The secret decrypts to the original plaintext under the host master key.
        assert (
            decrypt_secret(registry.secret_ciphertext, aad=AAD_REGISTRY_SECRET)
            == "registry-token-value"
        )

    def test_portable_across_master_keys(self, db: Session) -> None:
        _seed(db)
        data = build_bundle(db, PASSPHRASE)
        db.query(Registry).delete()
        db.query(User).delete()
        db.commit()

        try:
            _swap_master_key()  # simulate restoring on a fresh host
            restore_bundle(db, data, PASSPHRASE)
            registry = db.scalar(select(Registry).where(Registry.name == "ghcr"))
            assert registry is not None
            # Re-wrapped under the NEW master key, still yields the plaintext.
            assert (
                decrypt_secret(registry.secret_ciphertext, aad=AAD_REGISTRY_SECRET)
                == "registry-token-value"
            )
        finally:
            crypto.reset_secret_cipher()  # restore the shared test cipher

    def test_bundle_contains_no_plaintext_secret(self, db: Session) -> None:
        _seed(db)
        data = build_bundle(db, PASSPHRASE)
        assert b"registry-token-value" not in data


class TestScheduledBackup:
    def _configure_schedule(self, db: Session) -> None:
        db.add(
            BackupSchedule(
                id=BACKUP_SCHEDULE_ID,
                enabled=True,
                interval_hours=24,
                retention_count=2,
                passphrase_ciphertext=encrypt_secret(PASSPHRASE, aad="backup.passphrase"),
                secret_updated_at=utcnow(),
            )
        )
        db.commit()

    def test_run_due_creates_backup(self, db: Session, tmp_path) -> None:
        _seed(db)
        self._configure_schedule(db)
        store = BackupStore(tmp_path)
        assert run_due_backup(db, store=store, force=True) == "ok"
        backups = db.scalars(select(Backup)).all()
        assert len(backups) == 1
        assert backups[0].kind == BackupKind.SCHEDULED
        assert (tmp_path / backups[0].filename).exists()

    def test_disabled_schedule_skips(self, db: Session, tmp_path) -> None:
        _seed(db)
        db.add(BackupSchedule(id=BACKUP_SCHEDULE_ID, enabled=False))
        db.commit()
        assert run_due_backup(db, store=BackupStore(tmp_path), force=True) == "skipped"

    def test_retention_prunes_oldest(self, db: Session, tmp_path) -> None:
        store = BackupStore(tmp_path)
        for i in range(5):
            store.write(b"x", f"scrye-scheduled-old{i}.scryebak")
            db.add(
                Backup(
                    filename=f"scrye-scheduled-old{i}.scryebak",
                    size_bytes=1,
                    checksum_sha256="a",
                    kind=BackupKind.SCHEDULED,
                    app_version="0.1.0",
                    created_at=utcnow(),
                )
            )
        db.commit()
        pruned = prune_scheduled(db, keep=2, store=store)
        db.commit()  # prune_scheduled defers the commit to its caller
        assert pruned == 3
        assert len(db.scalars(select(Backup)).all()) == 2
