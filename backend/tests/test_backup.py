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

from app.backup.bundle import (
    BackupError,
    RestoreConflictError,
    build_bundle,
    read_manifest,
    restore_bundle,
)
from app.backup.scheduled import prune_scheduled, run_due_backup
from app.backup.store import BackupStore
from app.core import crypto
from app.core.secret_store import AAD_REGISTRY_SECRET, decrypt_secret, encrypt_secret
from app.core.timeutil import utcnow
from app.db.models import (
    BACKUP_SCHEDULE_ID,
    Artifact,
    ArtifactKind,
    Backup,
    BackupKind,
    BackupSchedule,
    Finding,
    FindingClass,
    Registry,
    RegistryAuthType,
    Role,
    Scan,
    Scanner,
    ScanStatus,
    Severity,
    TargetType,
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

    def test_artifacts_excluded_and_cleared_on_restore(self, db: Session) -> None:
        """API-10: raw-artifact rows don't travel in a bundle, so a restore must
        not repopulate them (their files aren't in the bundle) — while the scan
        and its findings do survive."""
        db.add(User(username="admin", password_hash="x", role=Role.ADMIN))
        scan = Scan(
            scanner=Scanner.TRIVY,
            target_type=TargetType.IMAGE,
            target="alpine:3.19",
            status=ScanStatus.SUCCEEDED,
        )
        db.add(scan)
        db.flush()
        db.add(
            Finding(
                scan_id=scan.id, finding_class=FindingClass.VULNERABILITY, severity=Severity.HIGH
            )
        )
        db.add(
            Artifact(
                scan_id=scan.id,
                kind=ArtifactKind.RAW_TRIVY_JSON,
                filename="trivy.json",
                relative_path=f"{scan.id}/trivy.json",
                sha256="deadbeef",
            )
        )
        db.commit()

        data = build_bundle(db, PASSPHRASE)
        # The bundle carries no artifact rows.
        assert b"trivy.json" not in data

        restore_bundle(db, data, PASSPHRASE)
        # Scan + finding restored; artifacts cleared (no dangling file references).
        assert db.scalar(select(Scan).where(Scan.target == "alpine:3.19")) is not None
        assert db.scalars(select(Finding)).all()
        assert db.scalars(select(Artifact)).all() == []

    def test_restore_honors_recorded_kdf_params(self, db: Session) -> None:
        """Item (g): restore derives the key from the bundle's advertised scrypt
        params, not the module constants — so tampering the recorded ``n`` (as a
        proxy for a bundle written under a different work factor) changes the
        derived key and restore fails, proving the params are actually read."""
        import json

        _seed(db)
        data = build_bundle(db, PASSPHRASE)
        envelope = json.loads(data)
        assert envelope["kdf"]["n"]  # the params travel in the bundle
        # A bundle that recorded a *different* n derives a different key; restore
        # honoring the recorded value therefore cannot decrypt the payload.
        envelope["kdf"]["n"] = 2**14
        tampered = json.dumps(envelope).encode("utf-8")
        with pytest.raises(BackupError):
            restore_bundle(db, tampered, PASSPHRASE)

    def test_restore_conflicts_inside_transaction_when_scan_active(self, db: Session) -> None:
        """CON-3: the active-scan guard is re-checked *inside* the restore's
        write transaction, so a scan queued after the endpoint's pre-check (i.e.
        across the upload await) still aborts the restore — and nothing is wiped."""
        _seed(db)
        data = build_bundle(db, PASSPHRASE)
        db.add(
            Scan(
                scanner=Scanner.TRIVY,
                target_type=TargetType.IMAGE,
                target="raced:latest",
                status=ScanStatus.QUEUED,
            )
        )
        db.commit()

        with pytest.raises(RestoreConflictError):
            restore_bundle(db, data, PASSPHRASE)
        db.rollback()

        # Restore atomicity: the conflict fired before the wipe, so the live
        # data — including the racing scan — is fully intact.
        assert db.scalar(select(User).where(User.username == "admin")) is not None
        assert db.scalar(select(Registry).where(Registry.name == "ghcr")) is not None
        raced = db.scalar(select(Scan).where(Scan.target == "raced:latest"))
        assert raced is not None and raced.status is ScanStatus.QUEUED

    def test_restore_rejects_scrypt_parameter_bomb(self, db: Session) -> None:
        """SEC-2: a crafted bundle demanding an absurd scrypt work factor must be
        rejected up front — before any key derivation memory is allocated — since
        the KDF envelope is attacker-controlled and read pre-passphrase."""
        import json

        _seed(db)
        data = build_bundle(db, PASSPHRASE)
        for bomb in (
            {"n": 2**30},  # ~128 GiB per RFC 7914 — the OOM-kill payload
            {"r": 2**16},
            {"p": 2**20},
            {"n": 2**20, "r": 16},  # inside the per-parameter caps, over the memory budget
        ):
            envelope = json.loads(data)
            envelope["kdf"].update(bomb)
            tampered = json.dumps(envelope).encode("utf-8")
            with pytest.raises(BackupError, match="scrypt"):
                restore_bundle(db, tampered, PASSPHRASE)

    def test_restore_rejects_malformed_kdf_params(self, db: Session) -> None:
        import json

        _seed(db)
        data = build_bundle(db, PASSPHRASE)
        envelope = json.loads(data)
        envelope["kdf"]["n"] = "not-a-number"
        tampered = json.dumps(envelope).encode("utf-8")
        with pytest.raises(BackupError, match="malformed"):
            restore_bundle(db, tampered, PASSPHRASE)

    def test_restore_batches_many_rows(self, db: Session) -> None:
        """API-3: the batched (executemany) restore round-trips a chunk-spanning
        number of rows without loss."""
        scan = Scan(
            scanner=Scanner.GRYPE,
            target_type=TargetType.IMAGE,
            target="busybox:latest",
            status=ScanStatus.SUCCEEDED,
        )
        db.add(scan)
        db.flush()
        for _ in range(1200):  # > _RESTORE_CHUNK_ROWS (500) to span chunks
            db.add(
                Finding(
                    scan_id=scan.id,
                    finding_class=FindingClass.VULNERABILITY,
                    severity=Severity.MEDIUM,
                )
            )
        db.commit()
        data = build_bundle(db, PASSPHRASE)
        db.query(Finding).delete()
        db.query(Scan).delete()
        db.commit()
        restore_bundle(db, data, PASSPHRASE)
        assert len(db.scalars(select(Finding)).all()) == 1200


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
