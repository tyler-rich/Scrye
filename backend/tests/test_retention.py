"""Tests for result-retention pruning of raw artifacts (app.core.retention)."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy.orm import Session

from app.core.app_settings import RetentionSettings, SettingsService
from app.core.artifacts import artifact_path, store_artifact
from app.core.retention import prune_expired_artifacts, run_retention
from app.core.timeutil import utcnow
from app.db.models import (
    Artifact,
    ArtifactKind,
    Finding,
    FindingClass,
    Scan,
    Scanner,
    ScanStatus,
    Severity,
    TargetType,
)


def _make_scan_with_artifact(db: Session, *, age_days: int) -> Scan:
    """Create a succeeded scan (with a finding + a stored raw artifact) aged N days."""
    created = utcnow() - timedelta(days=age_days)
    scan = Scan(
        scanner=Scanner.TRIVY,
        target_type=TargetType.IMAGE,
        target=f"img-{age_days}",
        status=ScanStatus.SUCCEEDED,
        options={},
        severity_counts={"high": 1},
        findings_count=1,
        created_at=created,
        finished_at=created,
    )
    db.add(scan)
    db.flush()
    db.add(
        Finding(
            scan_id=scan.id,
            finding_class=FindingClass.VULNERABILITY,
            severity=Severity.HIGH,
            vuln_id="CVE-2026-0001",
        )
    )
    stored = store_artifact(scan.id, "trivy.json", b'{"Results": []}')
    db.add(
        Artifact(
            scan_id=scan.id,
            kind=ArtifactKind.RAW_TRIVY_JSON,
            filename="trivy.json",
            relative_path=stored.relative_path,
            size_bytes=stored.size_bytes,
            sha256=stored.sha256,
        )
    )
    db.commit()
    return scan


class TestPrune:
    def test_prunes_old_artifacts_keeps_scan_and_findings(self, db: Session) -> None:
        old = _make_scan_with_artifact(db, age_days=100)
        old_path = artifact_path(old.artifacts[0].relative_path)
        assert old_path.is_file()

        pruned = prune_expired_artifacts(db, max_age_days=90)
        assert pruned == 1
        assert not old_path.exists()
        # Scan row and its normalized finding are preserved.
        db.refresh(old)
        assert db.get(Scan, old.id) is not None
        assert old.findings_count == 1
        assert db.query(Finding).filter(Finding.scan_id == old.id).count() == 1
        assert db.query(Artifact).filter(Artifact.scan_id == old.id).count() == 0

    def test_keeps_recent_artifacts(self, db: Session) -> None:
        recent = _make_scan_with_artifact(db, age_days=10)
        pruned = prune_expired_artifacts(db, max_age_days=90)
        assert pruned == 0
        assert db.query(Artifact).filter(Artifact.scan_id == recent.id).count() == 1

    def test_missing_file_still_removes_row(self, db: Session) -> None:
        scan = _make_scan_with_artifact(db, age_days=100)
        artifact_path(scan.artifacts[0].relative_path).unlink()
        pruned = prune_expired_artifacts(db, max_age_days=90)
        assert pruned == 1
        assert db.query(Artifact).count() == 0


class TestRunRetention:
    def test_disabled_is_noop(self, db: Session) -> None:
        _make_scan_with_artifact(db, age_days=100)
        assert run_retention(db) == 0
        assert db.query(Artifact).count() == 1

    def test_enabled_prunes(self, db: Session) -> None:
        _make_scan_with_artifact(db, age_days=100)
        SettingsService(db).set_retention(
            RetentionSettings(enabled=True, max_age_days=90), username="admin"
        )
        db.commit()
        assert run_retention(db) == 1
        assert db.query(Artifact).count() == 0
