"""Tests for dashboard aggregation (app.core.dashboard) and its endpoint."""

from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core import system_info
from app.core.dashboard import compute_dashboard, failed_scan_alerts
from app.core.timeutil import utcnow
from app.db.models import Scan, Scanner, ScanStatus, TargetType
from app.db.session import SessionLocal
from tests.test_auth import setup_admin


def _add_scan(
    db: Session,
    *,
    target: str,
    status: ScanStatus,
    scanner: Scanner = Scanner.TRIVY,
    target_type: TargetType = TargetType.IMAGE,
    counts: dict[str, int] | None = None,
    findings: int = 0,
    age_days: int = 0,
) -> Scan:
    created = utcnow() - timedelta(days=age_days)
    scan = Scan(
        scanner=scanner,
        target_type=target_type,
        target=target,
        status=status,
        options={},
        severity_counts=counts or {},
        findings_count=findings,
        created_at=created,
    )
    db.add(scan)
    db.commit()
    return scan


class TestComputeDashboard:
    def test_status_and_scanner_breakdown(self, db: Session) -> None:
        _add_scan(db, target="a", status=ScanStatus.SUCCEEDED)
        _add_scan(db, target="b", status=ScanStatus.FAILED)
        _add_scan(db, target="c", status=ScanStatus.SUCCEEDED, scanner=Scanner.GRYPE)
        data = compute_dashboard(db)
        assert data.total_scans == 3
        assert data.scans_by_status["succeeded"] == 2
        assert data.scans_by_status["failed"] == 1
        assert data.scans_by_scanner["trivy"] == 2
        assert data.scans_by_scanner["grype"] == 1

    def test_open_posture_uses_latest_per_target(self, db: Session) -> None:
        # Two scans of the same target: the newer (higher id) wins.
        _add_scan(db, target="repo", status=ScanStatus.SUCCEEDED, counts={"critical": 5, "high": 2})
        _add_scan(db, target="repo", status=ScanStatus.SUCCEEDED, counts={"critical": 1, "high": 0})
        _add_scan(db, target="other", status=ScanStatus.SUCCEEDED, counts={"high": 3}, findings=3)
        data = compute_dashboard(db)
        assert data.open_critical == 1  # latest repo scan only
        assert data.open_high == 3  # other scan
        targets = {p.target: p for p in data.top_vulnerable_targets}
        assert targets["repo"].critical == 1
        assert targets["other"].high == 3

    def test_open_posture_keeps_target_types_distinct(self, db: Session) -> None:
        """The same target string under different target types is two identities.

        Grype scans images, filesystems, and SBOMs; a shared name (e.g. two
        unrelated things both called ``sbom.json``/``app``) must not collapse
        into one "latest scan", silently dropping the other's findings from the
        aggregates.
        """
        _add_scan(
            db,
            target="app",
            target_type=TargetType.IMAGE,
            scanner=Scanner.GRYPE,
            status=ScanStatus.SUCCEEDED,
            counts={"critical": 2},
            findings=2,
        )
        _add_scan(
            db,
            target="app",
            target_type=TargetType.FILESYSTEM,
            scanner=Scanner.GRYPE,
            status=ScanStatus.SUCCEEDED,
            counts={"critical": 3},
            findings=3,
        )
        data = compute_dashboard(db)
        # Both identities contribute; neither shadows the other.
        assert data.open_critical == 5
        postures = {(p.target_type, p.target): p for p in data.top_vulnerable_targets}
        assert postures[("image", "app")].critical == 2
        assert postures[("filesystem", "app")].critical == 3

    def test_latest_scan_still_wins_within_one_target_type(self, db: Session) -> None:
        _add_scan(
            db,
            target="app",
            target_type=TargetType.IMAGE,
            status=ScanStatus.SUCCEEDED,
            counts={"critical": 9},
        )
        _add_scan(
            db,
            target="app",
            target_type=TargetType.IMAGE,
            status=ScanStatus.SUCCEEDED,
            counts={"critical": 1},
        )
        data = compute_dashboard(db)
        assert data.open_critical == 1

    def test_time_series_length_and_shape(self, db: Session) -> None:
        _add_scan(db, target="a", status=ScanStatus.SUCCEEDED)
        data = compute_dashboard(db)
        assert len(data.scans_over_time) == 30
        assert all({"date", "count"} <= set(point) for point in data.scans_over_time)
        assert data.scans_over_time[-1]["count"] >= 1  # today

    def test_failed_alerts(self, db: Session) -> None:
        _add_scan(db, target="ok", status=ScanStatus.SUCCEEDED)
        _add_scan(db, target="bad", status=ScanStatus.FAILED)
        alerts = failed_scan_alerts(db)
        assert [a.target for a in alerts] == ["bad"]


class TestDashboardEndpoint:
    def test_requires_auth(self, client: TestClient) -> None:
        assert client.get("/api/dashboard").status_code == 401

    def test_returns_widgets(self, client: TestClient) -> None:
        setup_admin(client)
        db = SessionLocal()
        try:
            _add_scan(db, target="img", status=ScanStatus.SUCCEEDED, counts={"critical": 2})
            _add_scan(db, target="img2", status=ScanStatus.FAILED)
        finally:
            db.close()

        body = client.get("/api/dashboard").json()
        assert body["total_scans"] == 2
        assert body["open_critical"] == 2
        assert len(body["scans_over_time"]) == 30
        assert any(a["target"] == "img2" for a in body["failed_alerts"])
        # Postures carry the target type (part of the target's identity).
        assert body["top_vulnerable_targets"][0]["target_type"] == "image"
        # Scanner DB freshness is present (binaries absent in tests → unavailable).
        names = {info["name"] for info in body["scanner_db"]}
        assert names == {"trivy", "grype"}


class TestScannerDbStatusCache:
    @pytest.mark.asyncio
    async def test_probe_results_are_cached_within_ttl(self, monkeypatch) -> None:
        """One dashboard load must not spawn scanner subprocesses per request."""
        calls = {"n": 0}

        async def _fake_probe_trivy() -> system_info.ScannerDbInfo:
            calls["n"] += 1
            return system_info.ScannerDbInfo(name="trivy", available=True)

        async def _fake_probe_grype() -> system_info.ScannerDbInfo:
            return system_info.ScannerDbInfo(name="grype", available=True)

        monkeypatch.setattr(system_info, "_probe_trivy_db", _fake_probe_trivy)
        monkeypatch.setattr(system_info, "_probe_grype_db", _fake_probe_grype)
        monkeypatch.setattr(system_info, "_db_status_cache", None)

        first = await system_info.scanner_db_status()
        second = await system_info.scanner_db_status()

        assert calls["n"] == 1  # second call served from the TTL cache
        assert first == second

    @pytest.mark.asyncio
    async def test_expired_cache_reprobes(self, monkeypatch) -> None:
        calls = {"n": 0}

        async def _fake_probe() -> system_info.ScannerDbInfo:
            calls["n"] += 1
            return system_info.ScannerDbInfo(name="x", available=True)

        monkeypatch.setattr(system_info, "_probe_trivy_db", _fake_probe)
        monkeypatch.setattr(system_info, "_probe_grype_db", _fake_probe)
        monkeypatch.setattr(system_info, "_db_status_cache", None)

        await system_info.scanner_db_status()
        # Backdate the cache entry past the TTL to force a re-probe.
        stamp, infos = system_info._db_status_cache
        monkeypatch.setattr(
            system_info,
            "_db_status_cache",
            (stamp - system_info._DB_STATUS_TTL_SECONDS - 1, infos),
        )
        await system_info.scanner_db_status()

        assert calls["n"] == 4  # two probes per miss, two misses
