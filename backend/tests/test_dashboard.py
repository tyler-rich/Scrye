"""Tests for dashboard aggregation (app.core.dashboard) and its endpoint."""

from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

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
    counts: dict[str, int] | None = None,
    findings: int = 0,
    age_days: int = 0,
) -> Scan:
    created = utcnow() - timedelta(days=age_days)
    scan = Scan(
        scanner=scanner,
        target_type=TargetType.IMAGE,
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
        # Scanner DB freshness is present (binaries absent in tests → unavailable).
        names = {info["name"] for info in body["scanner_db"]}
        assert names == {"trivy", "grype"}
