"""Tests for the Prometheus /metrics endpoint (app.core.metrics)."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.metrics import render_metrics
from app.db.models import Scan, Scanner, ScanStatus, TargetType
from app.db.session import SessionLocal
from tests.test_auth import setup_admin


def _add_scan(db: Session, target: str, status: ScanStatus, counts: dict[str, int]) -> None:
    db.add(
        Scan(
            scanner=Scanner.TRIVY,
            target_type=TargetType.IMAGE,
            target=target,
            status=status,
            options={},
            severity_counts=counts,
            findings_count=sum(counts.values()),
        )
    )
    db.commit()


class TestRenderMetrics:
    def test_exposition_format(self, db: Session) -> None:
        _add_scan(db, "a", ScanStatus.SUCCEEDED, {"critical": 3, "high": 1})
        text = render_metrics(db)
        assert "# TYPE scrye_build_info gauge" in text
        assert 'scrye_scans_total{status="succeeded"} 1' in text
        assert 'scrye_open_findings{severity="critical"} 3' in text
        assert 'scrye_open_findings{severity="high"} 1' in text
        assert "scrye_users_total" in text
        assert text.endswith("\n")


class TestMetricsEndpoint:
    def test_requires_auth(self, client: TestClient) -> None:
        assert client.get("/metrics").status_code == 401

    def test_authenticated_scrape(self, client: TestClient) -> None:
        setup_admin(client)
        db = SessionLocal()
        try:
            _add_scan(db, "img", ScanStatus.SUCCEEDED, {"high": 2})
        finally:
            db.close()
        resp = client.get("/metrics")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/plain")
        assert 'scrye_open_findings{severity="high"} 2' in resp.text
