"""Tests for scheduled-scan CRUD, run-now, and the fire helper."""

from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.timeutil import utcnow
from app.db.models import Scan, Scanner, ScanSchedule, ScanStatus, TargetType
from app.workers.schedules import fire_due_schedules
from tests.test_auth import CSRF, setup_admin
from tests.test_rbac_users_audit import login_as, make_user

IMAGE_SCHEDULE = {
    "name": "nightly-nginx",
    "cron": "0 2 * * *",
    "scanner": "trivy",
    "target_type": "image",
    "target": "nginx:latest",
}


class TestScheduleCrud:
    def test_create_and_list(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        resp = client.post("/api/scan-schedules", json=IMAGE_SCHEDULE, headers={CSRF: csrf})
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["cron"] == "0 2 * * *"
        assert body["enabled"] is True
        assert client.get("/api/scan-schedules").json()[0]["name"] == "nightly-nginx"

    def test_invalid_cron_rejected(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        resp = client.post(
            "/api/scan-schedules",
            json={**IMAGE_SCHEDULE, "cron": "99 * * * *"},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 422

    def test_sbom_target_rejected(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        resp = client.post(
            "/api/scan-schedules",
            json={**IMAGE_SCHEDULE, "target_type": "sbom"},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 422

    def test_unsupported_scanner_combo_rejected(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        resp = client.post(
            "/api/scan-schedules",
            json={**IMAGE_SCHEDULE, "target_type": "repository", "scanner": "grype"},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 422

    def test_duplicate_name_conflicts(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        assert (
            client.post(
                "/api/scan-schedules", json=IMAGE_SCHEDULE, headers={CSRF: csrf}
            ).status_code
            == 201
        )
        assert (
            client.post(
                "/api/scan-schedules", json=IMAGE_SCHEDULE, headers={CSRF: csrf}
            ).status_code
            == 409
        )

    def test_replace_and_delete(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        sid = client.post("/api/scan-schedules", json=IMAGE_SCHEDULE, headers={CSRF: csrf}).json()[
            "id"
        ]
        resp = client.put(
            f"/api/scan-schedules/{sid}",
            json={**IMAGE_SCHEDULE, "cron": "*/30 * * * *", "enabled": False},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 200
        assert resp.json()["cron"] == "*/30 * * * *"
        assert resp.json()["enabled"] is False
        assert client.delete(f"/api/scan-schedules/{sid}", headers={CSRF: csrf}).status_code == 204

    def test_viewer_cannot_create(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        make_user(client, csrf, "vera", "viewer")
        browser, vcsrf = login_as(client, "vera")
        resp = browser.post("/api/scan-schedules", json=IMAGE_SCHEDULE, headers={CSRF: vcsrf})
        assert resp.status_code == 403


class TestRunNow:
    def test_run_now_queues_a_scan(self, client: TestClient, monkeypatch) -> None:
        csrf = setup_admin(client)
        submitted: list[int] = []

        async def fake_submit(scan_id: int) -> None:
            submitted.append(scan_id)

        monkeypatch.setattr(client.app.state.scan_worker, "submit", fake_submit)
        sid = client.post("/api/scan-schedules", json=IMAGE_SCHEDULE, headers={CSRF: csrf}).json()[
            "id"
        ]
        resp = client.post(f"/api/scan-schedules/{sid}/run", headers={CSRF: csrf})
        assert resp.status_code == 200
        assert resp.json()["last_scan_id"] is not None
        assert submitted == [resp.json()["last_scan_id"]]


class TestFireDueSchedules:
    def test_due_schedule_creates_scan(self, db: Session) -> None:
        schedule = ScanSchedule(
            name="every-minute",
            enabled=True,
            cron="* * * * *",
            scanner=Scanner.TRIVY,
            target_type=TargetType.IMAGE,
            target="alpine:3",
            options={},
            created_at=utcnow() - timedelta(minutes=5),
        )
        db.add(schedule)
        db.commit()

        created = fire_due_schedules(db)
        assert len(created) == 1
        scan = db.get(Scan, created[0])
        assert scan is not None
        assert scan.status is ScanStatus.QUEUED
        assert scan.target == "alpine:3"
        db.refresh(schedule)
        assert schedule.last_scan_id == scan.id
        assert schedule.last_status == "ok"

    def test_disabled_schedule_does_not_fire(self, db: Session) -> None:
        db.add(
            ScanSchedule(
                name="off",
                enabled=False,
                cron="* * * * *",
                scanner=Scanner.TRIVY,
                target_type=TargetType.IMAGE,
                target="alpine:3",
                options={},
            )
        )
        db.commit()
        assert fire_due_schedules(db) == []

    def test_not_due_when_recently_run(self, db: Session) -> None:
        db.add(
            ScanSchedule(
                name="midnight",
                enabled=True,
                cron="0 0 * * *",
                scanner=Scanner.TRIVY,
                target_type=TargetType.IMAGE,
                target="alpine:3",
                options={},
                last_run_at=utcnow(),
            )
        )
        db.commit()
        assert fire_due_schedules(db) == []
