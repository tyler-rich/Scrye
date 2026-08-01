"""Tests for the backup/restore HTTP endpoints and schedule configuration."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.test_auth import CSRF, USER_PW, setup_admin

PASSPHRASE = "backup-passphrase-1234"


class TestBackupEndpoints:
    def test_create_list_download_delete(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        created = client.post(
            "/api/backups", json={"passphrase": PASSPHRASE, "note": "nightly"}, headers={CSRF: csrf}
        )
        assert created.status_code == 201, created.text
        backup = created.json()
        assert backup["filename"].endswith(".scryebak")
        assert backup["kind"] == "manual"

        listing = client.get("/api/backups").json()
        assert listing["total"] == 1

        download = client.get(f"/api/backups/{backup['id']}/download")
        assert download.status_code == 200
        assert download.headers["content-type"] == "application/octet-stream"
        assert PASSPHRASE.encode() not in download.content

        assert (
            client.delete(f"/api/backups/{backup['id']}", headers={CSRF: csrf}).status_code == 204
        )
        assert client.get("/api/backups").json() == {"total": 0, "items": []}

    def test_short_passphrase_rejected(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        resp = client.post("/api/backups", json={"passphrase": "short"}, headers={CSRF: csrf})
        assert resp.status_code == 422

    def test_backups_are_admin_only(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        client.post(
            "/api/users",
            json={"username": "op1", "password": USER_PW, "role": "operator"},
            headers={CSRF: csrf},
        )
        op = TestClient(client.app)
        op.post("/api/auth/login", json={"username": "op1", "password": USER_PW})
        assert op.get("/api/backups").status_code == 403


class TestRestoreEndpoint:
    def test_restore_round_trip_via_api(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        # Add a second user so we can prove restore repopulates it.
        client.post(
            "/api/users",
            json={"username": "viewer9", "password": USER_PW, "role": "viewer"},
            headers={CSRF: csrf},
        )
        backup_id = client.post(
            "/api/backups", json={"passphrase": PASSPHRASE}, headers={CSRF: csrf}
        ).json()["id"]
        data = client.get(f"/api/backups/{backup_id}/download").content

        # Delete the second user, then restore the bundle.
        users = client.get("/api/users").json()["items"]
        viewer = next(u for u in users if u["username"] == "viewer9")
        client.patch(f"/api/users/{viewer['id']}", json={"is_active": False}, headers={CSRF: csrf})

        resp = client.post(
            "/api/backups/restore",
            files={"file": ("backup.scryebak", data, "application/octet-stream")},
            data={"passphrase": PASSPHRASE, "confirm": "true"},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["rows"] >= 2

    def test_restore_refused_while_scan_active(self, client: TestClient) -> None:
        """API-11: restore must refuse (409) while a scan is queued or running,
        so the table wipe cannot race a worker committing findings."""
        from app.db.models import Scan, Scanner, ScanStatus, TargetType
        from app.db.session import SessionLocal

        csrf = setup_admin(client)
        backup_id = client.post(
            "/api/backups", json={"passphrase": PASSPHRASE}, headers={CSRF: csrf}
        ).json()["id"]
        content = client.get(f"/api/backups/{backup_id}/download").content

        # Insert a queued scan directly (not via the worker) so it stays queued.
        session = SessionLocal()
        try:
            session.add(
                Scan(
                    scanner=Scanner.TRIVY,
                    target_type=TargetType.IMAGE,
                    target="alpine:3.19",
                    status=ScanStatus.QUEUED,
                )
            )
            session.commit()
        finally:
            session.close()

        resp = client.post(
            "/api/backups/restore",
            files={"file": ("backup.scryebak", content, "application/octet-stream")},
            data={"passphrase": PASSPHRASE, "confirm": "true"},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 409, resp.text

    def test_restore_conflicts_when_scan_queued_during_upload(
        self, client: TestClient, monkeypatch
    ) -> None:
        """CON-3: the endpoint's pre-check runs before the upload await, so a
        scan queued *during* the upload must still be caught — by the re-check
        inside the restore transaction — and answered 409 with nothing wiped."""
        from app.api import backups as backups_module
        from app.db.models import Scan, Scanner, ScanStatus, TargetType
        from app.db.session import SessionLocal

        csrf = setup_admin(client)
        backup_id = client.post(
            "/api/backups", json={"passphrase": PASSPHRASE}, headers={CSRF: csrf}
        ).json()["id"]
        content = client.get(f"/api/backups/{backup_id}/download").content

        real_read = backups_module.read_upload_capped

        async def read_and_race(file, max_bytes, *, what):
            data = await real_read(file, max_bytes, what=what)
            # Simulate the race: a scan lands after the pre-check passed.
            session = SessionLocal()
            try:
                session.add(
                    Scan(
                        scanner=Scanner.GRYPE,
                        target_type=TargetType.IMAGE,
                        target="raced:latest",
                        status=ScanStatus.QUEUED,
                    )
                )
                session.commit()
            finally:
                session.close()
            return data

        monkeypatch.setattr(backups_module, "read_upload_capped", read_and_race)
        resp = client.post(
            "/api/backups/restore",
            files={"file": ("backup.scryebak", content, "application/octet-stream")},
            data={"passphrase": PASSPHRASE, "confirm": "true"},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 409, resp.text

        # Nothing was wiped: the racing scan is intact and still queued.
        session = SessionLocal()
        try:
            from sqlalchemy import select

            raced = session.scalar(select(Scan).where(Scan.target == "raced:latest"))
            assert raced is not None and raced.status is ScanStatus.QUEUED
        finally:
            session.close()
        # The worker was resumed even though the restore aborted.
        assert client.app.state.scan_worker._resume_gate.is_set()

    def test_restore_resumes_worker_after_success(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        backup_id = client.post(
            "/api/backups", json={"passphrase": PASSPHRASE}, headers={CSRF: csrf}
        ).json()["id"]
        content = client.get(f"/api/backups/{backup_id}/download").content
        resp = client.post(
            "/api/backups/restore",
            files={"file": ("backup.scryebak", content, "application/octet-stream")},
            data={"passphrase": PASSPHRASE, "confirm": "true"},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 200, resp.text
        assert client.app.state.scan_worker._resume_gate.is_set()

    def test_restore_rejects_scrypt_parameter_bomb(self, client: TestClient) -> None:
        """SEC-2: a crafted bundle demanding an absurd scrypt work factor is a
        400, rejected before any derivation memory is committed."""
        import json

        csrf = setup_admin(client)
        backup_id = client.post(
            "/api/backups", json={"passphrase": PASSPHRASE}, headers={CSRF: csrf}
        ).json()["id"]
        content = client.get(f"/api/backups/{backup_id}/download").content
        envelope = json.loads(content)
        envelope["kdf"]["n"] = 2**30  # ~128 GiB of scrypt memory if honored
        tampered = json.dumps(envelope).encode("utf-8")

        resp = client.post(
            "/api/backups/restore",
            files={"file": ("backup.scryebak", tampered, "application/octet-stream")},
            data={"passphrase": PASSPHRASE, "confirm": "true"},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 400, resp.text
        assert "scrypt" in resp.json()["detail"]

    def test_restore_requires_confirmation(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        data = client.post("/api/backups", json={"passphrase": PASSPHRASE}, headers={CSRF: csrf})
        backup_id = data.json()["id"]
        content = client.get(f"/api/backups/{backup_id}/download").content
        resp = client.post(
            "/api/backups/restore",
            files={"file": ("backup.scryebak", content, "application/octet-stream")},
            data={"passphrase": PASSPHRASE, "confirm": "false"},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 400

    def test_restore_wrong_passphrase(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        backup_id = client.post(
            "/api/backups", json={"passphrase": PASSPHRASE}, headers={CSRF: csrf}
        ).json()["id"]
        content = client.get(f"/api/backups/{backup_id}/download").content
        resp = client.post(
            "/api/backups/restore",
            files={"file": ("backup.scryebak", content, "application/octet-stream")},
            data={"passphrase": "wrong-passphrase", "confirm": "true"},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 400


class TestBackupSchedule:
    def test_schedule_requires_passphrase_to_enable(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        resp = client.put(
            "/api/backups/schedule",
            json={"enabled": True, "interval_hours": 12, "retention_count": 5},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 400

    def test_schedule_masks_passphrase(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        resp = client.put(
            "/api/backups/schedule",
            json={
                "enabled": True,
                "interval_hours": 12,
                "retention_count": 5,
                "passphrase": PASSPHRASE,
            },
            headers={CSRF: csrf},
        )
        assert resp.status_code == 200, resp.text
        body = client.get("/api/backups/schedule").json()
        assert body["enabled"] is True
        assert body["passphrase"]["is_set"] is True
        assert PASSPHRASE not in client.get("/api/backups/schedule").text
