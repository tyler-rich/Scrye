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
        assert len(listing) == 1

        download = client.get(f"/api/backups/{backup['id']}/download")
        assert download.status_code == 200
        assert download.headers["content-type"] == "application/octet-stream"
        assert PASSPHRASE.encode() not in download.content

        assert (
            client.delete(f"/api/backups/{backup['id']}", headers={CSRF: csrf}).status_code == 204
        )
        assert client.get("/api/backups").json() == []

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
        users = client.get("/api/users").json()
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
