"""Tests for notification channel CRUD, masking, and the test-send action."""

from __future__ import annotations

from fastapi.testclient import TestClient

import app.api.notifications as notifications_api
from app.core.notifications import DeliveryResult
from tests.test_auth import CSRF, setup_admin

WEBHOOK_SECRET = "super-secret-webhook-token"


class TestNotificationCrud:
    def test_create_masks_secret(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        resp = client.post(
            "/api/notifications",
            json={
                "name": "ops-webhook",
                "type": "webhook",
                "config": {"url": "https://example.test/hook"},
                "secret": WEBHOOK_SECRET,
                "enabled": True,
            },
            headers={CSRF: csrf},
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["secret"]["is_set"] is True
        assert WEBHOOK_SECRET not in resp.text
        assert body["secret"]["value"] != WEBHOOK_SECRET

    def test_smtp_requires_secret(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        resp = client.post(
            "/api/notifications",
            json={"name": "mail", "type": "smtp", "config": {"host": "mx"}},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 422

    def test_duplicate_name_conflicts(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        payload = {"name": "dup", "type": "webhook", "config": {"url": "https://x.test"}}
        assert (
            client.post("/api/notifications", json=payload, headers={CSRF: csrf}).status_code == 201
        )
        assert (
            client.post("/api/notifications", json=payload, headers={CSRF: csrf}).status_code == 409
        )

    def test_delete_removes_channel(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        cid = client.post(
            "/api/notifications",
            json={"name": "temp", "type": "webhook", "config": {"url": "https://x.test"}},
            headers={CSRF: csrf},
        ).json()["id"]
        assert client.delete(f"/api/notifications/{cid}", headers={CSRF: csrf}).status_code == 204
        assert client.get("/api/notifications").json() == []


class TestNotificationTest:
    def test_send_uses_transport(self, client: TestClient, monkeypatch) -> None:
        csrf = setup_admin(client)
        cid = client.post(
            "/api/notifications",
            json={"name": "hook", "type": "webhook", "config": {"url": "https://x.test"}},
            headers={CSRF: csrf},
        ).json()["id"]

        async def fake_send(channel, message):
            return DeliveryResult(ok=True, detail="Message delivered.")

        monkeypatch.setattr(notifications_api, "send_notification", fake_send)
        resp = client.post(f"/api/notifications/{cid}/test", headers={CSRF: csrf})
        assert resp.status_code == 200
        assert resp.json() == {"ok": True, "detail": "Message delivered."}
