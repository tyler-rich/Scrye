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

    def test_webhook_url_is_encrypted_and_masked(self, client: TestClient) -> None:
        """SEC-1: a token-bearing generic webhook URL must not be readable back.

        Slack/Teams/Mattermost webhook URLs embed the credential in the path, so
        the URL is treated as a write-only secret (stored encrypted, masked on
        read) exactly like Discord — not echoed verbatim from the config column.
        """
        csrf = setup_admin(client)
        secret_url = "https://hooks.slack.test/services/T000/B000/XXXXSECRETTOKEN"
        resp = client.post(
            "/api/notifications",
            json={"name": "slack", "type": "webhook", "config": {"url": secret_url}},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 201, resp.text
        assert "XXXXSECRETTOKEN" not in resp.text
        assert resp.json()["secret"]["is_set"] is True
        assert resp.json()["config"].get("url") in (None, notifications_api._URL_MASK)
        # And the read list never surfaces the token either.
        listing = client.get("/api/notifications", headers={CSRF: csrf})
        assert "XXXXSECRETTOKEN" not in listing.text

    def test_webhook_requires_a_url(self, client: TestClient) -> None:
        """A webhook with no URL is rejected (the URL is now its credential)."""
        csrf = setup_admin(client)
        resp = client.post(
            "/api/notifications",
            json={"name": "empty", "type": "webhook", "config": {}},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 422

    def test_discord_url_is_encrypted_and_masked(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        webhook = "https://discord.com/api/webhooks/123/super-secret-token"
        resp = client.post(
            "/api/notifications",
            json={"name": "disc", "type": "discord", "config": {"url": webhook}},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 201, resp.text
        # The webhook token (the credential) is never returned in full, and the
        # secret is recorded as set (it moved into the encrypted secret column).
        assert "super-secret-token" not in resp.text
        assert resp.json()["secret"]["is_set"] is True
        listing = client.get("/api/notifications", headers={CSRF: csrf})
        assert "super-secret-token" not in listing.text

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

    def test_update_cannot_clear_mandatory_secret(self, client: TestClient) -> None:
        """PATCH secret="" must not reach a state create forbids (APIR-6).

        Every channel type currently requires a secret, so clearing it would
        leave an enabled channel with no credential that only fails at send time.
        """
        csrf = setup_admin(client)
        cid = client.post(
            "/api/notifications",
            json={"name": "smtp1", "type": "smtp", "config": {"host": "mx"}, "secret": "pw"},
            headers={CSRF: csrf},
        ).json()["id"]
        resp = client.patch(
            f"/api/notifications/{cid}",
            json={"secret": ""},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 422
        assert "secret is required" in resp.json()["detail"].lower()

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
