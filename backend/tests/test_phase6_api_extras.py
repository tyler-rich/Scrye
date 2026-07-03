"""Tests for Phase 6 API additions: notification events + retention settings."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.test_auth import CSRF, setup_admin


class TestNotificationEvents:
    def test_events_endpoint_lists_known_events(self, client: TestClient) -> None:
        setup_admin(client)
        events = client.get("/api/notifications/events").json()
        assert set(events) == {"scan_completed", "scan_failed", "scan_high_severity"}

    def test_channel_persists_events(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        resp = client.post(
            "/api/notifications",
            json={
                "name": "alerts",
                "type": "webhook",
                "config": {"url": "https://x.test"},
                "events": ["scan_failed", "scan_high_severity"],
            },
            headers={CSRF: csrf},
        )
        assert resp.status_code == 201, resp.text
        cid = resp.json()["id"]
        assert resp.json()["events"] == ["scan_failed", "scan_high_severity"]
        # Update replaces the set.
        updated = client.patch(
            f"/api/notifications/{cid}",
            json={"events": ["scan_completed"]},
            headers={CSRF: csrf},
        )
        assert updated.json()["events"] == ["scan_completed"]


class TestRetentionSettings:
    def test_defaults_and_update(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        assert client.get("/api/settings/retention").json() == {
            "enabled": False,
            "max_age_days": 90,
        }
        resp = client.put(
            "/api/settings/retention",
            json={"enabled": True, "max_age_days": 30},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 200
        assert resp.json() == {"enabled": True, "max_age_days": 30}

    def test_update_requires_admin(self, client: TestClient) -> None:
        setup_admin(client)
        # No CSRF header → rejected.
        assert (
            client.put(
                "/api/settings/retention", json={"enabled": True, "max_age_days": 30}
            ).status_code
            == 403
        )
