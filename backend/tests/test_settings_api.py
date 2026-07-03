"""Tests for the general/authentication/scanner settings and About endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.test_auth import CSRF, USER_PW, setup_admin


def _make_viewer(client: TestClient, csrf: str, name: str = "viewer1") -> TestClient:
    """Create a viewer account and return a client logged in as them."""
    client.post(
        "/api/users",
        json={"username": name, "password": USER_PW, "role": "viewer"},
        headers={CSRF: csrf},
    )
    viewer = TestClient(client.app)
    viewer.post("/api/auth/login", json={"username": name, "password": USER_PW})
    return viewer


class TestGeneralSettings:
    def test_defaults_and_update(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        assert client.get("/api/settings/general").json()["instance_name"] == "Scrye"
        resp = client.put(
            "/api/settings/general",
            json={"instance_name": "Prod Scrye", "admin_note": "east cluster"},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 200
        assert client.get("/api/settings/general").json()["instance_name"] == "Prod Scrye"

    def test_viewer_can_read_but_not_write(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        viewer = _make_viewer(client, csrf)
        assert viewer.get("/api/settings/general").status_code == 200
        resp = viewer.get("/api/auth/me")
        vcsrf = viewer.cookies.get("scrye_csrf")
        assert resp.status_code == 200
        assert (
            viewer.put(
                "/api/settings/general",
                json={"instance_name": "hax"},
                headers={CSRF: vcsrf},
            ).status_code
            == 403
        )


class TestAuthenticationSettings:
    def test_cannot_disable_local_login_without_oidc(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        resp = client.put(
            "/api/settings/authentication",
            json={"local_login_enabled": False, "mfa_policy": "optional"},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 400

    def test_mfa_policy_persists(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        resp = client.put(
            "/api/settings/authentication",
            json={"local_login_enabled": True, "mfa_policy": "required_admin"},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 200
        assert client.get("/api/settings/authentication").json()["mfa_policy"] == "required_admin"


class TestScannerSettings:
    def test_update_defaults(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        resp = client.put(
            "/api/settings/scanners",
            json={
                "default_severities": ["HIGH", "CRITICAL"],
                "default_ignore_unfixed": True,
                "trivyignore": "CVE-2021-1234",
                "grype_ignore": "",
                "auto_update_db": False,
                "db_update_interval_hours": 12,
            },
            headers={CSRF: csrf},
        )
        assert resp.status_code == 200
        body = client.get("/api/settings/scanners").json()
        assert body["default_severities"] == ["HIGH", "CRITICAL"]
        assert body["default_ignore_unfixed"] is True
        assert body["db_update_interval_hours"] == 12


class TestAbout:
    def test_about_reports_version_and_counts(self, client: TestClient) -> None:
        setup_admin(client)
        body = client.get("/api/settings/about").json()
        assert body["version"]
        assert body["user_count"] == 1
        assert body["oidc_enabled"] is False
        assert isinstance(body["scanners"], list) and len(body["scanners"]) == 3
        # Scanner probe never leaks anything secret and always returns a name.
        assert {s["name"] for s in body["scanners"]} == {"trivy", "grype", "syft"}
