"""Tests for RBAC enforcement, admin user management, and the audit log."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.test_auth import ADMIN_PW, CSRF, USER_PW, setup_admin


def make_user(client: TestClient, csrf: str, username: str, role: str) -> dict:
    """Create a user as the logged-in admin and return its JSON view."""
    resp = client.post(
        "/api/users",
        json={"username": username, "password": USER_PW, "role": role},
        headers={CSRF: csrf},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def login_as(client: TestClient, username: str, password: str = USER_PW) -> tuple[TestClient, str]:
    """Open a separate browser (cookie jar) logged in as ``username``."""
    browser = TestClient(client.app)
    resp = browser.post("/api/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return browser, resp.json()["csrf_token"]


class TestRbac:
    def test_role_floor_enforced_on_admin_endpoints(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        make_user(client, csrf, "vera", "viewer")
        make_user(client, csrf, "oscar", "operator")

        for username in ("vera", "oscar"):
            browser, user_csrf = login_as(client, username)
            assert browser.get("/api/users").status_code == 403
            assert browser.get("/api/audit").status_code == 403
            resp = browser.post(
                "/api/users",
                json={"username": "sneak", "password": USER_PW, "role": "admin"},
                headers={CSRF: user_csrf},
            )
            assert resp.status_code == 403

        assert client.get("/api/users").status_code == 200
        assert client.get("/api/audit").status_code == 200

    def test_unauthenticated_gets_401(self, client: TestClient) -> None:
        setup_admin(client)
        fresh = TestClient(client.app)
        assert fresh.get("/api/users").status_code == 401
        assert fresh.get("/api/audit").status_code == 401


class TestUserManagement:
    def test_create_and_list(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        created = make_user(client, csrf, "vera", "viewer")
        assert created["role"] == "viewer"

        listed = client.get("/api/users").json()
        assert [u["username"] for u in listed] == ["admin", "vera"]
        # No credential material anywhere in the response.
        assert "password" not in str(listed).lower()

    def test_duplicate_username_conflicts(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        make_user(client, csrf, "vera", "viewer")
        resp = client.post(
            "/api/users",
            json={"username": "VERA", "password": USER_PW, "role": "viewer"},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 409

    def test_role_change(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        vera = make_user(client, csrf, "vera", "viewer")
        resp = client.patch(
            f"/api/users/{vera['id']}", json={"role": "operator"}, headers={CSRF: csrf}
        )
        assert resp.status_code == 200
        assert resp.json()["role"] == "operator"

    def test_self_lockout_guards(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        me = client.get("/api/auth/me").json()
        for payload in ({"role": "viewer"}, {"is_active": False}):
            resp = client.patch(f"/api/users/{me['id']}", json=payload, headers={CSRF: csrf})
            assert resp.status_code == 400

    def test_deactivation_revokes_sessions_and_blocks_login(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        vera = make_user(client, csrf, "vera", "viewer")
        browser, _ = login_as(client, "vera")
        assert browser.get("/api/auth/me").status_code == 200

        resp = client.patch(
            f"/api/users/{vera['id']}", json={"is_active": False}, headers={CSRF: csrf}
        )
        assert resp.status_code == 200
        assert browser.get("/api/auth/me").status_code == 401
        relog = TestClient(client.app).post(
            "/api/auth/login", json={"username": "vera", "password": USER_PW}
        )
        assert relog.status_code == 401

    def test_admin_password_reset_revokes_sessions(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        vera = make_user(client, csrf, "vera", "viewer")
        browser, _ = login_as(client, "vera")

        new_pw = "a-brand-new-passphrase"
        resp = client.patch(
            f"/api/users/{vera['id']}", json={"password": new_pw}, headers={CSRF: csrf}
        )
        assert resp.status_code == 200
        assert browser.get("/api/auth/me").status_code == 401
        browser2, _ = login_as(client, "vera", new_pw)
        assert browser2.get("/api/auth/me").status_code == 200


class TestAuditLog:
    def test_security_events_are_recorded(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        make_user(client, csrf, "vera", "viewer")
        fresh = TestClient(client.app)
        fresh.post("/api/auth/login", json={"username": "vera", "password": "wrong" * 3})
        browser, vera_csrf = login_as(client, "vera")
        browser.post("/api/auth/logout", headers={CSRF: vera_csrf})

        page = client.get("/api/audit").json()
        actions = [e["action"] for e in page["items"]]
        for expected in (
            "auth.setup",
            "user.created",
            "auth.login_failed",
            "auth.login",
            "auth.logout",
        ):
            assert expected in actions, f"missing {expected} in {actions}"
        assert page["total"] == len(page["items"])

    def test_audit_entries_contain_no_secret_values(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        make_user(client, csrf, "vera", "viewer")
        text = client.get("/api/audit").text
        assert ADMIN_PW not in text
        assert USER_PW not in text
        assert "argon2" not in text

    def test_failed_login_records_username_and_ip(self, client: TestClient) -> None:
        setup_admin(client)
        fresh = TestClient(client.app)
        fresh.post("/api/auth/login", json={"username": "GhostUser", "password": "wrong" * 3})
        entries = client.get("/api/audit").json()["items"]
        failed = next(e for e in entries if e["action"] == "auth.login_failed")
        assert failed["details"] == {"username": "ghostuser"}
        assert failed["ip"]
        assert failed["actor_id"] is None
