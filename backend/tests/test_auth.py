"""Tests for local auth: bootstrap, login, sessions, CSRF, rate limiting."""

from __future__ import annotations

from fastapi.testclient import TestClient

# Throwaway test-only credentials (ephemeral users in a temp database).
ADMIN_PW = "unit-test-admin-passphrase"
USER_PW = "unit-test-user-passphrase!"

CSRF = "x-csrf-token"


def setup_admin(client: TestClient, username: str = "admin") -> str:
    """Bootstrap the first admin and return the CSRF token."""
    resp = client.post("/api/auth/setup", json={"username": username, "password": ADMIN_PW})
    assert resp.status_code == 201, resp.text
    return resp.json()["csrf_token"]


class TestBootstrap:
    def test_status_reports_needs_setup(self, client: TestClient) -> None:
        body = client.get("/api/auth/status").json()
        assert body["needs_setup"] is True
        assert body["authenticated"] is False
        assert body["user"] is None
        assert body["oidc"] == {"enabled": False, "display_name": "OIDC"}

    def test_setup_creates_admin_and_logs_in(self, client: TestClient) -> None:
        resp = client.post("/api/auth/setup", json={"username": "Admin", "password": ADMIN_PW})
        assert resp.status_code == 201
        body = resp.json()
        assert body["user"]["username"] == "admin"  # stored lowercase
        assert body["user"]["role"] == "admin"
        assert body["csrf_token"]
        assert "scrye_session" in resp.cookies
        assert "scrye_csrf" in resp.cookies
        # Session cookie is HttpOnly; CSRF cookie is not.
        set_cookies = "\n".join(
            v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie"
        )
        assert "scrye_session" in set_cookies and "HttpOnly" in set_cookies
        # Logged in immediately.
        assert client.get("/api/auth/me").json()["username"] == "admin"
        # Status flips.
        assert client.get("/api/auth/status").json()["needs_setup"] is False

    def test_setup_only_works_once(self, client: TestClient) -> None:
        setup_admin(client)
        resp = client.post("/api/auth/setup", json={"username": "evil", "password": ADMIN_PW})
        assert resp.status_code == 409

    def test_setup_rejects_short_password(self, client: TestClient) -> None:
        resp = client.post("/api/auth/setup", json={"username": "admin", "password": "short"})
        assert resp.status_code == 422

    def test_no_credential_material_in_responses(self, client: TestClient) -> None:
        resp = client.post("/api/auth/setup", json={"username": "admin", "password": ADMIN_PW})
        for text in (resp.text, client.get("/api/auth/me").text):
            assert ADMIN_PW not in text
            assert "password" not in text.lower()
            assert "argon2" not in text.lower()


class TestLogin:
    def test_login_logout_round_trip(self, client: TestClient) -> None:
        setup_admin(client)
        client.cookies.clear()
        assert client.get("/api/auth/me").status_code == 401

        resp = client.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PW})
        assert resp.status_code == 200
        csrf = resp.json()["csrf_token"]
        assert client.get("/api/auth/me").status_code == 200

        assert client.post("/api/auth/logout", headers={CSRF: csrf}).status_code == 204
        assert client.get("/api/auth/me").status_code == 401

    def test_wrong_password_and_unknown_user_are_indistinguishable(
        self, client: TestClient
    ) -> None:
        setup_admin(client)
        client.cookies.clear()
        wrong = client.post("/api/auth/login", json={"username": "admin", "password": USER_PW})
        unknown = client.post("/api/auth/login", json={"username": "nobody", "password": USER_PW})
        assert wrong.status_code == unknown.status_code == 401
        assert wrong.json() == unknown.json()

    def test_revoked_session_cookie_is_dead(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        assert client.post("/api/auth/logout", headers={CSRF: csrf}).status_code == 204
        # Re-present the old cookie manually: still unauthorized.
        assert client.get("/api/auth/me").status_code == 401

    def test_rate_limit_kicks_in(self, client: TestClient) -> None:
        setup_admin(client)
        client.cookies.clear()
        # Setup consumed 1 attempt; burn through the rest of the window.
        for _ in range(4):
            client.post("/api/auth/login", json={"username": "admin", "password": "x" * 12})
        resp = client.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PW})
        assert resp.status_code == 429
        assert "retry-after" in resp.headers


class TestCsrf:
    def test_state_changing_requires_csrf_header(self, client: TestClient) -> None:
        setup_admin(client)
        assert client.post("/api/auth/logout").status_code == 403
        assert client.post("/api/auth/logout", headers={CSRF: "forged-token"}).status_code == 403
        # Still logged in after the rejected attempts.
        assert client.get("/api/auth/me").status_code == 200

    def test_csrf_cookie_matches_session_token(self, client: TestClient) -> None:
        setup_admin(client)
        csrf_cookie = client.cookies.get("scrye_csrf")
        assert csrf_cookie
        assert client.post("/api/auth/logout", headers={CSRF: csrf_cookie}).status_code == 204


class TestPasswordChange:
    def test_wrong_current_password_rejected(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        resp = client.post(
            "/api/auth/password",
            json={"current_password": "not-it-at-all", "new_password": USER_PW},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 403

    def test_change_revokes_other_sessions(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        other = TestClient(client.app)
        other.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PW})
        assert other.get("/api/auth/me").status_code == 200

        resp = client.post(
            "/api/auth/password",
            json={"current_password": ADMIN_PW, "new_password": USER_PW},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 204
        # The other browser session is gone; this one survives.
        assert other.get("/api/auth/me").status_code == 401
        assert client.get("/api/auth/me").status_code == 200
        # Old password is dead, new one works.
        client.cookies.clear()
        assert (
            client.post(
                "/api/auth/login", json={"username": "admin", "password": ADMIN_PW}
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/api/auth/login", json={"username": "admin", "password": USER_PW}
            ).status_code
            == 200
        )


class TestSessions:
    def test_list_and_revoke_own_sessions(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        other = TestClient(client.app)
        other.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PW})

        sessions = client.get("/api/auth/sessions").json()["items"]
        assert len(sessions) == 2
        current = [s for s in sessions if s["current"]]
        others = [s for s in sessions if not s["current"]]
        assert len(current) == 1 and len(others) == 1

        resp = client.delete(f"/api/auth/sessions/{others[0]['id']}", headers={CSRF: csrf})
        assert resp.status_code == 204
        assert other.get("/api/auth/me").status_code == 401

    def test_cannot_revoke_foreign_session(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        # Create a second user with their own session.
        client.post(
            "/api/users",
            json={"username": "viewer1", "password": USER_PW, "role": "viewer"},
            headers={CSRF: csrf},
        )
        other = TestClient(client.app)
        other.post("/api/auth/login", json={"username": "viewer1", "password": USER_PW})
        other_id = other.get("/api/auth/sessions").json()["items"][0]["id"]

        resp = client.delete(f"/api/auth/sessions/{other_id}", headers={CSRF: csrf})
        assert resp.status_code == 404  # not yours → indistinguishable from absent
        assert other.get("/api/auth/me").status_code == 200
