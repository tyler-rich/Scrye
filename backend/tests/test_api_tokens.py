"""Tests for personal API tokens and bearer-token authentication."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.test_auth import CSRF, USER_PW, setup_admin


def _make_operator(client: TestClient, csrf: str, name: str = "op1") -> TestClient:
    """Create an operator and return a client logged in as them."""
    client.post(
        "/api/users",
        json={"username": name, "password": USER_PW, "role": "operator"},
        headers={CSRF: csrf},
    )
    op = TestClient(client.app)
    op.post("/api/auth/login", json={"username": name, "password": USER_PW})
    return op


class TestApiTokenLifecycle:
    def test_create_returns_plaintext_once(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        resp = client.post("/api/api-tokens", json={"name": "ci"}, headers={CSRF: csrf})
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["token"].startswith("scrye_pat_")
        assert body["token_prefix"] == body["token"][:14]
        # Listing never includes the plaintext.
        listing = client.get("/api/api-tokens").json()
        assert listing["total"] == 1
        assert "token" not in listing["items"][0]

    def test_bearer_token_authenticates(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        token = client.post("/api/api-tokens", json={"name": "ci"}, headers={CSRF: csrf}).json()[
            "token"
        ]
        bare = TestClient(client.app)  # no cookies
        resp = bare.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["username"] == "admin"

    def test_revoked_token_is_rejected(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        created = client.post("/api/api-tokens", json={"name": "ci"}, headers={CSRF: csrf}).json()
        assert (
            client.delete(f"/api/api-tokens/{created['id']}", headers={CSRF: csrf}).status_code
            == 204
        )
        bare = TestClient(client.app)
        resp = bare.get("/api/auth/me", headers={"Authorization": f"Bearer {created['token']}"})
        assert resp.status_code == 401


class TestApiTokenAuthorization:
    def test_role_cannot_exceed_owner(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        op = _make_operator(client, csrf)
        opcsrf = op.cookies.get("scrye_csrf")
        resp = op.post(
            "/api/api-tokens",
            json={"name": "escalate", "role": "admin"},
            headers={CSRF: opcsrf},
        )
        assert resp.status_code == 403

    def test_token_role_gates_admin_endpoints(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        op = _make_operator(client, csrf)
        opcsrf = op.cookies.get("scrye_csrf")
        token = op.post(
            "/api/api-tokens",
            json={"name": "viewer-token", "role": "viewer"},
            headers={CSRF: opcsrf},
        ).json()["token"]
        bare = TestClient(client.app)
        headers = {"Authorization": f"Bearer {token}"}
        # Viewer-scoped token can read but not hit an admin-only endpoint.
        assert bare.get("/api/settings/general", headers=headers).status_code == 200
        assert bare.get("/api/registries", headers=headers).status_code == 403

    def test_low_privilege_token_of_admin_cannot_mint_admin_token(self, client: TestClient) -> None:
        """QUA-1: a low-privilege token owned by an admin cannot escalate.

        The mint check must cap against the caller's *effective* role (the
        token's capped role), not the owner account's role. An admin who mints a
        viewer-scoped token, then uses that token to request an admin token, must
        be refused — otherwise a stolen/scoped token defeats role capping.
        """
        csrf = setup_admin(client)
        viewer_token = client.post(
            "/api/api-tokens",
            json={"name": "scoped-viewer", "role": "viewer"},
            headers={CSRF: csrf},
        ).json()["token"]
        bare = TestClient(client.app)
        headers = {"Authorization": f"Bearer {viewer_token}"}

        # Explicitly requesting a higher role is rejected...
        escalate = bare.post(
            "/api/api-tokens", json={"name": "escalate", "role": "admin"}, headers=headers
        )
        assert escalate.status_code == 403, escalate.text

        # ...and the default role is the effective (viewer) role, not the owner's
        # admin role, so a token minted with no explicit role stays a viewer.
        minted = bare.post("/api/api-tokens", json={"name": "default-role"}, headers=headers)
        assert minted.status_code == 201, minted.text
        assert minted.json()["role"] == "viewer"

    def test_token_auth_skips_csrf(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        token = client.post("/api/api-tokens", json={"name": "ci"}, headers={CSRF: csrf}).json()[
            "token"
        ]
        bare = TestClient(client.app)
        # A state-changing call with a bearer token and NO CSRF header succeeds.
        resp = bare.post(
            "/api/api-tokens",
            json={"name": "second"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 201

    def test_session_only_endpoints_dont_500_under_bearer_auth(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        token = client.post("/api/api-tokens", json={"name": "ci"}, headers={CSRF: csrf}).json()[
            "token"
        ]
        bare = TestClient(client.app)
        headers = {"Authorization": f"Bearer {token}"}
        # These endpoints assume a cookie session; a bearer token has none, and
        # must not trigger an unhandled 500 (auth.session is None).
        assert bare.get("/api/auth/sessions", headers=headers).status_code == 200
        assert bare.post("/api/auth/logout", headers=headers).status_code == 204
