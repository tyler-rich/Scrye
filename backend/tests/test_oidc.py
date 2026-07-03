"""Tests for OIDC configuration and the authorization-code login flow.

The provider is mocked (no real network): discovery, code exchange, and ID-token
validation are stubbed so the linking/provisioning logic can be exercised.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

import app.auth.oidc as oidc_module
from app.auth.oidc import OidcMetadata
from tests.test_auth import CSRF, setup_admin

CLIENT_SECRET = "oidc-client-secret-value"
ISSUER = "https://idp.test"

_METADATA = OidcMetadata(
    issuer=ISSUER,
    authorization_endpoint=f"{ISSUER}/authorize",
    token_endpoint=f"{ISSUER}/token",
    jwks_uri=f"{ISSUER}/jwks",
)


def _enable_oidc(client: TestClient, csrf: str, **overrides: object) -> None:
    """Configure and enable OIDC with the mock provider."""
    payload = {
        "enabled": True,
        "issuer": ISSUER,
        "client_id": "scrye",
        "client_secret": CLIENT_SECRET,
        "auto_provision": True,
        "default_role": "viewer",
        **overrides,
    }
    resp = client.put("/api/oidc/config", json=payload, headers={CSRF: csrf})
    assert resp.status_code == 200, resp.text


class TestOidcConfig:
    def test_secret_is_write_only(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        _enable_oidc(client, csrf)
        body = client.get("/api/oidc/config").json()
        assert body["client_secret"]["is_set"] is True
        assert CLIENT_SECRET not in client.get("/api/oidc/config").text
        assert body["enabled"] is True

    def test_enabling_requires_issuer_and_client(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        resp = client.put(
            "/api/oidc/config",
            json={"enabled": True, "issuer": "", "client_id": ""},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 400

    def test_config_is_admin_only(self, client: TestClient) -> None:
        setup_admin(client)
        anon = TestClient(client.app)
        assert anon.get("/api/oidc/config").status_code == 401


class TestOidcLoginFlow:
    def _patch_provider(self, monkeypatch, claims: dict) -> None:
        """Stub discovery, token exchange, and ID-token validation."""

        async def fake_discover(issuer):
            return _METADATA

        async def fake_exchange(metadata, **kwargs):
            return {"id_token": "stub.jwt.token"}

        async def fake_verify(metadata, id_token, *, client_id, nonce):
            return claims

        monkeypatch.setattr(oidc_module, "discover", fake_discover)
        monkeypatch.setattr(oidc_module, "exchange_code", fake_exchange)
        monkeypatch.setattr(oidc_module, "verify_id_token", fake_verify)

    def _start_login(self, client: TestClient) -> str:
        """Hit the login endpoint and return the generated ``state``."""
        resp = client.get("/api/auth/oidc/login", follow_redirects=False)
        assert resp.status_code == 302, resp.text
        location = resp.headers["location"]
        assert location.startswith(f"{ISSUER}/authorize")
        return parse_qs(urlparse(location).query)["state"][0]

    def test_login_disabled_redirects_to_error(self, client: TestClient) -> None:
        setup_admin(client)
        resp = client.get("/api/auth/oidc/login", follow_redirects=False)
        assert resp.status_code == 302
        assert "oidc_error=disabled" in resp.headers["location"]

    def test_provisions_new_user_on_first_login(self, client: TestClient, monkeypatch) -> None:
        csrf = setup_admin(client)
        _enable_oidc(client, csrf)
        self._patch_provider(
            monkeypatch,
            {"sub": "abc-123", "iss": ISSUER, "preferred_username": "alice", "email": "a@test"},
        )
        state = self._start_login(client)
        callback = client.get(
            "/api/auth/oidc/callback",
            params={"state": state, "code": "authcode"},
            follow_redirects=False,
        )
        assert callback.status_code == 302
        assert callback.headers["location"] == "/"
        # A session was established for the provisioned account.
        assert client.get("/api/auth/me").json()["username"] == "alice"
        assert client.get("/api/auth/me").json()["role"] == "viewer"

    def test_admin_group_maps_to_admin_role(self, client: TestClient, monkeypatch) -> None:
        csrf = setup_admin(client)
        _enable_oidc(client, csrf, groups_claim="groups", admin_group="scrye-admins")
        self._patch_provider(
            monkeypatch,
            {
                "sub": "admin-1",
                "iss": ISSUER,
                "preferred_username": "boss",
                "groups": ["scrye-admins"],
            },
        )
        state = self._start_login(client)
        client.get(
            "/api/auth/oidc/callback",
            params={"state": state, "code": "authcode"},
            follow_redirects=False,
        )
        assert client.get("/api/auth/me").json()["role"] == "admin"

    def test_unknown_state_is_rejected(self, client: TestClient, monkeypatch) -> None:
        csrf = setup_admin(client)
        _enable_oidc(client, csrf)
        self._patch_provider(monkeypatch, {"sub": "x", "iss": ISSUER})
        resp = client.get(
            "/api/auth/oidc/callback",
            params={"state": "never-issued", "code": "authcode"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "oidc_error=expired" in resp.headers["location"]

    def test_second_login_links_same_identity(self, client: TestClient, monkeypatch) -> None:
        csrf = setup_admin(client)
        _enable_oidc(client, csrf)
        claims = {"sub": "abc-123", "iss": ISSUER, "preferred_username": "alice"}
        self._patch_provider(monkeypatch, claims)

        for _ in range(2):
            fresh = TestClient(client.app)
            state = self._start_login(fresh)
            fresh.get(
                "/api/auth/oidc/callback",
                params={"state": state, "code": "authcode"},
                follow_redirects=False,
            )
            assert fresh.get("/api/auth/me").json()["username"] == "alice"

        # Only one local account exists for the repeated identity.
        users = client.get("/api/users").json()
        assert [u["username"] for u in users].count("alice") == 1
