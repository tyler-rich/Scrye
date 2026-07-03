"""Tests for OIDC configuration and the authorization-code login flow.

The provider is mocked (no real network): discovery, code exchange, and ID-token
validation are stubbed so the linking/provisioning logic can be exercised. A
separate suite exercises the *real* ID-token verification (signature + claims +
the pinned algorithm allowlist) against a locally generated RSA key.
"""

from __future__ import annotations

import time
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

import app.auth.oidc as oidc_module
from app.auth._jose import JsonWebKey, JsonWebToken
from app.auth.oidc import OidcError, OidcMetadata, _allowed_algorithms
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


def _rsa_key(kid: str = "test-key") -> JsonWebKey:
    """Generate an RSA signing key with a stable ``kid`` for tests."""
    return JsonWebKey.generate_key("RSA", 2048, {"kid": kid}, is_private=True)


def _sign(
    claims: dict, key: JsonWebKey, *, alg: str = "RS256", kid: str | None = "test-key"
) -> str:
    """Sign ``claims`` into a compact JWS using ``alg`` and ``key``."""
    header: dict = {"alg": alg}
    if kid is not None:
        header["kid"] = kid
    return JsonWebToken([alg]).encode(header, claims, key).decode("ascii")


def _base_claims(**overrides: object) -> dict:
    """Return a well-formed ID-token claim set (overridable per test)."""
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": "scrye",
        "sub": "subject-1",
        "exp": now + 300,
        "iat": now,
        "nonce": "the-nonce",
    }
    claims.update(overrides)
    return claims


class TestAllowedAlgorithms:
    """Unit coverage for the signing-algorithm allowlist selection."""

    def test_defaults_to_rs256_when_unadvertised(self) -> None:
        assert _allowed_algorithms(_METADATA) == ["RS256"]

    def test_uses_advertised_set_and_strips_none(self) -> None:
        meta = OidcMetadata(
            issuer=ISSUER,
            authorization_endpoint=f"{ISSUER}/authorize",
            token_endpoint=f"{ISSUER}/token",
            jwks_uri=f"{ISSUER}/jwks",
            id_token_signing_alg_values_supported=("RS256", "none", "ES256"),
        )
        assert _allowed_algorithms(meta) == ["RS256", "ES256"]

    def test_falls_back_when_only_none_advertised(self) -> None:
        meta = OidcMetadata(
            issuer=ISSUER,
            authorization_endpoint=f"{ISSUER}/authorize",
            token_endpoint=f"{ISSUER}/token",
            jwks_uri=f"{ISSUER}/jwks",
            id_token_signing_alg_values_supported=("none",),
        )
        assert _allowed_algorithms(meta) == ["RS256"]


class TestIdTokenVerification:
    """Exercise the real signature/claim/algorithm checks in verify_id_token."""

    def _patch_jwks(self, monkeypatch, key: JsonWebKey) -> None:
        """Serve the public half of ``key`` as the provider JWKS."""
        jwks = {"keys": [key.as_dict(is_private=False)]}

        async def fake_fetch(jwks_uri: str) -> dict:
            return jwks

        monkeypatch.setattr(oidc_module, "_fetch_jwks", fake_fetch)

    async def test_valid_rs256_token_is_accepted(self, monkeypatch) -> None:
        key = _rsa_key()
        self._patch_jwks(monkeypatch, key)
        token = _sign(_base_claims(), key)
        claims = await oidc_module.verify_id_token(
            _METADATA, token, client_id="scrye", nonce="the-nonce"
        )
        assert claims["sub"] == "subject-1"

    async def test_hs256_algorithm_confusion_is_rejected(self, monkeypatch) -> None:
        # Classic RS->HS confusion: sign with HMAC using the (public) modulus as
        # the shared secret. Pinning the allowlist to RS256 must reject it.
        key = _rsa_key()
        self._patch_jwks(monkeypatch, key)
        forged = _sign(_base_claims(), b"public-key-bytes-as-hmac-secret", alg="HS256", kid=None)
        with pytest.raises(OidcError):
            await oidc_module.verify_id_token(
                _METADATA, forged, client_id="scrye", nonce="the-nonce"
            )

    async def test_unsigned_none_token_is_rejected(self, monkeypatch) -> None:
        key = _rsa_key()
        self._patch_jwks(monkeypatch, key)
        # An "alg: none" token carries an empty signature; it must never pass.
        unsigned = (
            JsonWebToken(["none"]).encode({"alg": "none"}, _base_claims(), "").decode("ascii")
        )
        with pytest.raises(OidcError):
            await oidc_module.verify_id_token(
                _METADATA, unsigned, client_id="scrye", nonce="the-nonce"
            )

    async def test_advertised_hs_alg_still_cannot_forge_with_rsa_key(self, monkeypatch) -> None:
        # Even if a provider advertised HS256, an HMAC token signed with the RSA
        # public bytes must fail signature verification (the JWKS is an RSA key).
        key = _rsa_key()
        self._patch_jwks(monkeypatch, key)
        meta = OidcMetadata(
            issuer=ISSUER,
            authorization_endpoint=f"{ISSUER}/authorize",
            token_endpoint=f"{ISSUER}/token",
            jwks_uri=f"{ISSUER}/jwks",
            id_token_signing_alg_values_supported=("RS256", "HS256"),
        )
        forged = _sign(_base_claims(), b"whatever-secret", alg="HS256", kid=None)
        with pytest.raises(OidcError):
            await oidc_module.verify_id_token(meta, forged, client_id="scrye", nonce="the-nonce")

    async def test_wrong_audience_is_rejected(self, monkeypatch) -> None:
        key = _rsa_key()
        self._patch_jwks(monkeypatch, key)
        token = _sign(_base_claims(aud="someone-else"), key)
        with pytest.raises(OidcError):
            await oidc_module.verify_id_token(
                _METADATA, token, client_id="scrye", nonce="the-nonce"
            )

    async def test_expired_token_is_rejected(self, monkeypatch) -> None:
        key = _rsa_key()
        self._patch_jwks(monkeypatch, key)
        past = int(time.time()) - 3600
        token = _sign(_base_claims(exp=past, iat=past - 300), key)
        with pytest.raises(OidcError):
            await oidc_module.verify_id_token(
                _METADATA, token, client_id="scrye", nonce="the-nonce"
            )

    async def test_nonce_mismatch_is_rejected(self, monkeypatch) -> None:
        key = _rsa_key()
        self._patch_jwks(monkeypatch, key)
        token = _sign(_base_claims(nonce="attacker-nonce"), key)
        with pytest.raises(OidcError):
            await oidc_module.verify_id_token(
                _METADATA, token, client_id="scrye", nonce="the-nonce"
            )


class _FakeResponse:
    """Minimal stand-in for an httpx response returning a fixed JSON document."""

    def __init__(self, doc: dict) -> None:
        self._doc = doc

    def raise_for_status(self) -> None:
        """No-op: the fake always represents a 200 OK."""

    def json(self) -> dict:
        """Return the canned discovery document."""
        return self._doc


class _FakeAsyncClient:
    """Async-context-manager httpx client stub serving one discovery document."""

    def __init__(self, doc: dict, **_kwargs: object) -> None:
        self._doc = doc

    async def __aenter__(self) -> _FakeAsyncClient:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def get(self, _url: str) -> _FakeResponse:
        """Return the canned discovery response regardless of URL."""
        return _FakeResponse(self._doc)


class TestDiscoveryParsesSigningAlgs:
    """Discovery should capture ``id_token_signing_alg_values_supported``."""

    async def test_signing_algs_parsed_from_discovery(self, monkeypatch) -> None:
        issuer = "https://disc.test"
        doc = {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "jwks_uri": f"{issuer}/jwks",
            "id_token_signing_alg_values_supported": ["RS256", "ES256"],
        }
        oidc_module._metadata_cache.clear()
        monkeypatch.setattr(
            oidc_module.httpx, "AsyncClient", lambda **kw: _FakeAsyncClient(doc, **kw)
        )
        metadata = await oidc_module.discover(issuer)
        assert metadata.id_token_signing_alg_values_supported == ("RS256", "ES256")
        assert _allowed_algorithms(metadata) == ["RS256", "ES256"]
        oidc_module._metadata_cache.clear()

    async def test_missing_signing_algs_defaults_empty(self, monkeypatch) -> None:
        issuer = "https://disc2.test"
        doc = {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "jwks_uri": f"{issuer}/jwks",
        }
        oidc_module._metadata_cache.clear()
        monkeypatch.setattr(
            oidc_module.httpx, "AsyncClient", lambda **kw: _FakeAsyncClient(doc, **kw)
        )
        metadata = await oidc_module.discover(issuer)
        assert metadata.id_token_signing_alg_values_supported == ()
        assert _allowed_algorithms(metadata) == ["RS256"]
        oidc_module._metadata_cache.clear()
