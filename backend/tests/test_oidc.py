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

import app.api.oidc as oidc_module_api
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

    def _oidc_login_on_fresh_client(self, client: TestClient, monkeypatch, claims: dict) -> None:
        """Drive a full OIDC login on a separate client (keeps ``client`` admin)."""
        self._patch_provider(monkeypatch, claims)
        oidc_client = TestClient(client.app)
        state = self._start_login(oidc_client)
        cb = oidc_client.get(
            "/api/auth/oidc/callback",
            params={"state": state, "code": "authcode"},
            follow_redirects=False,
        )
        assert cb.status_code == 302, cb.text

    def _oidc_login_audit_details(self, client: TestClient) -> dict | None:
        entries = client.get("/api/audit").json()["items"]
        logins = [e for e in entries if e["action"] == "auth.oidc_login"]
        assert logins, "no auth.oidc_login audit entry"
        return logins[0]["details"]

    def test_oidc_login_audits_mfa_delegation_under_mandatory_policy(
        self, client: TestClient, monkeypatch
    ) -> None:
        # SEC-8: mandatory MFA can't be enforced locally on the OIDC path (no local
        # second factor), so when the policy WOULD require it the OIDC login records
        # that the factor was delegated to the IdP — visibility for operators.
        csrf = setup_admin(client)
        resp = client.put(
            "/api/settings/authentication",
            json={"local_login_enabled": True, "mfa_policy": "required_all"},
            headers={CSRF: csrf},
        )
        assert resp.status_code == 200, resp.text
        _enable_oidc(client, csrf)
        self._oidc_login_on_fresh_client(
            client, monkeypatch, {"sub": "u1", "iss": ISSUER, "preferred_username": "vic"}
        )
        assert self._oidc_login_audit_details(client) == {"mfa_delegated_to_idp": True}

    def test_oidc_login_omits_mfa_delegation_when_policy_optional(
        self, client: TestClient, monkeypatch
    ) -> None:
        csrf = setup_admin(client)  # default policy is optional
        _enable_oidc(client, csrf)
        self._oidc_login_on_fresh_client(
            client, monkeypatch, {"sub": "u2", "iss": ISSUER, "preferred_username": "opt"}
        )
        assert self._oidc_login_audit_details(client) is None

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


class TestOidcRoleSyncHotfix:
    """Security hotfix: OIDC role sync must not demote on an absent groups claim
    and must never remove the last admin."""

    def _patch_provider(self, monkeypatch, claims: dict) -> None:
        async def fake_discover(issuer):
            return _METADATA

        async def fake_exchange(metadata, **kwargs):
            return {"id_token": "stub.jwt.token"}

        async def fake_verify(metadata, id_token, *, client_id, nonce):
            return claims

        monkeypatch.setattr(oidc_module, "discover", fake_discover)
        monkeypatch.setattr(oidc_module, "exchange_code", fake_exchange)
        monkeypatch.setattr(oidc_module, "verify_id_token", fake_verify)

    def _login(self, app, monkeypatch, claims: dict) -> TestClient:
        """Run one full OIDC login for ``claims`` in a fresh browser; return it."""
        self._patch_provider(monkeypatch, claims)
        browser = TestClient(app)
        resp = browser.get("/api/auth/oidc/login", follow_redirects=False)
        state = parse_qs(urlparse(resp.headers["location"]).query)["state"][0]
        browser.get(
            "/api/auth/oidc/callback",
            params={"state": state, "code": "authcode"},
            follow_redirects=False,
        )
        return browser

    def test_absent_groups_claim_preserves_existing_admin_role(
        self, client: TestClient, monkeypatch
    ) -> None:
        csrf = setup_admin(client)  # seed local admin (a second admin, so demotion is *allowed*)
        _enable_oidc(
            client, csrf, groups_claim="groups", admin_group="scrye-admins", default_role="viewer"
        )
        base = {"sub": "admin-1", "iss": ISSUER, "preferred_username": "boss"}
        # First login with the admin group present -> provisioned as admin.
        boss = self._login(client.app, monkeypatch, {**base, "groups": ["scrye-admins"]})
        assert boss.get("/api/auth/me").json()["role"] == "admin"
        # Next login where the ID token carries NO groups claim at all (e.g. the IdP
        # delivers groups only via UserInfo): the role must be PRESERVED, not
        # silently reset to default_role.
        boss2 = self._login(client.app, monkeypatch, base)
        assert boss2.get("/api/auth/me").json()["role"] == "admin"

    def test_present_groups_without_admin_group_demotes_when_other_admin_exists(
        self, client: TestClient, monkeypatch
    ) -> None:
        csrf = setup_admin(client)  # seed admin stays active -> boss is not the last admin
        _enable_oidc(
            client, csrf, groups_claim="groups", admin_group="scrye-admins", default_role="viewer"
        )
        base = {"sub": "admin-2", "iss": ISSUER, "preferred_username": "chief"}
        chief = self._login(client.app, monkeypatch, {**base, "groups": ["scrye-admins"]})
        assert chief.get("/api/auth/me").json()["role"] == "admin"
        # Groups claim present but WITHOUT the admin group -> authoritative demotion.
        chief2 = self._login(client.app, monkeypatch, {**base, "groups": ["some-team"]})
        assert chief2.get("/api/auth/me").json()["role"] == "viewer"

    def test_last_admin_is_not_demoted_via_sync(self, client: TestClient, monkeypatch) -> None:
        csrf = setup_admin(client)
        _enable_oidc(
            client, csrf, groups_claim="groups", admin_group="scrye-admins", default_role="viewer"
        )
        base = {"sub": "admin-3", "iss": ISSUER, "preferred_username": "solo"}
        solo = self._login(client.app, monkeypatch, {**base, "groups": ["scrye-admins"]})
        assert solo.get("/api/auth/me").json()["role"] == "admin"
        # Make ``solo`` the ONLY active admin by deactivating the seed local admin.
        solo_csrf = solo.cookies.get("scrye_csrf")
        seed = next(u for u in solo.get("/api/users").json() if u["username"] == "admin")
        deact = solo.patch(
            f"/api/users/{seed['id']}", json={"is_active": False}, headers={CSRF: solo_csrf}
        )
        assert deact.status_code == 200, deact.text
        # A login that would demote (groups present, admin group missing) must be
        # blocked by the last-admin guard: solo keeps admin.
        solo2 = self._login(client.app, monkeypatch, {**base, "groups": ["nobody"]})
        assert solo2.get("/api/auth/me").json()["role"] == "admin"


def test_binding_cookie_uses_host_prefix_when_secure(monkeypatch) -> None:
    """The browser-binding cookie must be a __Host- cookie under TLS (so no sibling
    subdomain can plant it), falling back to a plain host cookie on http dev."""
    from types import SimpleNamespace

    monkeypatch.setattr(
        oidc_module_api, "get_settings", lambda: SimpleNamespace(session_cookie_secure=True)
    )
    name, path, secure = oidc_module_api._binding_cookie()
    assert name == "__Host-scrye_oidc_binding"
    assert path == "/"
    assert secure is True

    monkeypatch.setattr(
        oidc_module_api, "get_settings", lambda: SimpleNamespace(session_cookie_secure=False)
    )
    name, path, secure = oidc_module_api._binding_cookie()
    assert name == "scrye_oidc_binding"
    assert secure is False


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
