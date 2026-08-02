"""Tests for OIDC account linking: self-link, guarded self-unlink, stale links.

Structured to mirror the abuse-case table this feature was scoped against
(docs/ARCHIVE.md §14, 2026-08-02 — OIDC account linking): :class:`TestAbuseCases`
carries one test per case **A1–A12**, and the classes after it cover the two
genuinely new controls (the callback's session-must-match-flow-user check and the
fresh full re-auth gate), the unlink stranding guard, and the stale-link
detection that keeps an IdP-side subject change from re-creating the very
duplicate-account bug linking exists to remove.

The provider is mocked exactly as in ``test_oidc.py`` — discovery, code exchange,
and ID-token verification are stubbed, so what is exercised here is Scrye's
binding logic, not Authlib's crypto (that has its own suite).
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pyotp
import pytest
from fastapi.testclient import TestClient

import app.api.oidc as oidc_api
import app.auth.oidc as oidc_module
from app.auth.oidc import OidcMetadata
from tests.test_auth import ADMIN_PW, CSRF, USER_PW, setup_admin

ISSUER = "https://idp.test"
CLIENT_SECRET = "oidc-client-secret-value"
LINKED_SUBJECT = "subject-of-the-admin"

_METADATA = OidcMetadata(
    issuer=ISSUER,
    authorization_endpoint=f"{ISSUER}/authorize",
    token_endpoint=f"{ISSUER}/token",
    jwks_uri=f"{ISSUER}/jwks",
)


def _enable_oidc(client: TestClient, csrf: str, **overrides: object) -> None:
    """Configure and enable OIDC against the mock provider."""
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


def _patch_provider(monkeypatch: pytest.MonkeyPatch, claims: dict) -> dict:
    """Stub discovery/exchange/verification; return a dict recording what was seen.

    The recorder lets a test assert on values the handler passed *into*
    verification (notably the per-flow ``nonce``), which is how the flow-binding
    half of A5 is checked without a real IdP.
    """
    seen: dict = {}

    async def fake_discover(issuer: str) -> OidcMetadata:
        return _METADATA

    async def fake_exchange(metadata: OidcMetadata, **kwargs: object) -> dict:
        seen["exchange"] = kwargs
        return {"id_token": "stub.jwt.token", "access_token": "stub-access-token"}

    async def fake_verify(
        metadata: OidcMetadata, id_token: str, *, client_id: str, nonce: str
    ) -> dict:
        seen["nonce"] = nonce
        seen["client_id"] = client_id
        return claims

    monkeypatch.setattr(oidc_module, "discover", fake_discover)
    monkeypatch.setattr(oidc_module, "exchange_code", fake_exchange)
    monkeypatch.setattr(oidc_module, "verify_id_token", fake_verify)
    return seen


def _start_link(
    client: TestClient,
    csrf: str,
    *,
    password: str = ADMIN_PW,
    totp_code: str | None = None,
    **extra: object,
) -> object:
    """POST the link start with fresh credentials; return the raw response."""
    body: dict = {"current_password": password, **extra}
    if totp_code is not None:
        body["totp_code"] = totp_code
    return client.post("/api/auth/oidc/link", json=body, headers={CSRF: csrf})


def _state_from(resp: object) -> str:
    """Pull the ``state`` out of a link start's authorization URL."""
    url = resp.json()["authorization_url"]  # type: ignore[attr-defined]
    return parse_qs(urlparse(url).query)["state"][0]


def _complete(client: TestClient, state: str, **params: str) -> object:
    """Drive the callback for ``state`` in ``client``'s browser."""
    return client.get(
        "/api/auth/oidc/callback",
        params={"state": state, "code": "authcode", **params},
        follow_redirects=False,
    )


def _link(client: TestClient, csrf: str, monkeypatch: pytest.MonkeyPatch, claims: dict) -> object:
    """Run a full successful link round trip and return the callback response."""
    _patch_provider(monkeypatch, claims)
    start = _start_link(client, csrf)
    assert start.status_code == 200, start.text  # type: ignore[attr-defined]
    return _complete(client, _state_from(start))


def _link_status(client: TestClient) -> dict:
    """Return the caller's own link status."""
    resp = client.get("/api/auth/oidc/link")
    assert resp.status_code == 200, resp.text
    return resp.json()


def _audit_actions(client: TestClient) -> list[str]:
    """Return the audit actions recorded so far (newest first)."""
    return [e["action"] for e in client.get("/api/audit").json()["items"]]


def _audit_entry(client: TestClient, action: str) -> dict:
    """Return the most recent audit entry for ``action``."""
    entries = [e for e in client.get("/api/audit").json()["items"] if e["action"] == action]
    assert entries, f"no {action} audit entry"
    return entries[0]


@pytest.fixture
def admin(client: TestClient) -> str:
    """Bootstrap an admin with OIDC enabled; return the CSRF token."""
    csrf = setup_admin(client)
    _enable_oidc(client, csrf)
    return csrf


class TestAbuseCases:
    """One regression test per abuse case A1–A12 from the feature's scoping."""

    def test_a1_unauthenticated_caller_cannot_start_a_link(
        self, client: TestClient, admin: str
    ) -> None:
        """A1: a link flow can never exist without a session-derived ``user_id``."""
        anon = TestClient(client.app)
        resp = anon.post("/api/auth/oidc/link", json={"current_password": ADMIN_PW})
        assert resp.status_code == 401
        # And nothing was created that a later callback could complete.
        assert (
            anon.get(
                "/api/auth/oidc/callback",
                params={"state": "x", "code": "y"},
                follow_redirects=False,
            )
            .headers["location"]
            .endswith("oidc_error=expired")
        )

    def test_a2_callback_without_a_session_fails_closed(
        self, client: TestClient, admin: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A2: the link callback requires a live session, not just the state+cookie."""
        _patch_provider(monkeypatch, {"sub": LINKED_SUBJECT, "iss": ISSUER})
        start = _start_link(client, admin)
        state = _state_from(start)
        # Drop only the session cookie; the binding cookie stays, so this is
        # precisely "right browser, no longer authenticated".
        client.cookies.delete("scrye_session")
        resp = _complete(client, state)
        assert resp.status_code == 302
        assert "oidc_link_error=session_mismatch" in resp.headers["location"]

    def test_a2_callback_under_a_different_user_fails_closed(
        self, client: TestClient, admin: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A2: session.user_id must equal flow.user_id, not merely be *a* session."""
        # A second account, logged in inside the same browser after the flow started.
        created = client.post(
            "/api/users",
            json={"username": "other", "password": USER_PW, "role": "admin"},
            headers={CSRF: admin},
        )
        assert created.status_code == 201, created.text
        _patch_provider(monkeypatch, {"sub": LINKED_SUBJECT, "iss": ISSUER})
        start = _start_link(client, admin)
        state = _state_from(start)

        # Swap the session for the other user's, keeping the binding cookie.
        login = client.post("/api/auth/login", json={"username": "other", "password": USER_PW})
        assert login.status_code == 200, login.text
        resp = _complete(client, state)
        assert "oidc_link_error=session_mismatch" in resp.headers["location"]
        # No identity was created for anyone.
        assert _link_status(client)["linked"] is False
        assert "auth.oidc_link_denied" in _audit_actions(client)

    def test_a3_link_start_requires_the_csrf_token(self, client: TestClient, admin: str) -> None:
        """A3: the start is a POST behind require_csrf — a cross-site page cannot begin one."""
        resp = client.post("/api/auth/oidc/link", json={"current_password": ADMIN_PW})
        assert resp.status_code == 403
        assert "CSRF" in resp.json()["detail"]

    def test_a4_flow_cannot_be_completed_in_another_browser(
        self, client: TestClient, admin: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A4: the browser-binding cookie confines a flow to the browser that began it."""
        _patch_provider(monkeypatch, {"sub": LINKED_SUBJECT, "iss": ISSUER})
        state = _state_from(_start_link(client, admin))

        other_browser = TestClient(client.app)
        other_browser.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PW})
        resp = _complete(other_browser, state)
        assert "oidc_link_error=expired" in resp.headers["location"]
        assert _link_status(client)["linked"] is False

    def test_a4_state_is_one_time_use(
        self, client: TestClient, admin: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A4: the flow row is consumed on first use, so a captured state cannot replay."""
        _patch_provider(monkeypatch, {"sub": LINKED_SUBJECT, "iss": ISSUER})
        state = _state_from(_start_link(client, admin))
        first = _complete(client, state)
        assert "oidc_link=success" in first.headers["location"]
        replay = _complete(client, state)
        assert "oidc_error=expired" in replay.headers["location"]

    def test_a5_attacker_started_flow_can_only_bind_to_the_attacker(
        self, client: TestClient, admin: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A5: a flow binds to *its own* starter, and carries a per-flow nonce.

        The inverted-login-CSRF shape — get the victim to complete a flow the
        attacker started — is blocked three times over: the browser binding (A4)
        stops the victim's browser completing it at all; that failed attempt
        *burns* the one-time flow row, so the attacker cannot then finish it
        either; and even a flow the attacker completes in their own browser
        carries the attacker's ``user_id``, so it binds to the attacker's own
        account and never the victim's.
        """
        created = client.post(
            "/api/users",
            json={"username": "victim", "password": USER_PW, "role": "admin"},
            headers={CSRF: admin},
        )
        assert created.status_code == 201, created.text

        attacker = TestClient(client.app)
        attacker_csrf = attacker.post(
            "/api/auth/login", json={"username": "admin", "password": ADMIN_PW}
        ).json()["csrf_token"]
        seen = _patch_provider(monkeypatch, {"sub": LINKED_SUBJECT, "iss": ISSUER})
        start = _start_link(attacker, attacker_csrf)
        state = _state_from(start)

        victim = TestClient(client.app)
        victim.post("/api/auth/login", json={"username": "victim", "password": USER_PW})
        # The victim's browser has no binding cookie for this flow.
        assert "oidc_link_error=expired" in _complete(victim, state).headers["location"]
        assert _link_status(victim)["linked"] is False
        # That attempt consumed the one-time row, so even the attacker cannot
        # now finish the flow they lured the victim into.
        assert "oidc_error=expired" in _complete(attacker, state).headers["location"]

        # Completed end-to-end by its own starter, the identity lands on the
        # attacker's account — never on the account they were aiming at.
        second = _state_from(_start_link(attacker, attacker_csrf))
        assert "oidc_link=success" in _complete(attacker, second).headers["location"]
        assert _link_status(attacker)["linked"] is True
        assert _link_status(victim)["linked"] is False
        # The ID token was checked against this flow's server-side nonce.
        assert seen["nonce"] and len(seen["nonce"]) >= 32

    def test_a6_no_caller_supplied_subject_anywhere(
        self, client: TestClient, admin: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A6: the subject comes only from the verified token — never from input.

        Three assertions, because "there is no field" is the invariant: a subject
        smuggled into the start payload is ignored outright, the bound subject is
        the token's, and neither the request schema nor the status view has any
        subject-shaped field to fill in.
        """
        _patch_provider(monkeypatch, {"sub": LINKED_SUBJECT, "iss": ISSUER})
        start = _start_link(
            client, admin, subject="attacker-chosen-subject", sub="attacker-chosen-subject"
        )
        assert start.status_code == 200, start.text
        assert "oidc_link=success" in _complete(client, _state_from(start)).headers["location"]

        from app.db.models import OidcIdentity
        from app.db.session import SessionLocal

        with SessionLocal() as session:
            identities = session.query(OidcIdentity).all()
            assert [i.subject for i in identities] == [LINKED_SUBJECT]

        # No subject field is exposed on the way in or the way out.
        schema = client.app.openapi()["components"]["schemas"]
        for model in ("OidcLinkStartIn", "OidcUnlinkIn", "OidcLinkStatusOut"):
            fields = set(schema[model].get("properties", {}))
            assert not {"sub", "subject"} & fields, f"{model} exposes a subject field"
        assert "subject" not in _link_status(client)

    def test_a7_identity_in_use_is_never_repointed(
        self, client: TestClient, admin: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A7: an ``(issuer, subject)`` bound to one account cannot be claimed by another."""
        assert (
            "oidc_link=success"
            in _link(client, admin, monkeypatch, {"sub": LINKED_SUBJECT, "iss": ISSUER}).headers[
                "location"
            ]
        )

        created = client.post(
            "/api/users",
            json={"username": "second", "password": USER_PW, "role": "admin"},
            headers={CSRF: admin},
        )
        assert created.status_code == 201, created.text
        second = TestClient(client.app)
        second_csrf = second.post(
            "/api/auth/login", json={"username": "second", "password": USER_PW}
        ).json()["csrf_token"]

        _patch_provider(monkeypatch, {"sub": LINKED_SUBJECT, "iss": ISSUER})
        start = _start_link(second, second_csrf, password=USER_PW)
        resp = _complete(second, _state_from(start))
        assert "oidc_link_error=identity_in_use" in resp.headers["location"]
        assert _link_status(second)["linked"] is False
        assert _link_status(client)["linked"] is True  # the original binding is intact

    def test_a7_relinking_your_own_identity_is_a_noop_success(
        self, client: TestClient, admin: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A7: re-linking the identity you already hold succeeds without a second row."""
        claims = {"sub": LINKED_SUBJECT, "iss": ISSUER}
        _link(client, admin, monkeypatch, claims)
        again = _link(client, admin, monkeypatch, claims)
        assert "oidc_link=unchanged" in again.headers["location"]

        from app.db.models import OidcIdentity
        from app.db.session import SessionLocal

        with SessionLocal() as session:
            assert session.query(OidcIdentity).count() == 1

    def test_a7_a_second_subject_for_the_same_issuer_is_refused(
        self, client: TestClient, admin: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A7: linking is insert-only — a new subject does not silently replace the old."""
        _link(client, admin, monkeypatch, {"sub": LINKED_SUBJECT, "iss": ISSUER})
        resp = _link(client, admin, monkeypatch, {"sub": "a-different-subject", "iss": ISSUER})
        assert "oidc_link_error=issuer_already_linked" in resp.headers["location"]

        from app.db.models import OidcIdentity
        from app.db.session import SessionLocal

        with SessionLocal() as session:
            assert [i.subject for i in session.query(OidcIdentity).all()] == [LINKED_SUBJECT]

    def test_a8_link_assigns_no_role_and_creates_no_session(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A8: the link path grants nothing — no role sync, no session, no provisioning."""
        csrf = setup_admin(client)
        _enable_oidc(client, csrf, groups_claim="groups", admin_group="scrye-admins")
        created = client.post(
            "/api/users",
            json={"username": "viewer1", "password": USER_PW, "role": "viewer"},
            headers={CSRF: csrf},
        )
        assert created.status_code == 201, created.text

        viewer = TestClient(client.app)
        viewer_csrf = viewer.post(
            "/api/auth/login", json={"username": "viewer1", "password": USER_PW}
        ).json()["csrf_token"]
        session_before = viewer.cookies.get("scrye_session")

        # An ID token that WOULD map to admin on the login path.
        _patch_provider(
            monkeypatch,
            {"sub": "viewer-sub", "iss": ISSUER, "groups": ["scrye-admins"]},
        )
        start = _start_link(viewer, viewer_csrf, password=USER_PW)
        resp = _complete(viewer, _state_from(start))

        assert "oidc_link=success" in resp.headers["location"]
        assert viewer.get("/api/auth/me").json()["role"] == "viewer"  # no escalation
        # No new session was minted: the callback set no session cookie.
        assert "scrye_session" not in resp.headers.get("set-cookie", "")
        assert viewer.cookies.get("scrye_session") == session_before
        assert "auth.oidc_login" not in _audit_actions(client)
        assert "auth.oidc_provisioned" not in _audit_actions(client)
        # Exactly one user was touched: no duplicate account appeared.
        assert len(client.get("/api/users").json()["items"]) == 2

    def test_a9_no_open_redirect_on_the_link_result(
        self, client: TestClient, admin: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A9: the post-link destination is a fixed app path; nothing steers it."""
        _patch_provider(monkeypatch, {"sub": LINKED_SUBJECT, "iss": ISSUER})
        state = _state_from(_start_link(client, admin))
        resp = _complete(
            client, state, return_to="https://evil.test", next="https://evil.test", redirect_uri="x"
        )
        assert resp.headers["location"] == "/settings?oidc_link=success"

    def test_a9_redirect_uri_is_derived_server_side(
        self, client: TestClient, admin: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A9: the token exchange replays the server-derived redirect URI."""
        seen = _patch_provider(monkeypatch, {"sub": LINKED_SUBJECT, "iss": ISSUER})
        state = _state_from(_start_link(client, admin))
        _complete(client, state)
        assert seen["exchange"]["redirect_uri"].endswith("/api/auth/oidc/callback")
        assert "evil" not in seen["exchange"]["redirect_uri"]

    def test_a10_link_start_joins_the_auth_rate_limiter(
        self, client: TestClient, admin: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A10: flow-row creation is bounded by the shared per-IP auth limiter."""
        _patch_provider(monkeypatch, {"sub": LINKED_SUBJECT, "iss": ISSUER})
        statuses = {
            _start_link(client, admin, password="wrong-password").status_code for _ in range(40)
        }
        assert 429 in statuses, "link start is not rate limited"

    def test_a11_insecure_transport_is_refused_up_front(
        self, client: TestClient, admin: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A11: the flow needs Secure cookies, so plain HTTP is refused before it starts."""
        monkeypatch.setattr(oidc_api, "session_cookie_would_be_dropped", lambda request: True)
        resp = _start_link(client, admin)
        assert resp.status_code == 503
        assert "HTTPS" in resp.json()["detail"]

    def test_a12_no_token_or_secret_material_leaks(
        self, client: TestClient, admin: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A12: no new secrets — nothing token-shaped is returned, stored, or audited."""
        _patch_provider(monkeypatch, {"sub": LINKED_SUBJECT, "iss": ISSUER})
        start = _start_link(client, admin)
        assert CLIENT_SECRET not in start.text
        assert ADMIN_PW not in start.text
        resp = _complete(client, _state_from(start))
        assert CLIENT_SECRET not in str(resp.headers)

        status_text = client.get("/api/auth/oidc/link").text
        for secret in (CLIENT_SECRET, ADMIN_PW, "stub.jwt.token", "stub-access-token"):
            assert secret not in status_text
        # The audit trail carries metadata only — not the opaque subject value.
        entry = _audit_entry(client, "auth.oidc_identity_linked")
        assert entry["details"] == {"issuer": ISSUER}
        assert LINKED_SUBJECT not in client.get("/api/audit").text


class TestFreshReauthGate:
    """The SEC-8 compensating control: a session alone can never create a login path."""

    def test_link_requires_the_current_password(self, client: TestClient, admin: str) -> None:
        resp = _start_link(client, admin, password="not-the-password")
        assert resp.status_code == 403
        assert "password" in resp.json()["detail"].lower()

    def test_link_rejects_a_missing_password(self, client: TestClient, admin: str) -> None:
        resp = client.post("/api/auth/oidc/link", json={}, headers={CSRF: admin})
        assert resp.status_code == 422

    def test_link_requires_a_totp_code_when_enrolled(self, client: TestClient, admin: str) -> None:
        """An MFA-enrolled account must present the second factor to link, too.

        This is what keeps the widening bounded: the account that gains an
        MFA-skipping login path is exactly the one that had to prove its second
        factor to create it.
        """
        from tests.test_mfa import _enroll_and_activate

        _enroll_and_activate(client, admin)
        assert _start_link(client, admin).status_code == 403
        assert _start_link(client, admin, totp_code="000000").status_code == 403

    def test_link_succeeds_with_password_and_current_totp(
        self, client: TestClient, admin: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from tests.test_mfa import _enroll_and_activate

        secret = _enroll_and_activate(client, admin)
        _patch_provider(monkeypatch, {"sub": LINKED_SUBJECT, "iss": ISSUER})
        resp = _start_link(client, admin, totp_code=pyotp.TOTP(secret).now())
        assert resp.status_code == 200, resp.text
        assert "oidc_link=success" in _complete(client, _state_from(resp)).headers["location"]

    def test_failed_reauth_is_audited_and_creates_no_flow(
        self, client: TestClient, admin: str
    ) -> None:
        _start_link(client, admin, password="not-the-password")
        assert "auth.reauth_failed" in _audit_actions(client)

        from app.db.models import OidcLoginFlow
        from app.db.session import SessionLocal

        with SessionLocal() as session:
            assert session.query(OidcLoginFlow).count() == 0

    def test_api_tokens_cannot_reach_the_link_surface(self, client: TestClient, admin: str) -> None:
        """Bearer auth is CSRF-exempt and cannot finish the browser round trip."""
        minted = client.post(
            "/api/api-tokens", json={"name": "ci", "role": "admin"}, headers={CSRF: admin}
        )
        assert minted.status_code == 201, minted.text
        token = minted.json()["token"]
        bearer = TestClient(client.app)
        resp = bearer.post(
            "/api/auth/oidc/link",
            json={"current_password": ADMIN_PW},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403
        assert "browser session" in resp.json()["detail"]

    def test_link_warns_when_mfa_would_be_delegated(self, client: TestClient, admin: str) -> None:
        """The UI is told to warn before the user creates the MFA-skipping path."""
        assert _link_status(client)["mfa_delegation_warning"] is False
        from tests.test_mfa import _enroll_and_activate

        _enroll_and_activate(client, admin)
        after = _link_status(client)
        assert after["mfa_enrolled"] is True
        assert after["mfa_delegation_warning"] is True

    def test_mandatory_policy_alone_triggers_the_warning(
        self, client: TestClient, admin: str
    ) -> None:
        resp = client.put(
            "/api/settings/authentication",
            json={"local_login_enabled": True, "mfa_policy": "required_admin"},
            headers={CSRF: admin},
        )
        assert resp.status_code == 200, resp.text
        assert _link_status(client)["mfa_delegation_warning"] is True


class TestUnlink:
    """Self-unlink: same gates as linking, plus the stranding guard."""

    def test_unlink_removes_the_identity_and_audits_it(
        self, client: TestClient, admin: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _link(client, admin, monkeypatch, {"sub": LINKED_SUBJECT, "iss": ISSUER})
        resp = client.request(
            "DELETE",
            "/api/auth/oidc/link",
            json={"current_password": ADMIN_PW},
            headers={CSRF: admin},
        )
        assert resp.status_code == 204, resp.text
        assert _link_status(client)["linked"] is False
        assert "auth.oidc_identity_unlinked" in _audit_actions(client)

    def test_unlink_requires_fresh_credentials(
        self, client: TestClient, admin: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _link(client, admin, monkeypatch, {"sub": LINKED_SUBJECT, "iss": ISSUER})
        resp = client.request(
            "DELETE",
            "/api/auth/oidc/link",
            json={"current_password": "not-the-password"},
            headers={CSRF: admin},
        )
        assert resp.status_code == 403
        assert _link_status(client)["linked"] is True

    def test_unlink_requires_csrf(
        self, client: TestClient, admin: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _link(client, admin, monkeypatch, {"sub": LINKED_SUBJECT, "iss": ISSUER})
        resp = client.request("DELETE", "/api/auth/oidc/link", json={"current_password": ADMIN_PW})
        assert resp.status_code == 403
        assert _link_status(client)["linked"] is True

    def test_unlink_without_a_link_is_a_404(self, client: TestClient, admin: str) -> None:
        resp = client.request(
            "DELETE",
            "/api/auth/oidc/link",
            json={"current_password": ADMIN_PW},
            headers={CSRF: admin},
        )
        assert resp.status_code == 404

    def test_unlink_refused_when_local_login_is_disabled(
        self, client: TestClient, admin: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Stranding guard: with local login off, the link is the only way in."""
        _link(client, admin, monkeypatch, {"sub": LINKED_SUBJECT, "iss": ISSUER})
        resp = client.put(
            "/api/settings/authentication",
            json={"local_login_enabled": False, "mfa_policy": "optional"},
            headers={CSRF: admin},
        )
        assert resp.status_code == 200, resp.text

        unlink = client.request(
            "DELETE",
            "/api/auth/oidc/link",
            json={"current_password": ADMIN_PW},
            headers={CSRF: admin},
        )
        assert unlink.status_code == 409
        assert "no way to sign in" in unlink.json()["detail"]
        assert _link_status(client)["linked"] is True

    def test_provisioned_account_cannot_unlink_itself_into_lockout(
        self, client: TestClient, admin: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An OIDC-provisioned account holds no usable password, so the gate refuses it.

        That is the stranding guard for the no-local-password case: the account
        cannot satisfy the fresh-password re-auth, so it can never remove the one
        identity it signs in with.
        """
        _patch_provider(
            monkeypatch, {"sub": "provisioned-sub", "iss": ISSUER, "preferred_username": "prov"}
        )
        browser = TestClient(client.app)
        start = browser.get("/api/auth/oidc/login", follow_redirects=False)
        state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
        assert _complete(browser, state).status_code == 302
        assert browser.get("/api/auth/me").json()["username"] == "prov"

        csrf = browser.cookies.get("scrye_csrf")
        for attempt in ("", "guessed-password", ADMIN_PW):
            resp = browser.request(
                "DELETE",
                "/api/auth/oidc/link",
                json={"current_password": attempt or "x"},
                headers={CSRF: csrf},
            )
            assert resp.status_code == 403, resp.text
        assert _link_status(browser)["linked"] is True


class TestStaleLinkDetection:
    """§7: an IdP-side subject change must announce itself, not resurface as the old bug."""

    def _login(self, app: object, monkeypatch: pytest.MonkeyPatch, claims: dict) -> object:
        """Run one full OIDC *login* in a fresh browser; return the callback response."""
        _patch_provider(monkeypatch, claims)
        browser = TestClient(app)  # type: ignore[arg-type]
        start = browser.get("/api/auth/oidc/login", follow_redirects=False)
        state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
        return browser.get(
            "/api/auth/oidc/callback",
            params={"state": state, "code": "authcode"},
            follow_redirects=False,
        )

    def test_new_subject_matching_a_linked_username_fails_closed(
        self, client: TestClient, admin: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The recreated-IdP-account case: same human, new subject, no duplicate account."""
        _link(client, admin, monkeypatch, {"sub": LINKED_SUBJECT, "iss": ISSUER})
        resp = self._login(
            client.app,
            monkeypatch,
            {"sub": "brand-new-subject", "iss": ISSUER, "preferred_username": "admin"},
        )
        assert "oidc_error=identity_stale" in resp.headers["location"]
        # Auto-provision is ON, and yet no duplicate account was minted.
        assert [u["username"] for u in client.get("/api/users").json()["items"]] == ["admin"]

    def test_stale_detection_matches_on_the_email_claim_too(
        self, client: TestClient, admin: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The Authentik mass-re-key case, where the username claim may also change."""
        _link(
            client,
            admin,
            monkeypatch,
            {"sub": LINKED_SUBJECT, "iss": ISSUER, "email": "boss@test"},
        )
        resp = self._login(
            client.app,
            monkeypatch,
            {
                "sub": "rekeyed-subject",
                "iss": ISSUER,
                "preferred_username": "someone-else",
                "email": "boss@test",
            },
        )
        assert "oidc_error=identity_stale" in resp.headers["location"]

    def test_stale_detection_never_rebinds(
        self, client: TestClient, admin: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Refuse-and-explain only: the claim match must not write or move a link."""
        _link(client, admin, monkeypatch, {"sub": LINKED_SUBJECT, "iss": ISSUER})
        self._login(
            client.app,
            monkeypatch,
            {"sub": "brand-new-subject", "iss": ISSUER, "preferred_username": "admin"},
        )

        from app.db.models import OidcIdentity
        from app.db.session import SessionLocal

        with SessionLocal() as session:
            rows = session.query(OidcIdentity).all()
            assert [r.subject for r in rows] == [LINKED_SUBJECT]

    def test_stale_detection_is_audited_without_raw_subjects(
        self, client: TestClient, admin: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _link(client, admin, monkeypatch, {"sub": LINKED_SUBJECT, "iss": ISSUER})
        self._login(
            client.app,
            monkeypatch,
            {"sub": "brand-new-subject", "iss": ISSUER, "preferred_username": "admin"},
        )
        entry = _audit_entry(client, "auth.oidc_identity_stale")
        assert entry["details"]["matched_by"] == "username"
        assert entry["details"]["issuer"] == ISSUER
        assert entry["details"]["linked_identity_id"]
        assert "brand-new-subject" not in client.get("/api/audit").text
        assert LINKED_SUBJECT not in client.get("/api/audit").text

    def test_unrelated_identity_still_provisions_normally(
        self, client: TestClient, admin: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No false positives: a genuinely new person is not mistaken for a stale link."""
        _link(client, admin, monkeypatch, {"sub": LINKED_SUBJECT, "iss": ISSUER})
        resp = self._login(
            client.app,
            monkeypatch,
            {
                "sub": "someone-new",
                "iss": ISSUER,
                "preferred_username": "newcomer",
                "email": "new@test",
            },
        )
        assert resp.headers["location"] == "/"
        usernames = {u["username"] for u in client.get("/api/users").json()["items"]}
        assert usernames == {"admin", "newcomer"}

    def test_relink_runbook_restores_sign_in(
        self, client: TestClient, admin: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The documented recovery — sign in locally, unlink, re-link — actually works."""
        _link(client, admin, monkeypatch, {"sub": LINKED_SUBJECT, "iss": ISSUER})
        assert (
            "oidc_error=identity_stale"
            in self._login(
                client.app,
                monkeypatch,
                {"sub": "rekeyed", "iss": ISSUER, "preferred_username": "admin"},
            ).headers["location"]
        )

        unlink = client.request(
            "DELETE",
            "/api/auth/oidc/link",
            json={"current_password": ADMIN_PW},
            headers={CSRF: admin},
        )
        assert unlink.status_code == 204, unlink.text
        _link(client, admin, monkeypatch, {"sub": "rekeyed", "iss": ISSUER})

        resp = self._login(
            client.app,
            monkeypatch,
            {"sub": "rekeyed", "iss": ISSUER, "preferred_username": "admin"},
        )
        assert resp.headers["location"] == "/"
        assert [u["username"] for u in client.get("/api/users").json()["items"]] == ["admin"]


class TestLinkStatus:
    """The read view backing the Settings card."""

    def test_status_reports_unlinked_before_any_link(self, client: TestClient, admin: str) -> None:
        body = _link_status(client)
        assert body == {
            "linked": False,
            "issuer": None,
            "email": None,
            "linked_at": None,
            "last_login_at": None,
            "provider_ready": True,
            "display_name": "OIDC",
            "mfa_enrolled": False,
            "mfa_delegation_warning": False,
        }

    def test_status_reports_last_use_after_an_oidc_login(
        self, client: TestClient, admin: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``last_login_at`` is the one honest hint that a link may have gone stale."""
        _link(client, admin, monkeypatch, {"sub": LINKED_SUBJECT, "iss": ISSUER})
        assert _link_status(client)["last_login_at"] is None

        _patch_provider(monkeypatch, {"sub": LINKED_SUBJECT, "iss": ISSUER})
        browser = TestClient(client.app)
        start = browser.get("/api/auth/oidc/login", follow_redirects=False)
        state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
        assert _complete(browser, state).headers["location"] == "/"
        assert _link_status(client)["last_login_at"] is not None

    def test_status_reports_provider_not_ready_when_oidc_is_off(self, client: TestClient) -> None:
        setup_admin(client)
        assert _link_status(client)["provider_ready"] is False

    def test_link_start_refused_when_oidc_is_not_configured(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        resp = _start_link(client, csrf)
        assert resp.status_code == 400
        assert "not enabled" in resp.json()["detail"]

    def test_status_requires_authentication(self, client: TestClient, admin: str) -> None:
        anon = TestClient(client.app)
        assert anon.get("/api/auth/oidc/link").status_code == 401
