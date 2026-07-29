"""Tests for HTTPS enforcement on sign-in and trusted-proxy scheme resolution.

Covers the three deployment shapes a Scrye operator can be in, because the
failure this guards against is invisible without them: with ``Secure`` cookies
and a plain-HTTP origin, the browser silently discards the session cookie, the
login *looks* successful, and every request after it 401s with nothing in the
logs to explain it.

1. **Direct HTTPS** — cookies are set with ``Secure`` and the login completes.
2. **Behind a TLS-terminating reverse proxy** — the app sees HTTP, the proxy
   sends ``X-Forwarded-Proto: https``, and that is honoured *only* when the peer
   is listed in ``SCRYE_FORWARDED_ALLOW_IPS``.
3. **Plain HTTP** — the sign-in is refused with a distinct, transport-specific
   log and audit record, unless the operator opted out with
   ``SCRYE_SESSION_COOKIE_SECURE=false``, in which case cookies are set without
   ``Secure`` and login works.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.api.auth import AUDIT_BLOCKED_INSECURE
from app.core.config import Settings
from app.core.forwarded import ForwardedProtoMiddleware, parse_trusted_proxies
from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.main import create_app, log_https_enforcement

# Throwaway test-only credentials (ephemeral users in a temp database).
ADMIN_PW = "unit-test-admin-passphrase"

#: A stand-in reverse proxy address. TestClient's default peer is the
#: non-routable literal ``"testclient"``, which is never trusted, so any test
#: exercising a proxy must set the peer explicitly.
PROXY_IP = "10.9.8.7"
OTHER_IP = "192.0.2.10"


@dataclass
class FakeSettings:
    """Minimal stand-in for the settings the cookie helpers read."""

    session_cookie_secure: bool = True
    session_lifetime_hours: int = 168


@pytest.fixture
def https_client_factory(monkeypatch: pytest.MonkeyPatch):
    """Build a TestClient with chosen cookie-Secure, base URL, proxy trust and peer."""

    def factory(
        *,
        secure_cookies: bool = True,
        base_url: str = "http://testserver",
        trusted: str = PROXY_IP,
        peer: str = "testclient",
        reset: bool = True,
    ) -> Iterator[TestClient]:
        # The cookie helpers (and the auth endpoints through them) read the
        # cached global settings, so patch there rather than rebuilding the cache.
        monkeypatch.setattr(
            "app.auth.cookies.get_settings",
            lambda: FakeSettings(session_cookie_secure=secure_cookies),
        )
        if reset:
            # Several tests bootstrap over one transport and then reconnect over
            # another; the second client must keep the first one's database.
            Base.metadata.drop_all(engine)
            Base.metadata.create_all(engine)
        app = create_app(Settings(forwarded_allow_ips=trusted))
        return TestClient(app, base_url=base_url, client=(peer, 43210))

    return factory


def _set_cookie_header(response: Any) -> str:
    """Join every ``Set-Cookie`` header on a response into one searchable string."""
    return "\n".join(v for k, v in response.headers.multi_items() if k.lower() == "set-cookie")


def _setup_admin(client: TestClient) -> Any:
    """Bootstrap the first admin over this client's transport."""
    return client.post("/api/auth/setup", json={"username": "admin", "password": ADMIN_PW})


class TestShape1DirectHttps:
    """Deployment shape 1: TLS terminated by Scrye's own listener."""

    def test_cookies_are_secure_and_login_completes(self, https_client_factory) -> None:
        with https_client_factory(base_url="https://testserver") as client:
            resp = _setup_admin(client)
            assert resp.status_code == 201, resp.text
            cookies = _set_cookie_header(resp)
            assert "scrye_session" in cookies
            assert cookies.count("Secure") == 2  # session + CSRF cookie
            assert "HttpOnly" in cookies
            # The session actually works on the next request.
            assert client.get("/api/auth/me").json()["username"] == "admin"

    def test_status_reports_a_secure_transport(self, https_client_factory) -> None:
        with https_client_factory(base_url="https://testserver") as client:
            body = client.get("/api/auth/status").json()
            assert body["https_enforced"] is True
            assert body["transport_secure"] is True


class TestShape2BehindTlsTerminatingProxy:
    """Deployment shape 2: the app sees HTTP; the client is on HTTPS."""

    def test_forwarded_proto_from_a_trusted_proxy_allows_login(self, https_client_factory) -> None:
        with https_client_factory(trusted=PROXY_IP, peer=PROXY_IP) as client:
            resp = client.post(
                "/api/auth/setup",
                json={"username": "admin", "password": ADMIN_PW},
                headers={"X-Forwarded-Proto": "https"},
            )
            assert resp.status_code == 201, resp.text
            # Secure stays on: the client is on HTTPS even though we saw HTTP.
            assert _set_cookie_header(resp).count("Secure") == 2

    def test_forwarded_proto_from_an_untrusted_peer_is_ignored(self, https_client_factory) -> None:
        """A client that merely claims HTTPS gets no say — the refusal still fires."""
        with https_client_factory(trusted=PROXY_IP, peer=OTHER_IP) as client:
            resp = client.post(
                "/api/auth/setup",
                json={"username": "admin", "password": ADMIN_PW},
                headers={"X-Forwarded-Proto": "https"},
            )
            assert resp.status_code == 503, resp.text
            assert "plain HTTP" in resp.json()["detail"]

    def test_cidr_trust_matches_a_proxy_inside_the_range(self, https_client_factory) -> None:
        with https_client_factory(trusted="10.9.0.0/16", peer=PROXY_IP) as client:
            resp = client.get("/api/auth/status", headers={"X-Forwarded-Proto": "https"})
            assert resp.json()["transport_secure"] is True

    def test_status_reports_the_forwarded_scheme(self, https_client_factory) -> None:
        with https_client_factory(trusted=PROXY_IP, peer=PROXY_IP) as client:
            secure = client.get("/api/auth/status", headers={"X-Forwarded-Proto": "https"}).json()
            assert secure["transport_secure"] is True
            plain = client.get("/api/auth/status").json()
            assert plain["transport_secure"] is False


class TestShape3PlainHttp:
    """Deployment shape 3: plain HTTP, with and without the operator opt-out."""

    def test_setup_is_refused_and_creates_no_account(self, https_client_factory) -> None:
        """Refusing *before* creating the admin keeps bootstrap re-runnable."""
        with https_client_factory() as client:
            resp = _setup_admin(client)
            assert resp.status_code == 503
            assert "scrye_session" not in _set_cookie_header(resp)
            # Bootstrap is still available: no half-provisioned deployment.
            assert client.get("/api/auth/status").json()["needs_setup"] is True

    def test_login_with_valid_credentials_is_refused(self, https_client_factory) -> None:
        # Bootstrap over HTTPS, then come back over plain HTTP.
        with https_client_factory(base_url="https://testserver") as client:
            assert _setup_admin(client).status_code == 201

        with https_client_factory(reset=False) as client:
            resp = client.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PW})
            assert resp.status_code == 503
            assert resp.status_code != 401  # never a bad-password rejection
            assert "scrye_session" not in _set_cookie_header(resp)

    def test_refusal_is_identical_for_valid_and_invalid_credentials(
        self, https_client_factory
    ) -> None:
        """The client-visible refusal must not distinguish good from bad credentials."""
        with https_client_factory(base_url="https://testserver") as client:
            assert _setup_admin(client).status_code == 201

        with https_client_factory(reset=False) as client:
            good = client.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PW})
            bad = client.post(
                "/api/auth/login", json={"username": "admin", "password": "wrong-passphrase-x"}
            )
            nobody = client.post(
                "/api/auth/login", json={"username": "ghost", "password": "wrong-passphrase-x"}
            )
        assert good.status_code == bad.status_code == nobody.status_code == 503
        assert good.json() == bad.json() == nobody.json()

    def test_opting_out_sets_cookies_without_secure_and_logs_in(self, https_client_factory) -> None:
        with https_client_factory(secure_cookies=False) as client:
            resp = _setup_admin(client)
            assert resp.status_code == 201, resp.text
            cookies = _set_cookie_header(resp)
            assert "scrye_session" in cookies
            assert "Secure" not in cookies
            assert "HttpOnly" in cookies  # the other protections are unchanged
            assert client.get("/api/auth/me").json()["username"] == "admin"

    def test_opting_out_reports_enforcement_off_in_status(self, https_client_factory) -> None:
        with https_client_factory(secure_cookies=False) as client:
            body = client.get("/api/auth/status").json()
            assert body["https_enforced"] is False
            assert body["transport_secure"] is False


class TestDistinctRejectionLogging:
    """The HTTPS refusal must never read as a bad-password 401 in the logs."""

    def test_valid_credentials_rejection_says_so_explicitly(
        self, https_client_factory, caplog: pytest.LogCaptureFixture
    ) -> None:
        with https_client_factory(base_url="https://testserver") as client:
            assert _setup_admin(client).status_code == 201

        caplog.clear()  # drop the bootstrap's own log lines
        with caplog.at_level(logging.INFO, logger="app.api.auth"):
            with https_client_factory(reset=False) as client:
                client.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PW})

        records = [r for r in caplog.records if r.name == "app.api.auth"]
        assert len(records) == 1
        message = records[0].getMessage()
        assert records[0].levelno == logging.ERROR
        assert "THE SUBMITTED CREDENTIALS WERE VALID" in message
        assert "NOT a bad-password rejection" in message
        # The remedy is named precisely: variable and value, plus the proxy route.
        assert "SCRYE_SESSION_COOKIE_SECURE=false" in message
        assert "X-Forwarded-Proto: https" in message
        assert "SCRYE_FORWARDED_ALLOW_IPS" in message
        assert ADMIN_PW not in message

    def test_invalid_credentials_rejection_is_a_separate_message(
        self, https_client_factory, caplog: pytest.LogCaptureFixture
    ) -> None:
        with https_client_factory(base_url="https://testserver") as client:
            assert _setup_admin(client).status_code == 201

        caplog.clear()  # drop the bootstrap's own log lines
        with caplog.at_level(logging.INFO, logger="app.api.auth"):
            with https_client_factory(reset=False) as client:
                client.post("/api/auth/login", json={"username": "admin", "password": "nope-nope"})

        message = next(r.getMessage() for r in caplog.records if r.name == "app.api.auth")
        assert "the submitted credentials were also rejected" in message
        assert "Correct credentials would be refused here too" in message
        assert "THE SUBMITTED CREDENTIALS WERE VALID" not in message

    def test_audit_records_a_distinct_action(self, https_client_factory) -> None:
        with https_client_factory(base_url="https://testserver") as client:
            assert _setup_admin(client).status_code == 201
        with https_client_factory(reset=False) as client:
            client.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PW})

        from app.db.models import AuditLog

        session = SessionLocal()
        try:
            actions = [row.action for row in session.query(AuditLog).all()]
            blocked = session.query(AuditLog).filter_by(action=AUDIT_BLOCKED_INSECURE).one()
        finally:
            session.close()
        assert AUDIT_BLOCKED_INSECURE in actions
        # A valid-credential refusal is never filed as a failed login.
        assert "auth.login_failed" not in actions
        assert blocked.details["credentials_valid"] is True
        assert blocked.details["scheme"] == "http"

    def test_bad_credentials_still_record_a_failed_login(self, https_client_factory) -> None:
        """Failed-login accounting is not lost just because the transport is wrong."""
        with https_client_factory(base_url="https://testserver") as client:
            assert _setup_admin(client).status_code == 201
        with https_client_factory(reset=False) as client:
            client.post("/api/auth/login", json={"username": "admin", "password": "nope-nope"})

        from app.db.models import AuditLog

        session = SessionLocal()
        try:
            actions = [row.action for row in session.query(AuditLog).all()]
        finally:
            session.close()
        assert "auth.login_failed" in actions
        assert AUDIT_BLOCKED_INSECURE in actions


class TestTrustedProxyParsing:
    """``SCRYE_FORWARDED_ALLOW_IPS`` parsing and its fail-safe behaviour."""

    def test_bare_addresses_and_cidrs_both_parse(self) -> None:
        trusted = parse_trusted_proxies("127.0.0.1, 172.16.0.0/12 ,::1")
        assert trusted.trusts("127.0.0.1")
        assert trusted.trusts("172.20.5.9")
        assert trusted.trusts("::1")
        assert not trusted.trusts("10.0.0.1")
        assert trusted.invalid == ()

    def test_unparseable_entries_are_collected_not_trusted(self) -> None:
        trusted = parse_trusted_proxies("proxy.internal, 10.0.0.1")
        assert trusted.invalid == ("proxy.internal",)
        assert trusted.trusts("10.0.0.1")
        assert not trusted.trusts("proxy.internal")

    def test_empty_configuration_trusts_nobody(self) -> None:
        trusted = parse_trusted_proxies("")
        assert trusted.is_configured is False
        assert not trusted.trusts("127.0.0.1")

    def test_wildcard_is_recognised_as_blanket_trust(self) -> None:
        trusted = parse_trusted_proxies("*")
        assert trusted.trust_all is True
        assert trusted.trusts("203.0.113.9")

    def test_non_ip_peers_are_never_trusted(self) -> None:
        trusted = parse_trusted_proxies("0.0.0.0/0")
        assert trusted.trusts("203.0.113.9")
        assert not trusted.trusts(None)
        assert not trusted.trusts("testclient")


class TestForwardedProtoMiddleware:
    """Scheme resolution is upgrade-only and gated on the peer."""

    @staticmethod
    async def _run(scope: dict[str, Any], trusted: str) -> dict[str, Any]:
        """Push ``scope`` through the middleware and return what the app saw."""
        seen: dict[str, Any] = {}

        async def app(inner_scope, receive, send):  # type: ignore[no-untyped-def]
            seen.update(inner_scope)

        middleware = ForwardedProtoMiddleware(app, trusted=parse_trusted_proxies(trusted))

        async def receive():  # type: ignore[no-untyped-def]
            return {"type": "http.request"}

        async def send(_message):  # type: ignore[no-untyped-def]
            return None

        await middleware(scope, receive, send)
        return seen

    @staticmethod
    def _scope(scheme: str, peer: str, headers: list[tuple[bytes, bytes]]) -> dict[str, Any]:
        """Build a minimal HTTP ASGI scope."""
        return {"type": "http", "scheme": scheme, "client": (peer, 1234), "headers": headers}

    @pytest.mark.asyncio
    async def test_trusted_peer_upgrades_http_to_https(self) -> None:
        scope = self._scope("http", PROXY_IP, [(b"x-forwarded-proto", b"https")])
        assert (await self._run(scope, PROXY_IP))["scheme"] == "https"

    @pytest.mark.asyncio
    async def test_untrusted_peer_is_ignored(self) -> None:
        scope = self._scope("http", OTHER_IP, [(b"x-forwarded-proto", b"https")])
        assert (await self._run(scope, PROXY_IP))["scheme"] == "http"

    @pytest.mark.asyncio
    async def test_https_is_never_downgraded_by_the_header(self) -> None:
        """Real TLS wins: a trusted proxy claiming ``http`` must not demote it.

        Load-bearing for composition with uvicorn's ``--proxy-headers``, which has
        already rewritten ``scope['client']`` to the *forwarded client* by the time
        this middleware runs — a downgrade decided from that peer would be wrong.
        """
        scope = self._scope("https", PROXY_IP, [(b"x-forwarded-proto", b"http")])
        assert (await self._run(scope, PROXY_IP))["scheme"] == "https"

    @pytest.mark.asyncio
    async def test_leftmost_entry_of_a_proxy_chain_wins(self) -> None:
        scope = self._scope("http", PROXY_IP, [(b"x-forwarded-proto", b"https, http")])
        assert (await self._run(scope, PROXY_IP))["scheme"] == "https"
        scope = self._scope("http", PROXY_IP, [(b"x-forwarded-proto", b"http, https")])
        assert (await self._run(scope, PROXY_IP))["scheme"] == "http"

    @pytest.mark.asyncio
    async def test_missing_header_leaves_the_scheme_alone(self) -> None:
        scope = self._scope("http", PROXY_IP, [])
        assert (await self._run(scope, PROXY_IP))["scheme"] == "http"


class TestStartupLogging:
    """The startup line must name the failure mode and the exact opt-out."""

    def test_enforcement_on_warns_about_plain_http_logins(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.INFO, logger="app.main"):
            log_https_enforcement(
                Settings(session_cookie_secure=True, forwarded_allow_ips="10.0.0.1")
            )
        message = "\n".join(r.getMessage() for r in caplog.records)
        assert "HTTPS enforcement is ON" in message
        assert "LOGINS OVER PLAIN HTTP WILL FAIL" in message
        assert "SCRYE_SESSION_COOKIE_SECURE=false" in message
        assert "X-Forwarded-Proto: https" in message
        assert "10.0.0.1/32" in message

    def test_enforcement_off_warns_about_cleartext_cookies(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.INFO, logger="app.main"):
            log_https_enforcement(
                Settings(session_cookie_secure=False, forwarded_allow_ips="10.0.0.1")
            )
        record = next(r for r in caplog.records if "HTTPS enforcement is OFF" in r.getMessage())
        assert record.levelno == logging.WARNING
        assert "WITHOUT the Secure attribute" in record.getMessage()

    def test_wildcard_proxy_trust_is_called_out(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.INFO, logger="app.main"):
            log_https_enforcement(Settings(session_cookie_secure=True, forwarded_allow_ips="*"))
        message = "\n".join(r.getMessage() for r in caplog.records)
        assert "trusted from EVERY peer" in message

    def test_unparseable_proxy_entries_are_called_out(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.INFO, logger="app.main"):
            log_https_enforcement(
                Settings(session_cookie_secure=True, forwarded_allow_ips="proxy.internal")
            )
        message = "\n".join(r.getMessage() for r in caplog.records)
        assert "not a valid IP or CIDR" in message
        assert "proxy.internal" in message
