"""Tests for TOTP MFA enrollment and the two-step login flow."""

from __future__ import annotations

import pyotp
from fastapi.testclient import TestClient

from tests.test_auth import ADMIN_PW, CSRF, setup_admin


def _enroll_and_activate(client: TestClient, csrf: str) -> str:
    """Enroll and activate MFA for the current user; return the TOTP secret."""
    enroll = client.post("/api/auth/mfa/enroll", json={}, headers={CSRF: csrf})
    assert enroll.status_code == 200, enroll.text
    secret = enroll.json()["secret"]
    assert enroll.json()["otpauth_uri"].startswith("otpauth://totp/")
    code = pyotp.TOTP(secret).now()
    resp = client.post("/api/auth/mfa/activate", json={"code": code}, headers={CSRF: csrf})
    assert resp.status_code == 204, resp.text
    return secret


class TestMfaEnrollment:
    def test_enroll_activate_sets_flag(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        _enroll_and_activate(client, csrf)
        assert client.get("/api/auth/me").json()["mfa_enabled"] is True

    def test_activate_rejects_wrong_code(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        client.post("/api/auth/mfa/enroll", json={}, headers={CSRF: csrf})
        resp = client.post("/api/auth/mfa/activate", json={"code": "000000"}, headers={CSRF: csrf})
        assert resp.status_code == 400
        assert client.get("/api/auth/me").json()["mfa_enabled"] is False

    def test_secret_never_returned_after_enrollment(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        secret = _enroll_and_activate(client, csrf)
        # The plaintext secret must not appear in any subsequent read.
        assert secret not in client.get("/api/auth/me").text


class TestMfaLogin:
    def test_login_requires_second_factor(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        secret = _enroll_and_activate(client, csrf)
        client.cookies.clear()

        first = client.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PW})
        assert first.status_code == 200
        body = first.json()
        assert body["mfa_required"] is True
        assert body["mfa_token"]
        assert body["user"] is None
        # No session established yet.
        assert client.get("/api/auth/me").status_code == 401

        code = pyotp.TOTP(secret).now()
        second = client.post(
            "/api/auth/mfa/verify", json={"mfa_token": body["mfa_token"], "code": code}
        )
        assert second.status_code == 200
        assert second.json()["user"]["username"] == "admin"
        assert client.get("/api/auth/me").status_code == 200

    def test_verify_rejects_bad_code(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        _enroll_and_activate(client, csrf)
        client.cookies.clear()
        token = client.post(
            "/api/auth/login", json={"username": "admin", "password": ADMIN_PW}
        ).json()["mfa_token"]
        resp = client.post("/api/auth/mfa/verify", json={"mfa_token": token, "code": "000000"})
        assert resp.status_code == 401

    def test_challenge_token_is_single_use(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        secret = _enroll_and_activate(client, csrf)
        client.cookies.clear()
        token = client.post(
            "/api/auth/login", json={"username": "admin", "password": ADMIN_PW}
        ).json()["mfa_token"]
        code = pyotp.TOTP(secret).now()
        first = client.post("/api/auth/mfa/verify", json={"mfa_token": token, "code": code})
        assert first.status_code == 200
        client.cookies.clear()
        again = client.post("/api/auth/mfa/verify", json={"mfa_token": token, "code": code})
        assert again.status_code == 401


class TestMfaPolicyEnforcement:
    def test_fresh_instance_defaults_to_no_mfa_requirement(self, client: TestClient) -> None:
        # A brand-new instance must never force MFA: the default policy is
        # OPTIONAL, so an un-enrolled account logs straight in with no second
        # factor and no forced-enrollment prompt. Guards against a silent flip of
        # the AuthSettings.mfa_policy default.
        setup_admin(client)  # first admin, MFA never enrolled, no policy set
        client.cookies.clear()

        resp = client.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PW})
        assert resp.status_code == 200
        body = resp.json()
        assert body["mfa_required"] is False
        assert body["enrollment_required"] is False
        assert body["mfa_token"] is None
        # A full session is granted immediately (no second step required).
        assert body["user"]["username"] == "admin"
        assert client.get("/api/auth/me").status_code == 200

    def test_required_policy_forces_enrollment_at_login(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        client.put(
            "/api/settings/authentication",
            json={"local_login_enabled": True, "mfa_policy": "required_all"},
            headers={CSRF: csrf},
        )
        client.cookies.clear()

        first = client.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PW})
        assert first.status_code == 200
        body = first.json()
        assert body["mfa_required"] is True
        assert body["enrollment_required"] is True
        assert body["mfa_secret"] and body["mfa_token"]
        assert body["user"] is None
        # No session is granted until enrollment completes.
        assert client.get("/api/auth/me").status_code == 401

        code = pyotp.TOTP(body["mfa_secret"]).now()
        second = client.post(
            "/api/auth/mfa/verify", json={"mfa_token": body["mfa_token"], "code": code}
        )
        assert second.status_code == 200
        assert client.get("/api/auth/me").json()["mfa_enabled"] is True

    def test_reenroll_requires_current_password(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        _enroll_and_activate(client, csrf)  # MFA now active
        # Re-enrolling (which deactivates MFA) needs the password: a session alone
        # must not be able to strip the second factor.
        without = client.post("/api/auth/mfa/enroll", json={}, headers={CSRF: csrf})
        assert without.status_code == 403
        assert client.get("/api/auth/me").json()["mfa_enabled"] is True
        with_pw = client.post(
            "/api/auth/mfa/enroll", json={"current_password": ADMIN_PW}, headers={CSRF: csrf}
        )
        assert with_pw.status_code == 200

    def test_reenroll_over_pending_secret_requires_password(self, client: TestClient) -> None:
        # Security hotfix: the password gate must also cover the PENDING window —
        # a secret exists but MFA is not yet active. Otherwise a session-only
        # attacker (stolen cookie + CSRF, no password) could overwrite the pending
        # secret and make the victim enroll the attacker's authenticator.
        csrf = setup_admin(client)
        first = client.post("/api/auth/mfa/enroll", json={}, headers={CSRF: csrf})
        assert first.status_code == 200  # first-ever enrollment: no prior secret, no gate
        assert client.get("/api/auth/me").json()["mfa_enabled"] is False  # pending, not active
        # A second enroll while the pending secret exists must now require the password.
        without = client.post("/api/auth/mfa/enroll", json={}, headers={CSRF: csrf})
        assert without.status_code == 403
        with_pw = client.post(
            "/api/auth/mfa/enroll", json={"current_password": ADMIN_PW}, headers={CSRF: csrf}
        )
        assert with_pw.status_code == 200


class TestMfaDisable:
    def test_disable_requires_password(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        _enroll_and_activate(client, csrf)
        bad = client.post(
            "/api/auth/mfa/disable", json={"password": "wrong-password"}, headers={CSRF: csrf}
        )
        assert bad.status_code == 403
        ok = client.post("/api/auth/mfa/disable", json={"password": ADMIN_PW}, headers={CSRF: csrf})
        assert ok.status_code == 204
        assert client.get("/api/auth/me").json()["mfa_enabled"] is False

    def test_cannot_disable_when_policy_requires(self, client: TestClient) -> None:
        csrf = setup_admin(client)
        _enroll_and_activate(client, csrf)
        client.put(
            "/api/settings/authentication",
            json={"local_login_enabled": True, "mfa_policy": "required_all"},
            headers={CSRF: csrf},
        )
        resp = client.post(
            "/api/auth/mfa/disable", json={"password": ADMIN_PW}, headers={CSRF: csrf}
        )
        assert resp.status_code == 400


class TestPendingMfaStoreConcurrency:
    def test_concurrent_issue_and_consume_never_raise(self) -> None:
        """Hammer issue/consume/prune from many threads (mirroring the sync
        login/verify endpoints running on different threadpool threads). An
        unlocked ``_prune`` would raise ``RuntimeError: dictionary changed size
        during iteration``; the lock must keep every operation clean (CON-8)."""
        import threading

        from app.auth.mfa import _CHALLENGE_TTL_SECONDS, PendingMfaStore

        store = PendingMfaStore()
        # A mix of live and already-expired challenges so ``_prune`` has rows to
        # remove on every call, maximizing the chance of a concurrent mutation.
        for i in range(200):
            token = store.issue(i)
            if i % 2 == 0:
                store._pending[token].expires_at = 0.0  # force-expire half of them

        errors: list[BaseException] = []
        barrier = threading.Barrier(8)

        def worker(worker_id: int) -> None:
            barrier.wait()
            try:
                for j in range(300):
                    tok = store.issue(worker_id * 1000 + j)
                    store.consume(tok)
            except BaseException as exc:  # noqa: BLE001 - the assertion is "no raise"
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(w,)) for w in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert not errors, f"concurrent access raised: {errors[0]!r}"
        assert _CHALLENGE_TTL_SECONDS > 0
