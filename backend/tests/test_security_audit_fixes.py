"""Regression tests for the post-Phase-6 security-audit fixes.

Each test pins a specific behavior a review finding turned into a fix:

* log-redaction gaps (quoted multi-word secrets, exception tracebacks),
* cron evaluator correctness (DOW 7 = Sunday, ``N/step`` extension, ``*/step``
  Vixie OR/AND semantics),
* scanner argv option-injection guards (leading ``-`` rejection),
* the generic git checkout landing on the writable ``/cache`` volume (not tmpfs),
* the registry-probe refusing to forward credentials to a non-HTTPS realm,
* the backup restore failing closed on an unversioned bundle.
"""

from __future__ import annotations

import asyncio
import logging

import pytest
from pydantic import ValidationError

import app.backup.bundle as bundle
import app.core.registry_check as registry_check
import app.scanners.credentials as credentials
from app.api.scan_schemas import ScanCreateIn
from app.core.config import get_settings
from app.core.cron import CronExpression
from app.core.logging import REDACTED, RedactingFormatter, redact
from app.core.registry_check import _bearer_token
from app.db.models import GitProvider, Scanner, TargetType
from app.scanners.base import CommandResult
from app.scanners.credentials import GitAuth, generic_repo_checkout

# --- Log redaction -----------------------------------------------------------


class TestRedactionGaps:
    def test_quoted_value_with_spaces_is_masked(self) -> None:
        # A quoted secret containing spaces (SMTP password / backup passphrase in
        # a dict/JSON repr) must be redacted whole, not skipped at the first space.
        assert redact('{"password": "my secret phrase"}') == f'{{"password": "{REDACTED}"}}'
        assert redact("passphrase='correct horse battery staple'") == f"passphrase='{REDACTED}'"
        assert "secret phrase" not in redact('{"password": "my secret phrase"}')

    def test_single_word_value_still_masked(self) -> None:
        assert redact("token=abc123") == f"token={REDACTED}"

    def test_exception_traceback_is_redacted(self) -> None:
        # A secret in an exception string must not survive via the formatted
        # traceback (which the message-only path never touched).
        record = logging.LogRecord(
            name="t",
            level=logging.ERROR,
            pathname=__file__,
            lineno=1,
            msg="boom",
            args=(),
            exc_info=None,
        )
        try:
            raise ValueError("failed for token=leaked-secret-value")
        except ValueError:
            import sys

            record.exc_info = sys.exc_info()
        rendered = RedactingFormatter().format(record)
        assert "leaked-secret-value" not in rendered
        assert REDACTED in rendered
        assert "ValueError" in rendered


# --- Cron evaluator ----------------------------------------------------------


class TestCronFixes:
    def test_day_of_week_seven_is_sunday(self) -> None:
        expr = CronExpression.parse("0 0 * * 7")
        # 2024-01-07 is a Sunday; 2024-01-08 a Monday.
        assert expr.matches(__import__("datetime").datetime(2024, 1, 7, 0, 0))
        assert not expr.matches(__import__("datetime").datetime(2024, 1, 8, 0, 0))

    def test_bare_value_with_step_extends_to_max(self) -> None:
        # `5/15` in the minute field means 5,20,35,50 (Vixie), not just {5}.
        assert CronExpression.parse("5/15 * * * *").minutes == frozenset({5, 20, 35, 50})

    def test_star_step_day_keeps_and_semantics(self) -> None:
        from datetime import datetime

        # `*/2` day-of-month is 1,3,5,... (odd). With an explicit weekday, Vixie
        # ANDs the two day fields (both must match) because `*/2` is unrestricted.
        expr = CronExpression.parse("0 0 */2 * 0")  # odd day AND Sunday
        assert expr.matches(datetime(2024, 1, 7, 0, 0))  # day 7 (odd) + Sunday
        assert not expr.matches(datetime(2024, 1, 14, 0, 0))  # Sunday but even day
        # Pre-fix this OR'd and would have matched an odd, non-Sunday day:
        assert not expr.matches(datetime(2024, 1, 5, 0, 0))  # day 5 (odd) but Friday


# --- Scanner argv option-injection -------------------------------------------


class TestTargetValidation:
    def test_leading_dash_target_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ScanCreateIn(scanner=Scanner.TRIVY, target="--output=/data/scrye.db")

    def test_leading_dash_ref_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ScanCreateIn(
                scanner=Scanner.TRIVY,
                target_type=TargetType.REPOSITORY,
                target="https://example.test/x.git",
                branch="--upload-pack=evil",
            )

    def test_ordinary_target_accepted(self) -> None:
        payload = ScanCreateIn(scanner=Scanner.TRIVY, target="alpine:3.19")
        assert payload.target == "alpine:3.19"


# --- Git checkout lands on /cache, not tmpfs ---------------------------------


def test_generic_checkout_uses_cache_scratch(monkeypatch) -> None:
    async def fake_run_command(argv, *, timeout, env):
        return CommandResult(returncode=0, stdout=b"", stderr=b"", argv=argv)

    monkeypatch.setattr(credentials, "run_command", fake_run_command)

    async def go() -> str:
        auth = GitAuth(provider=GitProvider.GENERIC, token="tok")
        async with generic_repo_checkout(
            "https://example.test/x.git", auth, {}, timeout=5
        ) as checkout:
            return checkout

    checkout = asyncio.run(go())
    # The large working tree must sit under the disk-backed cache volume, never
    # the small RAM-backed /tmp tmpfs.
    assert str(get_settings().scanner_cache_dir) in checkout


# --- Registry probe: HTTPS-only bearer realm ---------------------------------


class _RecordingClient:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def get(self, url, **kwargs):  # pragma: no cover - only for https path
        self.calls.append(url)
        raise AssertionError("should not be called for a non-https realm")


def test_bearer_token_refuses_non_https_realm() -> None:
    client = _RecordingClient()
    result = asyncio.run(
        _bearer_token(client, {"realm": "http://evil.example/token"}, ("user", "secret"))
    )
    assert result is None
    assert client.calls == []


def test_bearer_token_missing_realm() -> None:
    client = _RecordingClient()
    assert asyncio.run(_bearer_token(client, {}, ("user", "secret"))) is None


def test_check_registry_refuses_http_host(monkeypatch) -> None:
    # Hotfix: an admin-configured http:// registry host must not have credentials
    # sent to it in cleartext — the probe fails closed before any request.
    def _boom(*args, **kwargs):  # pragma: no cover - must never be reached
        raise AssertionError("no HTTP client should be created for an http:// host")

    monkeypatch.setattr(registry_check.httpx, "AsyncClient", _boom)
    result = asyncio.run(
        registry_check.check_registry(
            registry_host="http://internal-registry.local", username="u", secret="s"
        )
    )
    assert result.ok is False
    assert "https" in result.detail.lower()


# --- Backup restore fails closed on an unversioned bundle --------------------


def test_restore_rejects_unversioned_bundle_into_versioned_db(db, monkeypatch) -> None:
    passphrase = "correct-horse-battery-staple"
    data = bundle.build_bundle(db, passphrase)  # test DB has no schema version
    # Pretend the running installation is migration-managed (versioned).
    monkeypatch.setattr(bundle, "_schema_version", lambda _db: "0008_something")
    with pytest.raises(bundle.BackupError):
        bundle.restore_bundle(db, data, passphrase)
