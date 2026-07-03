"""Tests for log redaction and write-only secret masking."""

from __future__ import annotations

import io
import logging
from datetime import UTC, datetime

from app.core.logging import REDACTED, SecretRedactionFilter, redact
from app.core.masking import SECRET_MASK, masked_secret


class TestRedact:
    def test_key_value_forms(self) -> None:
        assert redact("password=hunter2") == f"password={REDACTED}"
        assert redact("login with passwd: hunter2 ok") == f"login with passwd: {REDACTED} ok"
        assert redact('{"token": "abc.def.ghi"}') == f'{{"token": "{REDACTED}"}}'
        assert redact("client_secret = s3cr3t!") == f"client_secret = {REDACTED}"
        assert redact("api_key=AKIA123 region=us") == f"api_key={REDACTED} region=us"

    def test_authorization_headers(self) -> None:
        assert redact("Authorization: Bearer eyJhbGciOi.abc") == f"Authorization: Bearer {REDACTED}"
        assert redact("authorization=Basic dXNlcjpwYXNz") == f"authorization=Basic {REDACTED}"
        # The credential itself must be gone in every form.
        assert "eyJhbGciOi" not in redact("Authorization: Bearer eyJhbGciOi.abc")
        assert "dXNlcjpwYXNz" not in redact("authorization=Basic dXNlcjpwYXNz")

    def test_prefixed_and_compound_field_names(self) -> None:
        # The schema stores secrets under compound names (registry_password,
        # git_token, oidc_client_secret, ...); the value must still be masked.
        assert redact("registry_password=hunter2") == f"registry_password={REDACTED}"
        assert redact("git_token=ghp_abcdef123") == f"git_token={REDACTED}"
        assert redact("oidc_client_secret=s3cr3t") == f"oidc_client_secret={REDACTED}"
        assert redact("db_password: swordfish") == f"db_password: {REDACTED}"
        assert redact("user_password=leak") == f"user_password={REDACTED}"
        assert redact("backup_passphrase=letmein") == f"backup_passphrase={REDACTED}"
        assert redact('{"git_token": "abc.def"}') == f'{{"git_token": "{REDACTED}"}}'
        # None of the plaintext values survive.
        for text in (
            "registry_password=hunter2",
            "git_token=ghp_abcdef123",
            "oidc_client_secret=s3cr3t",
        ):
            assert text.split("=", 1)[1] not in redact(text)

    def test_camel_case_field_names(self) -> None:
        assert redact("registryPassword=camelCaseSecret") == f"registryPassword={REDACTED}"
        assert redact("apiToken=abc123") == f"apiToken={REDACTED}"

    def test_non_secret_text_untouched(self) -> None:
        text = "scan completed for image nginx:1.27 in 4.2s (42 findings)"
        assert redact(text) == text

    def test_keys_not_ending_in_a_secret_suffix_untouched(self) -> None:
        # The secret word must be the *tail* of the key; unrelated keys that
        # merely contain a secret word mid-name are left alone.
        assert redact("secret_info_note=harmless") == "secret_info_note=harmless"
        assert redact("token_count=42") == "token_count=42"
        assert redact("duration=4.2s count=42") == "duration=4.2s count=42"

    def test_near_miss_keys_that_end_in_a_non_secret_word(self) -> None:
        # Keys that carry a secret word but do NOT end in one describe/qualify a
        # secret rather than being one, so their (non-secret) value is preserved.
        # `*_hint`, `*_type`, `*_santa`, `*_field` are all metadata, not the value.
        for text in (
            "password_hint=reset via email",  # a hint, not the password
            "token_type=Bearer",  # OAuth token *type*, not the token
            "secret_santa=alice",  # not a secret at all
            "not_a_password_field=whatever",  # ends in 'field'
        ):
            assert redact(text) == text, f"unexpectedly redacted: {text!r}"

    def test_expiry_style_metadata_is_not_redacted(self) -> None:
        # `access_token_expiry` names *when a token expires* (a timestamp), not
        # the token itself — the secret word 'token' is mid-key, not the tail,
        # so the timestamp value is kept. Contrast with the bare `access_token`,
        # which is the credential and IS redacted. If a contains-based policy is
        # ever preferred over this suffix rule, this is the case that flips.
        assert (
            redact("access_token_expiry=2026-01-01T00:00:00Z")
            == "access_token_expiry=2026-01-01T00:00:00Z"
        )
        assert redact("access_token=abc.def.ghi") == f"access_token={REDACTED}"


class TestRedactionFilter:
    def _capture(self) -> tuple[logging.Logger, io.StringIO]:
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.addFilter(SecretRedactionFilter())
        logger = logging.getLogger("scrye.test.redaction")
        logger.handlers = [handler]
        logger.propagate = False
        logger.setLevel(logging.DEBUG)
        return logger, stream

    def test_plaintext_secret_never_reaches_log_output(self) -> None:
        logger, stream = self._capture()
        logger.info("storing registry credential password=%s for %s", "SuperSecret42", "ghcr.io")
        output = stream.getvalue()
        assert "SuperSecret42" not in output
        assert REDACTED in output
        assert "ghcr.io" in output

    def test_plain_messages_pass_through(self) -> None:
        logger, stream = self._capture()
        logger.info("healthy in %sms", 12)
        assert "healthy in 12ms" in stream.getvalue()


class TestMaskedSecret:
    def test_unset_secret(self) -> None:
        view = masked_secret(None)
        assert view.is_set is False
        assert view.value == ""
        assert view.updated_at is None

    def test_set_secret_returns_mask_and_timestamp_only(self) -> None:
        ts = datetime(2026, 7, 3, 12, 0, tzinfo=UTC)
        view = masked_secret(ts)
        assert view.is_set is True
        assert view.value == SECRET_MASK
        assert view.updated_at == ts
        # The serialized form contains no fields other than the mask metadata.
        assert set(view.model_dump()) == {"is_set", "value", "updated_at"}
