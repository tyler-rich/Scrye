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

    def test_non_secret_text_untouched(self) -> None:
        text = "scan completed for image nginx:1.27 in 4.2s (42 findings)"
        assert redact(text) == text


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
