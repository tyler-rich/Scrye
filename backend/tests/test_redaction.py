"""Tests for log redaction and write-only secret masking."""

from __future__ import annotations

import io
import logging
from datetime import UTC, datetime

import pytest
from uvicorn.logging import AccessFormatter

from app.core.logging import (
    REDACTED,
    RedactingFormatter,
    configure_logging,
    install_redaction,
    redact,
)
from app.core.masking import SECRET_MASK, masked_secret


class TestRedact:
    def test_key_value_forms(self) -> None:
        assert redact("password=hunter2") == f"password={REDACTED}"
        # An unquoted value now consumes to end-of-line (or the next key=pair), so
        # trailing free text is over-redacted rather than risk leaking a spaced
        # secret (SEC-4) — see test_spaced_unquoted_secret_is_fully_redacted.
        assert redact("login with passwd: hunter2 ok") == f"login with passwd: {REDACTED}"
        assert redact('{"token": "abc.def.ghi"}') == f'{{"token": "{REDACTED}"}}'
        assert redact("client_secret = s3cr3t!") == f"client_secret = {REDACTED}"
        # A following structured key=value pair still bounds the redaction.
        assert redact("api_key=AKIA123 region=us") == f"api_key={REDACTED} region=us"

    def test_spaced_unquoted_secret_is_fully_redacted(self) -> None:
        # SEC-4: an unquoted secret containing spaces/commas was only masked up to
        # its first space/comma, leaking the tail. It must now be redacted whole.
        assert redact("password=p@ss w0rd here") == f"password={REDACTED}"
        assert redact("api_key=abc,def") == f"api_key={REDACTED}"
        assert redact("smtp_password: my mail pass 123") == f"smtp_password: {REDACTED}"
        for leaked in ("w0rd", "here", ",def", "mail pass"):
            assert leaked not in redact("password=p@ss w0rd here")
            assert leaked not in redact("api_key=abc,def")
            assert leaked not in redact("smtp_password: my mail pass 123")

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


class TestRedactingFormatter:
    def _capture(self) -> tuple[logging.Logger, io.StringIO]:
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        install_redaction(handler)
        logger = logging.getLogger("scrye.test.redaction")
        logger.handlers = [handler]
        logger.propagate = False
        logger.setLevel(logging.DEBUG)
        return logger, stream

    def test_plaintext_secret_never_reaches_log_output(self) -> None:
        logger, stream = self._capture()
        # Non-secret context that precedes the secret is preserved; the secret
        # (unquoted, last on the line) is consumed to end-of-line (SEC-4).
        # Note the secret spans the msg/args boundary — `password=` lives in the
        # format string, the value in the args — which is precisely why redaction
        # has to run on the rendered line rather than on either half.
        logger.info("storing registry credential for %s password=%s", "ghcr.io", "SuperSecret42")
        output = stream.getvalue()
        assert "SuperSecret42" not in output
        assert REDACTED in output
        assert "ghcr.io" in output

    def test_plain_messages_pass_through(self) -> None:
        logger, stream = self._capture()
        logger.info("healthy in %sms", 12)
        assert "healthy in 12ms" in stream.getvalue()

    def test_record_is_not_mutated(self) -> None:
        # The formatter must leave msg/args intact so downstream formatters (and
        # any second handler on the same record) still see the original structure.
        logger, _ = self._capture()
        records: list[logging.LogRecord] = []
        logger.handlers[0].addFilter(lambda record: records.append(record) or True)
        logger.info("password=%s", "SuperSecret42")
        (record,) = records
        assert record.msg == "password=%s"
        assert record.args == ("SuperSecret42",)

    def test_exception_traceback_is_redacted(self) -> None:
        logger, stream = self._capture()
        try:
            raise ValueError("failed for token=leaked-secret-value")
        except ValueError:
            logger.exception("scan failed")
        output = stream.getvalue()
        assert "leaked-secret-value" not in output
        assert REDACTED in output
        assert "ValueError" in output

    def test_wrapping_is_idempotent_and_preserves_the_inner_formatter(self) -> None:
        handler = logging.StreamHandler(io.StringIO())
        inner = logging.Formatter("%(levelname)s|%(message)s")
        handler.setFormatter(inner)
        install_redaction(handler)
        install_redaction(handler)
        wrapper = handler.formatter
        assert isinstance(wrapper, RedactingFormatter)
        assert wrapper.inner is inner
        record = logging.LogRecord("t", logging.INFO, __file__, 1, "token=abc", None, None)
        assert wrapper.format(record) == f"INFO|token={REDACTED}"


class TestUvicornAccessLogging:
    """Regression: redaction must not break uvicorn's access logger.

    uvicorn's ``AccessFormatter`` unpacks ``record.args`` into a five-tuple.
    Record-level redaction used to null ``args`` out, so every access line raised
    ``TypeError: cannot unpack non-iterable NoneType object`` and logging printed
    a ~50-line traceback in place of the line — roughly 144k lines/day from the
    30-second healthcheck alone. See ``docs/ARCHIVE.md`` §14 (2026-08-02).
    """

    ACCESS_FMT = '%(client_addr)s - "%(request_line)s" %(status_code)s'

    def _access_logger(self) -> tuple[logging.Logger, io.StringIO, list[BaseException]]:
        errors: list[BaseException] = []
        stream = io.StringIO()

        class _StrictHandler(logging.StreamHandler):  # type: ignore[type-arg]
            """Surfaces formatting failures that ``logging`` would otherwise swallow."""

            def handleError(self, record: logging.LogRecord) -> None:  # noqa: N802
                import sys

                errors.append(sys.exc_info()[1] or RuntimeError("unknown logging error"))

        handler = _StrictHandler(stream)
        handler.setFormatter(AccessFormatter(self.ACCESS_FMT, use_colors=False))
        install_redaction(handler)
        logger = logging.getLogger("scrye.test.uvicorn.access")
        logger.handlers = [handler]
        logger.propagate = False
        logger.setLevel(logging.INFO)
        return logger, stream, errors

    @staticmethod
    def _log_access(logger: logging.Logger, path: str, status: int = 200) -> None:
        """Emit the exact record uvicorn's access middleware emits."""
        logger.info('%s - "%s %s HTTP/%s" %d', "127.0.0.1:54076", "GET", path, "1.1", status)

    def test_access_record_formats_without_raising(self) -> None:
        logger, stream, errors = self._access_logger()
        self._log_access(logger, "/healthz")
        assert errors == [], f"access log formatting raised: {errors!r}"
        assert stream.getvalue().strip() == '127.0.0.1:54076 - "GET /healthz HTTP/1.1" 200 OK'

    def test_access_record_args_survive_formatting(self) -> None:
        # The five-tuple must still be on the record after it has been formatted,
        # so a second handler (or a re-format) sees the same structure.
        record = logging.LogRecord(
            name="uvicorn.access",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg='%s - "%s %s HTTP/%s" %d',
            args=("127.0.0.1:54076", "GET", "/healthz", "1.1", 200),
            exc_info=None,
        )
        formatter = RedactingFormatter(AccessFormatter(self.ACCESS_FMT, use_colors=False))
        assert formatter.format(record) == '127.0.0.1:54076 - "GET /healthz HTTP/1.1" 200 OK'
        assert record.args == ("127.0.0.1:54076", "GET", "/healthz", "1.1", 200)
        # Formatting twice must be stable — proof nothing was consumed in place.
        assert formatter.format(record) == '127.0.0.1:54076 - "GET /healthz HTTP/1.1" 200 OK'

    def test_redaction_still_applies_to_access_lines(self) -> None:
        logger, stream, errors = self._access_logger()
        self._log_access(logger, "/api/scans?api_token=SuperSecret42")
        output = stream.getvalue()
        assert errors == [], f"access log formatting raised: {errors!r}"
        assert "SuperSecret42" not in output
        assert REDACTED in output
        # The client address and the start of the request line are preserved; the
        # tail after the secret is consumed by the SEC-4 tempered-greedy value
        # match (over-redacting beats leaking) — see TestRedact above.
        assert output.startswith('127.0.0.1:54076 - "GET /api/scans?api_token=')

    def test_bearer_token_in_an_access_line_is_redacted(self) -> None:
        logger, stream, errors = self._access_logger()
        self._log_access(logger, "/api/x?auth=Bearer%20abc")
        self._log_access(logger, "/api/y?access_token=ghp_abcdef123")
        output = stream.getvalue()
        assert errors == []
        assert "ghp_abcdef123" not in output

    @pytest.mark.parametrize("logger_name", ["uvicorn", "uvicorn.access", "uvicorn.error", ""])
    def test_configure_logging_wraps_uvicorn_handlers(self, logger_name: str) -> None:
        """`configure_logging` must cover uvicorn's non-propagating loggers."""
        import logging.config

        from uvicorn.config import LOGGING_CONFIG

        target = logging.getLogger(logger_name)
        saved = {
            name: (logging.getLogger(name).handlers[:], logging.getLogger(name).propagate)
            for name in ("", "uvicorn", "uvicorn.access", "uvicorn.error")
        }
        try:
            # Mirror real startup: uvicorn's dictConfig runs first (Config.__init__),
            # then the app import reaches create_app() -> configure_logging().
            logging.config.dictConfig(LOGGING_CONFIG)
            configure_logging("INFO")
            assert target.handlers or logger_name in {"uvicorn.error", ""}
            for handler in target.handlers:
                assert isinstance(handler.formatter, RedactingFormatter)
        finally:
            for name, (handlers, propagate) in saved.items():
                restored = logging.getLogger(name)
                restored.handlers = handlers
                restored.propagate = propagate


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
