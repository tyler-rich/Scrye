"""Logging configuration with secret redaction.

Every log record passes through :class:`SecretRedactionFilter`, which masks
values attached to known secret-ish field names (``password=...``,
``"token": "..."``, ``Authorization: Bearer ...``) so plaintext secrets can
never leak through log output, even from third-party libraries or accidental
debug statements. This implements the "logging filter redacts known secret
fields" requirement of ``docs/ARCHIVE.md`` §6.
"""

from __future__ import annotations

import logging
import re

_CONFIGURED = False

#: Secret-bearing suffixes a field name may *end* with. Matching on the suffix
#: (rather than the exact word) means prefixed/compound keys that the schema
#: actually uses — ``registry_password``, ``git_token``, ``oidc_client_secret``,
#: ``db_password``, ``registryPassword`` — are redacted too, not just the bare
#: word. Order longest-first so the alternation prefers the most specific match.
_SECRET_FIELD_NAMES = (
    "client_secret",
    "refresh_token",
    "session_token",
    "access_token",
    "private_key",
    "secret_key",
    "access_key",
    "credentials",
    "credential",
    "passphrase",
    "id_token",
    "csrf_token",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "secret",
    "token",
    "authorization",
    "pwd",
)

REDACTED = "[REDACTED]"

# key = value / key: value / "key": "value" — with optional quoting around both.
# The key may carry a prefix joined by word chars / '.' / '-' (or camelCase), so
# `registry_password`, `git_token`, `oidc_client_secret` redact just like the
# bare word: `[\w.-]*` before the secret suffix absorbs the prefix, and the
# suffix must sit at the end of the key (immediately before the separator).
# The value is matched in three forms: a double-quoted run, a single-quoted run,
# or an unquoted run. The unquoted run is *tempered-greedy* — it consumes to the
# end of the line UNLESS it first reaches the start of another `key=`/`key:` pair
# (`(?!\s+[\w.-]+\s*[:=])`). This closes SEC-4: an unquoted secret that contains
# spaces or commas (an SMTP password, a backup passphrase, a multi-word token)
# is now redacted whole instead of only up to its first space/comma, while a
# following structured field like `region=us` is still preserved. `.` never
# crosses a newline, so a secret is bounded to its own log line. Over-redacting a
# trailing free-text phrase is the accepted trade-off — never leaking secret
# bytes is the filter's whole job. The value must start with a non-space (`\S`)
# so the engine can't give back the key's trailing space and start the value on
# it (which would slip past the Bearer/Basic guard). Scheme keywords
# (Bearer/Basic) are excluded from the unquoted form so header-style credentials
# are handled (whole-token) by the bearer pattern below instead.
_KV_PATTERN = re.compile(
    r"(?i)([\"']?\b[\w.-]*(?:" + "|".join(_SECRET_FIELD_NAMES) + r")\b[\"']?\s*[:=]\s*)"
    r"(?:\"([^\"]*)\"|'([^']*)'|((?!(?:bearer|basic)\b)\S(?:(?!\s+[\w.-]+\s*[:=]).)*))"
)
# Authorization header style bearer/basic tokens.
_BEARER_PATTERN = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+")
# URL userinfo credentials: https://user:token@host -> https://[REDACTED]@host.
# Covers transient credential-embedded git clone URLs (docs/ARCHIVE.md §4.1) so a
# token can never surface through a logged URL or a stored scanner error. Greedy
# up to the last '@' before the path so a literal '@' inside the userinfo can't
# leave a trailing fragment exposed.
_URL_USERINFO_PATTERN = re.compile(r"(?i)\b(https?://)[^\s/]+@")


def _kv_replacement(match: re.Match[str]) -> str:
    """Rebuild a matched key/value pair with the value masked, quotes preserved."""
    key = match.group(1)
    if match.group(2) is not None:  # double-quoted value
        return f'{key}"{REDACTED}"'
    if match.group(3) is not None:  # single-quoted value
        return f"{key}'{REDACTED}'"
    return f"{key}{REDACTED}"  # unquoted value


def strip_url_credentials(text: str) -> str:
    """Mask ``user:pass@`` userinfo in any ``http(s)`` URL within ``text``."""
    return _URL_USERINFO_PATTERN.sub(rf"\g<1>{REDACTED}@", text)


def redact(text: str) -> str:
    """Return ``text`` with values of known secret fields masked.

    Args:
        text: Arbitrary log text that may contain ``key=value`` /
            ``"key": "value"`` pairs, Authorization-style tokens, or URLs with
            embedded credentials.

    Returns:
        The text with secret values replaced by ``[REDACTED]``.
    """
    # Bearer/Basic first, so the scheme keyword can't be consumed as a KV value
    # (which would leave the token itself exposed).
    text = _BEARER_PATTERN.sub(rf"\g<1> {REDACTED}", text)
    text = strip_url_credentials(text)
    return _KV_PATTERN.sub(_kv_replacement, text)


class SecretRedactionFilter(logging.Filter):
    """Logging filter that redacts secret values from every record.

    Redacts the rendered message **and** any attached exception traceback /
    stack info — the stdlib ``Formatter`` appends those from ``exc_info`` /
    ``stack_info`` separately from the message, so a secret embedded in an
    exception string (e.g. an ``httpx``/``smtplib`` error carrying a webhook URL
    or SMTP password) would otherwise bypass message-only redaction.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Redact the record's message and traceback; always keep the record."""
        try:
            message = record.getMessage()
        except (TypeError, ValueError):
            # Malformed format args; leave the record untouched rather than drop it.
            return True
        redacted = redact(message)
        if redacted != message or record.args:
            record.msg = redacted
            record.args = None
        if record.exc_info:
            # Pre-format the traceback now and redact it; setting exc_text makes
            # the handler's Formatter reuse this (already-masked) text verbatim.
            exc_text = record.exc_text or logging.Formatter().formatException(record.exc_info)
            record.exc_text = redact(exc_text)
        if record.stack_info:
            record.stack_info = redact(record.stack_info)
        return True


#: Loggers that configure their own handlers with ``propagate=False`` (so records
#: never reach the root handlers our filter is attached to). uvicorn's access
#: logger in particular emits full request lines — query strings can carry an
#: OIDC ``code``/``state`` or a token — so it must be filtered directly.
_INDEPENDENT_LOGGERS = ("uvicorn", "uvicorn.access", "uvicorn.error")


def configure_logging(level: str = "INFO") -> None:
    """Configure root logging once, idempotently, with secret redaction.

    Args:
        level: Root log level name (e.g. ``"INFO"``).
    """
    global _CONFIGURED
    if _CONFIGURED:
        return

    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s | %(message)s",
    )
    redaction = SecretRedactionFilter()
    for handler in logging.getLogger().handlers:
        handler.addFilter(redaction)
    # Cover loggers that don't propagate to root (notably uvicorn.access): attach
    # to both the logger (applies regardless of when its handlers are added) and
    # any handlers it already has.
    for name in _INDEPENDENT_LOGGERS:
        independent = logging.getLogger(name)
        independent.addFilter(redaction)
        for handler in independent.handlers:
            handler.addFilter(redaction)
    _CONFIGURED = True
