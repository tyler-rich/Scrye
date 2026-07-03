"""Logging configuration with secret redaction.

Every log record passes through :class:`SecretRedactionFilter`, which masks
values attached to known secret-ish field names (``password=...``,
``"token": "..."``, ``Authorization: Bearer ...``) so plaintext secrets can
never leak through log output, even from third-party libraries or accidental
debug statements. This implements the "logging filter redacts known secret
fields" requirement of ``docs/PLAN.md`` §6.
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
# Scheme keywords (Bearer/Basic) are excluded from the value so header-style
# credentials are handled (whole-token) by the bearer pattern below instead.
_KV_PATTERN = re.compile(
    r"(?i)([\"']?\b[\w.-]*(?:" + "|".join(_SECRET_FIELD_NAMES) + r")\b[\"']?\s*[:=]\s*)"
    r"([\"']?)((?!(?:bearer|basic)\b)[^\s\"',;&]+)(\2)"
)
# Authorization header style bearer/basic tokens.
_BEARER_PATTERN = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+")
# URL userinfo credentials: https://user:token@host -> https://[REDACTED]@host.
# Covers transient credential-embedded git clone URLs (docs/PLAN.md §4.1) so a
# token can never surface through a logged URL or a stored scanner error.
_URL_USERINFO_PATTERN = re.compile(r"(?i)\b(https?://)[^/\s@]+@")


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
    return _KV_PATTERN.sub(rf"\g<1>\g<2>{REDACTED}\g<4>", text)


class SecretRedactionFilter(logging.Filter):
    """Logging filter that redacts secret values from every record."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Render the record's message, redact it, and always keep the record."""
        try:
            message = record.getMessage()
        except (TypeError, ValueError):
            # Malformed format args; leave the record untouched rather than drop it.
            return True
        redacted = redact(message)
        if redacted != message or record.args:
            record.msg = redacted
            record.args = None
        return True


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
    _CONFIGURED = True
