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

#: Field names whose values must never appear in logs.
_SECRET_FIELD_NAMES = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "client_secret",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "session_token",
    "csrf_token",
    "api_key",
    "apikey",
    "authorization",
    "access_key",
    "secret_key",
    "private_key",
    "credential",
    "credentials",
)

REDACTED = "[REDACTED]"

# key = value / key: value / "key": "value" — with optional quoting around both.
# Scheme keywords (Bearer/Basic) are excluded from the value so header-style
# credentials are handled (whole-token) by the bearer pattern below instead.
_KV_PATTERN = re.compile(
    r"(?i)([\"']?\b(?:" + "|".join(_SECRET_FIELD_NAMES) + r")\b[\"']?\s*[:=]\s*)"
    r"([\"']?)((?!(?:bearer|basic)\b)[^\s\"',;&]+)(\2)"
)
# Authorization header style bearer/basic tokens.
_BEARER_PATTERN = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+")


def redact(text: str) -> str:
    """Return ``text`` with values of known secret fields masked.

    Args:
        text: Arbitrary log text that may contain ``key=value`` /
            ``"key": "value"`` pairs or Authorization-style tokens.

    Returns:
        The text with secret values replaced by ``[REDACTED]``.
    """
    # Bearer/Basic first, so the scheme keyword can't be consumed as a KV value
    # (which would leave the token itself exposed).
    text = _BEARER_PATTERN.sub(rf"\g<1> {REDACTED}", text)
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
