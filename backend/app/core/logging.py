"""Logging configuration with secret redaction.

Every log line passes through :class:`RedactingFormatter`, which masks values
attached to known secret-ish field names (``password=...``, ``"token": "..."``,
``Authorization: Bearer ...``) so plaintext secrets can never leak through log
output, even from third-party libraries or accidental debug statements. This
implements the "logging filter redacts known secret fields" requirement of
``docs/ARCHIVE.md`` §6.

Redaction runs on the **rendered line**, not on the :class:`logging.LogRecord`.
See :class:`RedactingFormatter` for why that distinction is load-bearing.
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


class RedactingFormatter(logging.Formatter):
    """Formatter wrapper that redacts a handler's fully rendered output.

    Redaction runs on the **formatted line**, never on the
    :class:`logging.LogRecord`. That distinction is load-bearing, and getting it
    wrong is what broke uvicorn's access logger (see ``docs/ARCHIVE.md`` §14,
    2026-08-02).

    A secret routinely straddles the boundary between a record's format string
    and its args — ``log.info("password=%s", pw)`` has neither half matching
    :data:`_KV_PATTERN` on its own — so :func:`redact` can only work *after*
    ``%``-interpolation. Redacting a record in place therefore forces collapsing
    ``msg``/``args`` into one pre-rendered string and clearing ``args``, and a
    cleared ``args`` is fatal to any formatter that reads it: uvicorn's
    ``AccessFormatter`` unpacks ``record.args`` into a five-tuple
    (``client_addr``, ``method``, ``full_path``, ``http_version``,
    ``status_code``) and raises ``TypeError: cannot unpack non-iterable NoneType
    object`` on every request.

    Formatting the output instead leaves the record untouched, so every
    formatter still sees the structure it expects — and it redacts strictly
    *more* than the record-level approach did: the access line's
    ``client_addr``/``request_line`` fields, which are rebuilt from ``args`` and
    never appear in ``getMessage()``, plus any exception traceback or stack info
    the inner formatter appends, are all covered by the same single pass.
    """

    def __init__(self, inner: logging.Formatter | None = None) -> None:
        """Wrap ``inner`` (the handler's real formatter; a plain one if ``None``)."""
        super().__init__()
        self.inner = inner if inner is not None else logging.Formatter()

    def format(self, record: logging.LogRecord) -> str:
        """Render ``record`` with the wrapped formatter, then mask secrets."""
        return redact(self.inner.format(record))


def install_redaction(handler: logging.Handler) -> None:
    """Wrap ``handler``'s formatter so its output is redacted. Idempotent.

    Args:
        handler: The handler to protect. Its existing formatter (including
            uvicorn's ``DefaultFormatter``/``AccessFormatter``) is preserved and
            delegated to, so log layout and colouring are unchanged.
    """
    if isinstance(handler.formatter, RedactingFormatter):
        return
    handler.setFormatter(RedactingFormatter(handler.formatter))


#: Loggers that configure their own handlers with ``propagate=False`` (so records
#: never reach the root handlers), plus their parent. uvicorn's access logger in
#: particular emits full request lines — query strings can carry an OIDC
#: ``code``/``state`` or a token — so its handlers must be wrapped directly.
_INDEPENDENT_LOGGERS = ("uvicorn", "uvicorn.access", "uvicorn.error")


def configure_logging(level: str = "INFO") -> None:
    """Configure root logging once, idempotently, with secret redaction.

    Must run *after* uvicorn has installed its own handlers, which it does: the
    CLI builds ``uvicorn.Config`` (whose ``__init__`` applies uvicorn's
    ``LOGGING_CONFIG`` via ``dictConfig``) before ``Config.load()`` imports
    ``app.main`` and reaches :func:`~app.main.create_app`. Wrapping is idempotent
    and re-applied on every call, so a later reconfiguration can be re-covered by
    calling this again.

    Args:
        level: Root log level name (e.g. ``"INFO"``).
    """
    global _CONFIGURED
    if not _CONFIGURED:
        logging.basicConfig(
            level=getattr(logging, level.upper(), logging.INFO),
            format="%(asctime)s %(levelname)-8s %(name)s | %(message)s",
        )
        _CONFIGURED = True

    for name in ("", *_INDEPENDENT_LOGGERS):
        for handler in logging.getLogger(name).handlers:
            install_redaction(handler)
