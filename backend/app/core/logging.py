"""Logging configuration.

Phase 0 provides basic, structured-ish console logging. The secret-redaction
filter required by the security model is added in Phase 1 alongside the crypto
module; a seam is left here so it can be attached without restructuring.
"""

from __future__ import annotations

import logging

_CONFIGURED = False


def configure_logging(level: str = "INFO") -> None:
    """Configure root logging once, idempotently.

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
    # NOTE (Phase 1): attach a redaction filter here so known secret fields are
    # never emitted to logs. Left intentionally unimplemented in Phase 0.
    _CONFIGURED = True
