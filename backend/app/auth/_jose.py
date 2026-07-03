# ruff: noqa: I001 - import order here is deliberate (see the comment below).
"""Import shim for Authlib's deprecated ``jose`` module.

Authlib's ``jose`` submodule is deprecated in favor of ``joserfc`` but remains
supported until Authlib 2.0; Scrye uses it for OIDC ID-token validation. On
import, ``authlib.deprecate`` installs a global ``simplefilter("always", ...)``
that would re-surface its deprecation warning on every run. Importing that
module *first*, then overriding the filter inside a ``catch_warnings`` block,
lets us suppress the one benign warning here so the rest of the codebase imports
the JWT helpers with an ordinary, sorted import.
"""

from __future__ import annotations

import warnings

import authlib.deprecate  # noqa: F401 - import installs the filter we override next

with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    from authlib.jose import JsonWebKey, JsonWebToken, jwt
    from authlib.jose.errors import JoseError

__all__ = ["JoseError", "JsonWebKey", "JsonWebToken", "jwt"]
