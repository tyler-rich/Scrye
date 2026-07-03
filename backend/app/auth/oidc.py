"""Generic OIDC (authorization-code + PKCE) client built on Authlib (§5).

Scrye speaks generic OIDC to any compliant provider (Pocket ID is the reference
target, RS256). This module owns the protocol mechanics:

- discover the provider metadata (``/.well-known/openid-configuration``),
- build the authorization URL with ``state``, ``nonce``, and PKCE ``S256``,
- exchange the authorization code for tokens, and
- verify the ID token signature (against the provider JWKS) and its ``iss`` /
  ``aud`` / ``exp`` / ``nonce`` claims.

The per-login ``state``/``nonce``/PKCE verifier are persisted in the
``oidc_login_flows`` table (not a server session), so the callback validates the
response without any session middleware. No secrets are logged here.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx

from app.auth._jose import JoseError, JsonWebKey, jwt

#: Discovery/JWKS cache TTL (seconds). Provider metadata rarely changes; caching
#: avoids a network round-trip on every login while still refreshing keys.
_CACHE_TTL_SECONDS = 300
_HTTP_TIMEOUT_SECONDS = 10
#: Clock-skew tolerance when validating time-based claims.
_LEEWAY_SECONDS = 60


class OidcError(RuntimeError):
    """Raised when an OIDC operation fails (config, network, or validation).

    Messages are safe to surface to the browser/login screen and never contain
    the client secret or any token material.
    """


@dataclass(frozen=True)
class OidcMetadata:
    """The subset of provider metadata Scrye needs."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str


#: Simple in-process TTL cache: issuer -> (expiry_epoch, value).
_metadata_cache: dict[str, tuple[float, OidcMetadata]] = {}
_jwks_cache: dict[str, tuple[float, dict]] = {}


def generate_pkce_pair() -> tuple[str, str]:
    """Return a ``(code_verifier, code_challenge)`` PKCE S256 pair."""
    verifier = secrets.token_urlsafe(64)[:96]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


async def discover(issuer: str) -> OidcMetadata:
    """Fetch (and cache) the provider's OpenID configuration.

    Args:
        issuer: The configured issuer URL.

    Returns:
        The parsed :class:`OidcMetadata`.

    Raises:
        OidcError: If discovery fails or required endpoints are missing.
    """
    issuer = issuer.rstrip("/")
    now = time.monotonic()
    cached = _metadata_cache.get(issuer)
    if cached and cached[0] > now:
        return cached[1]

    url = f"{issuer}/.well-known/openid-configuration"
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS) as http:
            response = await http.get(url)
            response.raise_for_status()
            doc = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OidcError(f"OIDC discovery failed for issuer {issuer!r}.") from exc

    try:
        metadata = OidcMetadata(
            issuer=doc["issuer"],
            authorization_endpoint=doc["authorization_endpoint"],
            token_endpoint=doc["token_endpoint"],
            jwks_uri=doc["jwks_uri"],
        )
    except KeyError as exc:
        raise OidcError(f"OIDC discovery document missing {exc.args[0]!r}.") from exc

    _metadata_cache[issuer] = (now + _CACHE_TTL_SECONDS, metadata)
    return metadata


async def _fetch_jwks(jwks_uri: str) -> dict:
    """Fetch (and cache) the provider JWKS."""
    now = time.monotonic()
    cached = _jwks_cache.get(jwks_uri)
    if cached and cached[0] > now:
        return cached[1]
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS) as http:
            response = await http.get(jwks_uri)
            response.raise_for_status()
            jwks = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OidcError("Could not fetch the OIDC signing keys (JWKS).") from exc
    _jwks_cache[jwks_uri] = (now + _CACHE_TTL_SECONDS, jwks)
    return jwks


def build_authorization_url(
    metadata: OidcMetadata,
    *,
    client_id: str,
    redirect_uri: str,
    scopes: str,
    state: str,
    nonce: str,
    code_challenge: str,
) -> str:
    """Construct the provider authorization URL for a redirect."""
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scopes,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"{metadata.authorization_endpoint}?{urlencode(params)}"


async def exchange_code(
    metadata: OidcMetadata,
    *,
    code: str,
    code_verifier: str,
    redirect_uri: str,
    client_id: str,
    client_secret: str | None,
) -> dict:
    """Exchange an authorization code for the token response.

    Uses ``client_secret_post`` when a secret is configured, and public-client
    PKCE otherwise. Returns the raw token response (must contain ``id_token``).
    """
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": code_verifier,
    }
    if client_secret:
        data["client_secret"] = client_secret
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS) as http:
            response = await http.post(
                metadata.token_endpoint,
                data=data,
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
            tokens = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OidcError("OIDC token exchange failed.") from exc
    if "id_token" not in tokens:
        raise OidcError("OIDC token response did not include an ID token.")
    return tokens


async def verify_id_token(
    metadata: OidcMetadata,
    id_token: str,
    *,
    client_id: str,
    nonce: str,
) -> dict:
    """Verify an ID token's signature and core claims, returning the claims.

    Raises:
        OidcError: On signature failure, claim mismatch, expiry, or nonce
            mismatch. Never leaks token material.
    """
    jwks = await _fetch_jwks(metadata.jwks_uri)
    try:
        key_set = JsonWebKey.import_key_set(jwks)
        claims = jwt.decode(
            id_token,
            key_set,
            claims_options={
                "iss": {"essential": True, "value": metadata.issuer},
                "aud": {"essential": True, "value": client_id},
                "exp": {"essential": True},
            },
        )
        claims.validate(now=int(time.time()), leeway=_LEEWAY_SECONDS)
    except (JoseError, ValueError, KeyError) as exc:
        raise OidcError("OIDC ID token validation failed.") from exc

    if claims.get("nonce") != nonce:
        raise OidcError("OIDC nonce mismatch; possible replay.")
    if not claims.get("sub"):
        raise OidcError("OIDC ID token is missing the subject claim.")
    return dict(claims)
