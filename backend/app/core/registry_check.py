"""Best-effort container-registry credential test (docs/PLAN.md §4.5).

Given a decrypted registry credential, probe the registry's Docker Registry v2
API to confirm the host is reachable and the credential is accepted. Supports
both direct Basic auth and the standard bearer-token handshake (Docker Hub /
GHCR style): ``GET /v2/`` → ``401`` with a ``Www-Authenticate: Bearer`` challenge
→ fetch a token from the realm with Basic auth → retry.

The plaintext secret is used only in-memory for the request and never logged;
result messages are secret-free.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from app.core.config import get_settings
from app.core.egress import EgressError, validate_egress_url_async

_TIMEOUT_SECONDS = 10.0
_CHALLENGE_RE = re.compile(r'(\w+)="([^"]*)"')


@dataclass(frozen=True)
class RegistryCheck:
    """Outcome of a registry credential test."""

    ok: bool
    detail: str


def _normalize_base(registry_host: str) -> str:
    """Return the registry base URL, defaulting to HTTPS when no scheme is given."""
    host = registry_host.strip().rstrip("/")
    if host.startswith(("http://", "https://")):
        return host
    return f"https://{host}"


def _parse_challenge(header: str) -> dict[str, str]:
    """Parse a ``Www-Authenticate: Bearer realm="...",service="..."`` header."""
    return {key: value for key, value in _CHALLENGE_RE.findall(header)}


async def _bearer_token(
    client: httpx.AsyncClient, challenge: dict[str, str], auth: tuple[str, str]
) -> str | None:
    """Fetch a bearer token from the challenge realm, or ``None`` on failure.

    The realm URL comes from the probed registry's own ``Www-Authenticate``
    header, so it is untrusted: the stored credential is sent to it as Basic auth.
    Refuse to forward the credential unless the realm is an ``https`` URL — this
    stops a malicious/typo'd registry from harvesting the credential in cleartext
    over ``http`` or redirecting it to an attacker/internal endpoint (the client
    is created with ``follow_redirects=False`` so a credentialed request is never
    silently bounced cross-host).
    """
    realm = challenge.get("realm")
    if not realm:
        return None
    if urlparse(realm).scheme != "https":
        return None
    # The realm host is attacker-influenced (it comes from the probed registry's
    # own header); refuse to send the credential to an internal/metadata target.
    try:
        await validate_egress_url_async(realm, allow_internal=get_settings().allow_internal_egress)
    except EgressError:
        return None
    params = {k: challenge[k] for k in ("service", "scope") if challenge.get(k)}
    response = await client.get(realm, params=params, auth=auth)
    if response.status_code != 200:
        return None
    try:
        body = response.json()
    except ValueError:
        return None
    token = body.get("token") or body.get("access_token")
    return token if isinstance(token, str) and token else None


async def check_registry(*, registry_host: str, username: str | None, secret: str) -> RegistryCheck:
    """Probe a registry's v2 API to validate connectivity and the credential.

    Args:
        registry_host: The registry host (with or without a scheme).
        username: The stored username (may be empty for token auth).
        secret: The decrypted password/token (used in-memory only).

    Returns:
        A :class:`RegistryCheck` describing the outcome; never raises.
    """
    base = _normalize_base(registry_host)
    # Refuse to send the stored credential over cleartext http. `_normalize_base`
    # already defaults a scheme-less host to https; this rejects an explicit
    # `http://` host so a probe never leaks Basic-auth credentials in cleartext
    # (consistent with the Docker-environment proxy-URL validator).
    if urlparse(base).scheme != "https":
        return RegistryCheck(
            False,
            "Registry probe requires an https URL; refusing to send credentials over http.",
        )
    try:
        await validate_egress_url_async(base, allow_internal=get_settings().allow_internal_egress)
    except EgressError as exc:
        return RegistryCheck(False, str(exc))
    url = f"{base}/v2/"
    auth = (username or "", secret)
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS, follow_redirects=False) as client:
            response = await client.get(url, auth=auth)
            if response.status_code == 200:
                return RegistryCheck(True, "Registry reachable and credentials accepted.")
            if response.status_code == 401:
                challenge = _parse_challenge(response.headers.get("www-authenticate", ""))
                if not challenge:
                    return RegistryCheck(False, "Registry rejected the credentials (HTTP 401).")
                token = await _bearer_token(client, challenge, auth)
                if token is None:
                    return RegistryCheck(False, "Authentication failed at the token endpoint.")
                verified = await client.get(url, headers={"Authorization": f"Bearer {token}"})
                if verified.status_code == 200:
                    return RegistryCheck(True, "Registry reachable and credentials accepted.")
                return RegistryCheck(
                    False, f"Token issued but the registry returned HTTP {verified.status_code}."
                )
            return RegistryCheck(False, f"Registry returned HTTP {response.status_code}.")
    except httpx.HTTPError as exc:
        return RegistryCheck(False, f"Could not reach the registry: {exc}.")
