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

import httpx

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
    """Fetch a bearer token from the challenge realm, or ``None`` on failure."""
    realm = challenge.get("realm")
    if not realm:
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
    url = f"{base}/v2/"
    auth = (username or "", secret)
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS, follow_redirects=True) as client:
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
