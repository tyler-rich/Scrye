"""Read-only Docker socket-proxy client for image enumeration (docs/PLAN.md §3).

Scrye never mounts ``/var/run/docker.sock`` (locked decision §0.3, CIS
5.21/5.22). Instead it talks HTTP to a **read-only** ``docker-socket-proxy``
sidecar that exposes only listing endpoints. This client can therefore only
*enumerate* images — it never creates, controls, or removes anything.

The proxy speaks the Docker Engine API, so ``GET /images/json`` returns the same
shape as the daemon. We surface each image's usable references (repo tags) plus
size and id for the "scan running images" picker; the user then launches normal
image scans against those references.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from app.core.egress import EgressError, validate_egress_url_async

#: Wall-clock timeout for a single proxy request (seconds). Enumeration is cheap;
#: a slow/hung proxy should fail fast rather than block the request thread.
_PROXY_TIMEOUT_SECONDS = 10.0


class DockerProxyError(RuntimeError):
    """Raised when the Docker socket proxy cannot be reached or returns badly.

    The message is safe to surface to operators; it carries no credentials (the
    proxy is unauthenticated on an internal network, by design).
    """


@dataclass(frozen=True)
class DockerImage:
    """A single image enumerated from a Docker environment."""

    id: str
    tags: list[str]
    size_bytes: int


def _parse_images(payload: object) -> list[DockerImage]:
    """Normalize a Docker ``/images/json`` array into :class:`DockerImage` rows.

    Untagged images (``<none>:<none>``) are dropped: they have no reference a
    scanner could pull, so they are not offered for scanning.
    """
    if not isinstance(payload, list):
        raise DockerProxyError("Docker proxy returned an unexpected images payload.")
    images: list[DockerImage] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        raw_tags = entry.get("RepoTags") or []
        tags = [t for t in raw_tags if isinstance(t, str) and t and "<none>" not in t]
        if not tags:
            continue
        images.append(
            DockerImage(
                id=str(entry.get("Id", "")),
                tags=tags,
                size_bytes=int(entry.get("Size") or 0),
            )
        )
    return images


async def list_images(proxy_url: str) -> list[DockerImage]:
    """Enumerate tagged images from a read-only Docker socket proxy.

    Args:
        proxy_url: Base URL of the proxy (e.g. ``http://docker-socket-proxy:2375``).

    Returns:
        The tagged images visible to the proxy.

    Raises:
        DockerProxyError: If the proxy is unreachable or returns a non-200 /
            malformed response.
    """
    base = proxy_url.rstrip("/")
    # The proxy legitimately lives on the internal network, so private addresses
    # are allowed here — but a misconfigured/hostile proxy_url pointed at loopback
    # or the cloud-metadata endpoint is still refused (allow_internal keeps only
    # RFC-1918 targets in scope).
    try:
        await validate_egress_url_async(base, allow_internal=True)
    except EgressError as exc:
        raise DockerProxyError(str(exc)) from exc
    try:
        async with httpx.AsyncClient(timeout=_PROXY_TIMEOUT_SECONDS) as http:
            response = await http.get(f"{base}/images/json")
    except httpx.HTTPError as exc:
        raise DockerProxyError(f"Could not reach the Docker proxy at {base}: {exc}.") from exc

    if response.status_code != 200:
        raise DockerProxyError(
            f"Docker proxy at {base} returned HTTP {response.status_code}. "
            "Check that it is read-only with IMAGES=1 and reachable on the internal network."
        )
    try:
        payload = response.json()
    except ValueError as exc:
        raise DockerProxyError("Docker proxy returned a non-JSON response.") from exc
    return _parse_images(payload)
