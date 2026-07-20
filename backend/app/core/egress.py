"""Outbound-egress guard for admin-configured fetch targets (SEC-6 / SSRF).

Several server-side fetchers take an admin-supplied URL or host — the
notification transports (webhook / Discord / Matrix / SMTP), the registry
connectivity probe, and the read-only Docker socket proxy. Without a destination
check they can be pointed at the cloud metadata endpoint
(``169.254.169.254``), loopback, or an internal service: a classic SSRF surface,
even though these actions are admin-gated and CSRF-protected.

This module resolves a target host and refuses:

- **always** — loopback, link-local (which includes the cloud metadata IP),
  multicast, unspecified, and otherwise-reserved addresses; these are never a
  legitimate notification/registry destination;
- **by default** — RFC-1918 / ULA / CGNAT private addresses, unless the operator
  has explicitly enabled ``SCRYE_ALLOW_INTERNAL_EGRESS`` (self-hosted
  deployments commonly run an internal SMTP relay or private registry).

The Docker socket proxy legitimately targets an internal sidecar, so it passes
``allow_internal=True`` — private is permitted there, but loopback/metadata is
still refused.

Resolution happens here and httpx re-resolves when it connects, so this is a
best-effort, defense-in-depth control (not DNS-rebinding-proof), which is
appropriate for an admin-gated surface.
"""

from __future__ import annotations

import functools
import ipaddress
import socket
from urllib.parse import urlparse

import anyio.to_thread

_ALLOWED_SCHEMES = frozenset({"http", "https"})

_IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class EgressError(ValueError):
    """Raised when an outbound target resolves to a disallowed address.

    Subclasses :class:`ValueError` so notification transports' existing
    ``except ValueError`` handler surfaces it as a clean, secret-free failure.
    """


def _blocked_reason(ip: _IPAddress, *, allow_internal: bool) -> str | None:
    """Return why ``ip`` is disallowed, or ``None`` if it is an allowed target."""
    # Classify IPv4-mapped IPv6 (e.g. ::ffff:169.254.169.254) as its IPv4 form.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local/metadata"
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_reserved:
        return "reserved"
    if ip.is_private and not allow_internal:
        return "private/internal"
    return None


def _resolve(host: str) -> list[_IPAddress]:
    """Resolve ``host`` to every address it maps to (IP literals pass through)."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise EgressError(f"could not resolve host {host!r}: {exc}") from exc
    addrs = [ipaddress.ip_address(info[4][0]) for info in infos]
    if not addrs:
        raise EgressError(f"host {host!r} did not resolve to any address")
    return addrs


def validate_egress_host(host: str | None, *, allow_internal: bool = False) -> None:
    """Refuse ``host`` if any resolved address is a disallowed target.

    Args:
        host: The target hostname or IP literal.
        allow_internal: Permit RFC-1918 / ULA / CGNAT private addresses (used by
            the Docker proxy, which targets an internal sidecar). Loopback and
            link-local/metadata are refused regardless.

    Raises:
        EgressError: If the host is empty, unresolvable, or resolves to a
            disallowed address.
    """
    if not host:
        raise EgressError("no target host in the configured URL")
    for ip in _resolve(host):
        reason = _blocked_reason(ip, allow_internal=allow_internal)
        if reason is None:
            continue
        message = f"refusing to connect to {reason} address {ip} (host {host!r})"
        if reason == "private/internal":
            message += "; set SCRYE_ALLOW_INTERNAL_EGRESS=1 to allow internal targets"
        raise EgressError(message)


def validate_egress_url(url: str, *, allow_internal: bool = False) -> str:
    """Validate a URL's scheme and destination host; return the URL unchanged.

    Raises:
        EgressError: On a non-http(s) scheme or a disallowed destination.
    """
    parsed = urlparse(url)
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        raise EgressError(
            f"unsupported URL scheme {parsed.scheme!r} for {url!r}; only http/https are allowed"
        )
    validate_egress_host(parsed.hostname, allow_internal=allow_internal)
    return url


async def validate_egress_url_async(url: str, *, allow_internal: bool = False) -> str:
    """Async wrapper for :func:`validate_egress_url` (offloads DNS resolution)."""
    return await anyio.to_thread.run_sync(
        functools.partial(validate_egress_url, url, allow_internal=allow_internal)
    )
