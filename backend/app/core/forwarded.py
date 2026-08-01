"""Trusted-proxy resolution of the request scheme (``X-Forwarded-Proto``).

Scrye serves **plain HTTP** inside the container and is normally fronted by a
TLS-terminating reverse proxy, so the scheme the *client* actually used is only
knowable from ``X-Forwarded-Proto``. That header is attacker-controllable and is
never trusted blindly: honouring it from any peer would let a caller simply
claim HTTPS and defeat the HTTPS-enforcement check that guards the ``Secure``
session cookie.

The trust boundary is the one the deployment already configures for
``X-Forwarded-For`` — ``SCRYE_FORWARDED_ALLOW_IPS`` — so a single setting names
the proxy and both the client IP and the client's scheme follow it. An empty or
non-matching value **fails safe**: the header is ignored and the request is
treated as plain HTTP.

**Composition with uvicorn's own proxy-header handling.** ``docker/entrypoint.sh``
starts uvicorn with ``--proxy-headers --forwarded-allow-ips "$SCRYE_FORWARDED_ALLOW_IPS"``,
so in the shipped image the ASGI scope's scheme is *already* ``https`` when a
trusted proxy forwarded it. This middleware therefore only ever **upgrades** the
scheme (``http`` → ``https``) and never downgrades it, for two reasons:

1. uvicorn rewrites ``scope["client"]`` to the *forwarded client* address once it
   trusts a hop, so by the time this middleware runs the peer address is no
   longer the proxy's — a downgrade decided from it would be wrong.
2. A request that already arrived over real TLS (direct HTTPS, or a dev server
   run without ``--proxy-headers``) must never be demoted by a header.

Upgrading is safe under both conditions because it happens only for a peer the
operator explicitly listed.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from starlette.requests import Request
from starlette.types import ASGIApp, Receive, Scope, Send

#: Sentinel accepted by uvicorn's ``--forwarded-allow-ips`` meaning "trust every
#: peer". Supported here for parity with the server flag (a divergence would be
#: more confusing than the risk it avoids), but it is blanket trust and the app
#: warns loudly about it at startup. Never use it in a real deployment.
TRUST_ALL = "*"

_FORWARDED_PROTO_HEADER = b"x-forwarded-proto"

IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class TrustedProxies:
    """A parsed ``SCRYE_FORWARDED_ALLOW_IPS`` value — the forwarded-header trust boundary."""

    networks: tuple[IpNetwork, ...] = ()
    trust_all: bool = False
    raw: str = ""
    invalid: tuple[str, ...] = field(default=())

    @property
    def is_configured(self) -> bool:
        """Return True when at least one usable peer (or ``*``) was configured."""
        return self.trust_all or bool(self.networks)

    def trusts(self, host: str | None) -> bool:
        """Return True when ``host`` is a peer whose forwarded headers we honour.

        Anything that is not a parseable IP address (``None``, a hostname, the
        ``"testclient"`` placeholder, a unix-socket peer) is untrusted.
        """
        if self.trust_all:
            return True
        if not host or not self.networks:
            return False
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(address in network for network in self.networks)

    def describe(self) -> str:
        """Return a short human-readable rendering for startup logs."""
        if self.trust_all:
            return "every peer ('*')"
        if not self.networks:
            return "no peer (unset or unparseable)"
        return ", ".join(str(network) for network in self.networks)


def parse_trusted_proxies(raw: str) -> TrustedProxies:
    """Parse a comma-separated list of IPs/CIDRs into a :class:`TrustedProxies`.

    Mirrors uvicorn's ``--forwarded-allow-ips`` syntax: bare addresses become
    single-host networks, ``*`` means "trust everything", and unparseable entries
    are collected in ``invalid`` so startup can report them rather than silently
    widening or narrowing the boundary.
    """
    networks: list[IpNetwork] = []
    invalid: list[str] = []
    trust_all = False
    for entry in (part.strip() for part in raw.split(",")):
        if not entry:
            continue
        if entry == TRUST_ALL:
            trust_all = True
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            invalid.append(entry)
    return TrustedProxies(
        networks=tuple(networks), trust_all=trust_all, raw=raw, invalid=tuple(invalid)
    )


def peer_host(scope: Scope) -> str | None:
    """Return the immediate peer's address from an ASGI scope, if it has one."""
    client = scope.get("client")
    if not client:
        return None
    return str(client[0])


def request_is_secure(request: Request) -> bool:
    """Return True when the *client* reached Scrye over HTTPS.

    Reads the resolved scheme, i.e. real TLS termination at this process, or an
    ``X-Forwarded-Proto: https`` that a trusted proxy sent (applied by uvicorn's
    ``--proxy-headers`` and/or :class:`ForwardedProtoMiddleware`).
    """
    return request.url.scheme == "https"


class ForwardedProtoMiddleware:
    """Upgrade the ASGI scope's scheme from ``X-Forwarded-Proto`` for trusted peers.

    Pure-ASGI (not ``BaseHTTPMiddleware``) so it can rewrite the scope before any
    downstream code builds a ``Request`` from it, and so it adds no task-group
    overhead to every request.
    """

    def __init__(self, app: ASGIApp, trusted: TrustedProxies) -> None:
        """Wrap ``app``, honouring forwarded headers only from ``trusted`` peers."""
        self.app = app
        self.trusted = trusted

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Resolve the client scheme, then hand the request downstream."""
        if scope["type"] == "http" and scope.get("scheme") != "https":
            forwarded = self._forwarded_proto(scope)
            if forwarded == "https" and self.trusted.trusts(peer_host(scope)):
                # Never a downgrade: an already-https scheme is left alone above.
                scope["scheme"] = "https"
        await self.app(scope, receive, send)

    @staticmethod
    def _forwarded_proto(scope: Scope) -> str | None:
        """Return the originating client's protocol from ``X-Forwarded-Proto``."""
        for name, value in scope.get("headers", ()):
            if name.lower() == _FORWARDED_PROTO_HEADER:
                # A proxy chain appends, oldest first, so the left-most entry is
                # the scheme the original client used.
                return value.decode("latin-1").split(",")[0].strip().lower()
        return None
