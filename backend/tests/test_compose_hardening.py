"""Regression guards for the hardened Compose runtime constraints.

The scanners fail at runtime with ``mkdir /tmp/trivy-XXXXXXXXX: permission
denied`` when the tmpfs ``/tmp`` is left root-owned under a non-root ``user:`` —
a freshly mounted tmpfs is owned by uid 0, so a uid-1000 process (and the
in-memory credential materialization) cannot write to it. These string-level
checks pin the ownership/volume options so that hardening can't silently regress
the next time the Compose file is edited.

The second half of this module guards the ``docker-env`` socket proxy, the only
container in the stack that mounts ``/var/run/docker.sock``: its request
allowlist must stay pinned to exactly the one endpoint the app calls.

A third group pins the resource-limit split: memory limits stay inline in
portable form, CPU limits stay in the opt-in overlay, and no ``deploy:`` key
comes back to the base file (NAS platforms reject it).
"""

from __future__ import annotations

import re
from pathlib import Path

import httpx
import pytest

from app.core.docker_proxy import list_images

DOCKER_DIR = Path(__file__).resolve().parents[2] / "docker"
COMPOSE = DOCKER_DIR / "docker-compose.yml"
CPU_LIMITS_OVERLAY = DOCKER_DIR / "docker-compose.cpu-limits.yml"


def _scrye_tmp_mount() -> str:
    """Return the scrye service's ``/tmp`` tmpfs mount line."""
    lines = [
        line.strip()
        for line in COMPOSE.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("- /tmp:")
    ]
    assert lines, "no scrye /tmp tmpfs mount (`- /tmp:...`) found in docker-compose.yml"
    return lines[0]


def test_tmp_tmpfs_is_owned_by_the_app_uid() -> None:
    mount = _scrye_tmp_mount()
    assert "uid=1000" in mount and "gid=1000" in mount, (
        "the /tmp tmpfs must be owned by the container uid (1000); a root-owned "
        f"tmpfs leaves a non-root process unable to write to /tmp: {mount!r}"
    )


def test_cache_volume_is_mounted_for_scanner_databases() -> None:
    text = COMPOSE.read_text(encoding="utf-8")
    # The writable, persistent cache volume is where the scanners' vuln DBs and
    # temp extraction land instead of the read-only $HOME/.cache or the tmpfs.
    assert "scrye_cache:/cache" in text, "the /cache volume must be mounted for scanner caches"


def test_scrye_service_has_explicit_stop_grace_period() -> None:
    # Docker's default SIGTERM->SIGKILL budget is 10s, which the in-process
    # worker/scheduler shutdown can exceed on a busy instance — the process would
    # be SIGKILLed mid-commit (CON-6). An explicit, larger grace must be pinned.
    text = COMPOSE.read_text(encoding="utf-8")
    assert "stop_grace_period:" in text, (
        "the scrye service must set an explicit stop_grace_period so a graceful "
        "shutdown is not SIGKILLed at Docker's 10s default (CON-6)"
    )


# --------------------------------------------------------------------------
# Docker socket proxy: the allowlist must cover exactly what the client calls
#
# The `docker-env` sidecar is the only container in the stack that mounts
# /var/run/docker.sock, so its request allowlist is the single most load-bearing
# security control in the Compose file. wollomatic/socket-proxy allowlists by
# regex per HTTP method (issue #63), which means the guarantee is only as good as
# that one pattern staying in sync with the one endpoint the app actually uses.
# These tests tie the two together: the pattern is compiled exactly the way the
# proxy compiles it and exercised against the path the client is *observed* to
# request, plus the sensitive paths the previous tecnativa config allowed.
# --------------------------------------------------------------------------

#: Paths the old tecnativa config permitted (IMAGES=1 / CONTAINERS=1 / INFO=1
#: plus the image's default EVENTS/PING/VERSION) that must now be refused.
PREVIOUSLY_ALLOWED_SENSITIVE_PATHS = (
    "/containers/json",
    "/containers/abc123/json",  # every container's env vars and command line
    "/containers/abc123/logs",
    "/containers/abc123/export",  # whole container filesystem as a tarball
    "/containers/abc123/archive",  # arbitrary file read out of any container
    "/v1.44/containers/abc123/json",
    "/images/abc123/get",  # image tarball export
    "/images/abc123/json",
    "/images/abc123/history",
    "/images/search",
    "/info",
    "/events",
    "/_ping",
    "/version",
)


def _proxy_allow_get_pattern() -> str:
    """Return the socket proxy's ``-allowGET=`` regex from the Compose file."""
    matches = re.findall(
        r"^\s*-\s*'?-allowGET=(.+?)'?$",
        COMPOSE.read_text(encoding="utf-8"),
        flags=re.MULTILINE,
    )
    assert len(matches) == 1, (
        "expected exactly one -allowGET entry on the socket-proxy service; each "
        f"additional entry widens the allowlist. Found: {matches!r}"
    )
    return matches[0]


def _compiled_proxy_allowlist() -> re.Pattern[str]:
    """Compile the allowlist the way socket-proxy does.

    Upstream anchors every allow pattern itself (``regexp.Compile("^"+regex+"$")``
    in ``internal/config``) and matches it against ``r.URL.Path`` only, so the
    query string never participates.
    """
    return re.compile("^" + _proxy_allow_get_pattern() + "$")


async def _observed_client_path(monkeypatch: pytest.MonkeyPatch) -> str:
    """Return the URL path ``list_images`` actually requests from the proxy."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=[])

    real_client = httpx.AsyncClient

    def factory(*args: object, **kwargs: object) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    # A literal RFC-1918 address: the egress guard permits private targets for the
    # proxy (allow_internal) and needs no DNS for an IP literal.
    await list_images("http://10.31.7.9:2375")
    assert len(seen) == 1, f"expected exactly one proxy request, got {len(seen)}"
    return seen[0].url.path


async def test_socket_proxy_allowlist_matches_the_path_the_client_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = await _observed_client_path(monkeypatch)
    assert _compiled_proxy_allowlist().match(path), (
        f"the socket proxy's -allowGET pattern does not match {path!r}, the path "
        "docker_proxy.list_images actually requests — 'scan running images' would "
        "fail with HTTP 403 from the proxy"
    )


async def test_socket_proxy_allowlist_covers_no_endpoint_the_client_does_not_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Guards the other direction: the allowlist must not have been widened past
    # the single endpoint the client uses. Anything the app never calls is a
    # gratuitous grant of Docker API access on the one socket-holding container.
    path = await _observed_client_path(monkeypatch)
    allowlist = _compiled_proxy_allowlist()
    for denied in PREVIOUSLY_ALLOWED_SENSITIVE_PATHS:
        assert denied != path
        assert not allowlist.match(denied), (
            f"the socket proxy allowlist permits {denied!r}, which Scrye never "
            "calls; the docker-env sidecar must expose only the image listing"
        )


def test_socket_proxy_allows_no_method_other_than_get() -> None:
    text = COMPOSE.read_text(encoding="utf-8")
    # socket-proxy keys its allowlist by method and answers 405 for any method
    # with no entry, so the absence of these flags is what makes the proxy
    # read-only — the equivalent of the old POST=0.
    for flag in ("-allowHEAD=", "-allowPOST=", "-allowPUT=", "-allowPATCH=", "-allowDELETE="):
        assert flag not in text, (
            f"{flag} is set on the socket proxy; only GET may be allowed so the "
            "docker-env sidecar stays strictly read-only"
        )


def test_socket_proxy_restricts_which_clients_may_connect() -> None:
    text = COMPOSE.read_text(encoding="utf-8")
    assert "-allowfrom=" in text, (
        "the socket proxy must set -allowfrom; upstream's default (127.0.0.1/32) "
        "would make it unreachable, and an unrestricted value would let anything "
        "on the Compose network reach the Docker socket"
    )
    assert "-allowfrom=0.0.0.0/0" not in text, (
        "-allowfrom=0.0.0.0/0 removes the source restriction on the one container "
        "holding the Docker socket"
    )


def test_socket_proxy_is_digest_pinned_and_unprivileged() -> None:
    text = COMPOSE.read_text(encoding="utf-8")
    image = re.search(r"^\s*image:\s*(wollomatic/socket-proxy:\S+)$", text, flags=re.MULTILINE)
    assert image, "the docker-env sidecar must use wollomatic/socket-proxy (issue #63)"
    assert "@sha256:" in image.group(
        1
    ), f"the socket proxy image must be pinned by digest, not a floating tag: {image.group(1)!r}"
    # Upstream ships USER 65534 in a from-scratch image; the compose `user:` only
    # overrides the GID so the process can read the host socket.
    assert 'user: "65534:' in text, (
        "the socket proxy must run as the unprivileged upstream uid (65534); it "
        "needs only the host docker GID to read the socket"
    )


def test_socket_proxy_needs_no_writable_filesystem() -> None:
    text = COMPOSE.read_text(encoding="utf-8")
    # The HAProxy-based predecessor required a writable /run for its pid/stats
    # socket under read_only (audit INF-5). The Go binary needs no writable path,
    # so re-introducing one would be an unexplained widening.
    assert "/run:size=" not in text, (
        "the socket proxy no longer needs a writable /run tmpfs; a from-scratch "
        "Go binary writes nothing (INF-5 retired)"
    )


# --------------------------------------------------------------------------
# Resource limits: memory inline and portable, CPU in the opt-in overlay
#
# The stack used to cap CPU and memory through `deploy.resources`. Compose v2
# honours that block standalone, but it is Swarm-oriented and several NAS
# container platforms (Synology Container Manager, QNAP Container Station)
# reject or mishandle `deploy:` keys outright, so the base file would not deploy
# there at all. Memory limits — the ones that bound an OOM blast radius, and that
# bound the RAM-backed /tmp tmpfs — moved to the portable `mem_limit` /
# `mem_reservation` keys and stayed on by default; the CPU caps moved to
# docker-compose.cpu-limits.yml, applied with a second `-f`.
#
# These guard both halves of that split: the base file must stay `deploy:`-free
# and keep its memory caps, and the overlay must keep a CPU cap for every service
# rather than quietly losing one.
# --------------------------------------------------------------------------

#: Memory cap every service must carry inline in the base Compose file.
EXPECTED_MEM_LIMITS = {"scrye": "2g", "trivy-server": "1g", "docker-socket-proxy": "64m"}

#: CPU cap the opt-in overlay must keep for each of those services.
EXPECTED_CPU_LIMITS = {"scrye": "2.0", "trivy-server": "1.0", "docker-socket-proxy": "0.5"}


def _service_blocks(path: Path) -> dict[str, str]:
    """Split a Compose file's ``services:`` mapping into per-service text blocks.

    Deliberately string-level, like the rest of this module: these tests exist to
    catch an edit to the checked-in YAML, and a hand-rolled split keeps them free
    of a YAML parser the backend does not otherwise depend on. Full-line comments
    are dropped so prose about a limit can't stand in for the limit itself.
    """
    blocks: dict[str, list[str]] = {}
    current: str | None = None
    in_services = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.rstrip() == "services:":
            in_services = True
            continue
        if not in_services or not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            break  # a new top-level key (networks:, volumes:, secrets:) ends services
        service = re.match(r"^  ([A-Za-z0-9_.-]+):\s*$", line)
        if service:
            current = service.group(1)
            blocks[current] = []
        elif current is not None:
            blocks[current].append(line)
    return {name: "\n".join(body) for name, body in blocks.items()}


def _overlay_text() -> str:
    """Return the CPU-limit overlay's text, failing clearly if it was deleted."""
    assert CPU_LIMITS_OVERLAY.is_file(), (
        f"{CPU_LIMITS_OVERLAY.name} is missing. CPU limits were moved into this "
        "opt-in overlay rather than deleted; removing the file drops the caps"
    )
    return CPU_LIMITS_OVERLAY.read_text(encoding="utf-8")


def test_base_compose_declares_no_deploy_key() -> None:
    # `deploy:` in the base file is what breaks deployment on the NAS container
    # platforms; the whole point of the split is that this file parses anywhere.
    offenders = [
        line
        for line in COMPOSE.read_text(encoding="utf-8").splitlines()
        if re.match(r"^\s*deploy:\s*$", line)
    ]
    assert not offenders, (
        "docker-compose.yml declares a `deploy:` block again. Swarm-oriented "
        "`deploy:` keys are rejected or mishandled by Synology Container Manager "
        "and QNAP Container Station; use `mem_limit`/`mem_reservation` here and "
        "put CPU caps in docker-compose.cpu-limits.yml"
    )


def test_base_compose_pins_a_portable_memory_limit_for_every_service() -> None:
    blocks = _service_blocks(COMPOSE)
    assert set(blocks) == set(EXPECTED_MEM_LIMITS), (
        "the services in docker-compose.yml no longer match the ones with a pinned "
        f"memory cap: {sorted(blocks)} vs {sorted(EXPECTED_MEM_LIMITS)}. A new "
        "service needs a mem_limit (and a cpus entry in the overlay), not an exemption"
    )
    for service, expected in EXPECTED_MEM_LIMITS.items():
        assert f"mem_limit: {expected}" in blocks[service], (
            f"the {service} service must keep `mem_limit: {expected}`. Memory is the "
            "containment control that stays on by default — it bounds the OOM blast "
            "radius, and the RAM-backed /tmp tmpfs counts against it"
        )


def test_scrye_service_keeps_its_memory_reservation() -> None:
    assert "mem_reservation: 256m" in _service_blocks(COMPOSE)["scrye"], (
        "the scrye service must keep its memory reservation; it moved out of "
        "`deploy.resources.reservations` and must not have been dropped on the way"
    )


def test_cpu_limit_overlay_caps_every_service_the_base_file_defines() -> None:
    _overlay_text()  # fail with the "overlay is missing" message, not a parse error
    overlay = _service_blocks(CPU_LIMITS_OVERLAY)
    assert set(overlay) == set(EXPECTED_CPU_LIMITS) == set(_service_blocks(COMPOSE)), (
        "the CPU overlay and the base Compose file describe different services: "
        f"{sorted(overlay)} vs {sorted(_service_blocks(COMPOSE))}. Every service "
        "must be capped, so a service added to one file must be added to both"
    )
    for service, expected in EXPECTED_CPU_LIMITS.items():
        assert (
            f"cpus: {expected}" in overlay[service]
        ), f"the {service} entry in {CPU_LIMITS_OVERLAY.name} must keep `cpus: {expected}`"


def test_cpu_limit_overlay_uses_the_portable_cpus_key() -> None:
    # Two reasons this must not become a `deploy.resources.limits.cpus` block:
    # more Compose implementations accept the bare `cpus:` key, and Compose
    # *rejects* the merged project outright when an overlay's
    # `deploy.resources.limits` meets the base file's `mem_limit`
    # ("can't set distinct values on 'mem_limit' and
    # 'deploy.resources.limits.memory'"), so the overlay would not apply at all.
    offenders = [
        line for line in _overlay_text().splitlines() if re.match(r"^\s*deploy:\s*$", line)
    ]
    assert not offenders, (
        f"{CPU_LIMITS_OVERLAY.name} must express CPU caps with the portable `cpus:` "
        "key; a `deploy.resources.limits` block collides with the base file's "
        "`mem_limit` and makes the merged project invalid"
    )


ENTRYPOINT = Path(__file__).resolve().parents[2] / "docker" / "entrypoint.sh"


def test_forwarded_allow_ips_default_is_not_wildcard() -> None:
    # Security hotfix: uvicorn --forwarded-allow-ips must NOT default to "*".
    # Trusting every upstream hop lets a client spoof X-Forwarded-For (bypassing
    # the auth rate limiter and forging audit-log IPs). The default must be a
    # bounded trusted range (the Docker bridge Caddy connects from), overridable
    # via SCRYE_FORWARDED_ALLOW_IPS.
    text = ENTRYPOINT.read_text(encoding="utf-8")
    assert "--forwarded-allow-ips" in text, "entrypoint must set --forwarded-allow-ips"
    assert '"${SCRYE_FORWARDED_ALLOW_IPS:-*}"' not in text, (
        "the forwarded-allow-ips default must not be the wildcard '*' — it enables "
        "X-Forwarded-For spoofing behind the reverse proxy"
    )
    assert "SCRYE_FORWARDED_ALLOW_IPS" in text, "the trusted range must stay operator-overridable"
