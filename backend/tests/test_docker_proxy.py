"""Tests for the read-only Docker socket-proxy client parsing and error reporting."""

from __future__ import annotations

import httpx
import pytest

from app.core.docker_proxy import DockerProxyError, _parse_images, list_images


def test_parse_images_keeps_tagged_and_drops_untagged() -> None:
    payload = [
        {"Id": "sha256:aaa", "RepoTags": ["alpine:3.19", "alpine:latest"], "Size": 5000000},
        {"Id": "sha256:bbb", "RepoTags": ["<none>:<none>"], "Size": 100},
        {"Id": "sha256:ccc", "RepoTags": None, "Size": 200},
    ]
    images = _parse_images(payload)
    assert len(images) == 1
    assert images[0].id == "sha256:aaa"
    assert images[0].tags == ["alpine:3.19", "alpine:latest"]
    assert images[0].size_bytes == 5000000


def test_parse_images_rejects_non_list() -> None:
    with pytest.raises(DockerProxyError):
        _parse_images({"not": "a list"})


async def test_non_200_message_points_at_the_wollomatic_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 403 is the case operators actually hit, so the detail must name its causes.

    The sidecar has been ``wollomatic/socket-proxy`` since 2026-07-24; the message
    must not send anyone looking for tecnativa's ``IMAGES=1`` env var, which no
    longer exists.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="")

    real_client = httpx.AsyncClient

    def factory(*args: object, **kwargs: object) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    # A literal RFC-1918 address: the egress guard permits private targets for the
    # proxy (allow_internal) and needs no DNS for an IP literal.
    with pytest.raises(DockerProxyError) as excinfo:
        await list_images("http://10.31.7.9:2375")

    message = str(excinfo.value)
    assert "IMAGES=1" not in message
    assert "HTTP 403" in message
    assert "-allowGET" in message
    assert "-allowfrom" in message
    assert "forbidden IP" in message
