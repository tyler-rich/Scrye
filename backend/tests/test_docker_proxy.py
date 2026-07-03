"""Tests for the read-only Docker socket-proxy client parsing."""

from __future__ import annotations

import pytest

from app.core.docker_proxy import DockerProxyError, _parse_images


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
