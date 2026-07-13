"""Tests for the outbound-egress SSRF guard (SEC-6)."""

from __future__ import annotations

import asyncio

import pytest

import app.core.docker_proxy as docker_proxy
import app.core.registry_check as registry_check
from app.core.egress import EgressError, validate_egress_host, validate_egress_url


class TestEgressGuard:
    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1:8089/x",  # loopback (the app itself)
            "http://[::1]/x",  # IPv6 loopback
            "http://169.254.169.254/latest/meta-data/",  # cloud metadata
            "http://10.0.0.5:2375/",  # RFC-1918
            "http://192.168.1.10/",  # RFC-1918
            "http://172.16.0.9/",  # RFC-1918
        ],
    )
    def test_internal_targets_blocked_by_default(self, url: str) -> None:
        with pytest.raises(EgressError):
            validate_egress_url(url)

    @pytest.mark.parametrize("url", ["https://8.8.8.8/", "http://1.1.1.1/v2/"])
    def test_public_targets_allowed(self, url: str) -> None:
        assert validate_egress_url(url) == url

    def test_non_http_scheme_rejected(self) -> None:
        with pytest.raises(EgressError, match="scheme"):
            validate_egress_url("ftp://8.8.8.8/")

    def test_private_allowed_only_with_allow_internal(self) -> None:
        with pytest.raises(EgressError, match="private/internal"):
            validate_egress_host("10.1.2.3")
        # allow_internal permits RFC-1918 targets (internal SMTP / registry).
        validate_egress_host("10.1.2.3", allow_internal=True)

    def test_metadata_blocked_even_with_allow_internal(self) -> None:
        # allow_internal re-permits private ranges but NEVER loopback/metadata.
        with pytest.raises(EgressError, match="link-local/metadata"):
            validate_egress_host("169.254.169.254", allow_internal=True)
        with pytest.raises(EgressError, match="loopback"):
            validate_egress_host("127.0.0.1", allow_internal=True)

    def test_empty_host_rejected(self) -> None:
        with pytest.raises(EgressError):
            validate_egress_host("")


class TestFetcherIntegration:
    def test_registry_probe_refuses_metadata_host(self) -> None:
        result = asyncio.run(
            registry_check.check_registry(
                registry_host="https://169.254.169.254", username="u", secret="s"
            )
        )
        assert result.ok is False
        assert "metadata" in result.detail.lower() or "link-local" in result.detail.lower()

    def test_docker_proxy_refuses_loopback(self) -> None:
        with pytest.raises(docker_proxy.DockerProxyError, match="loopback"):
            asyncio.run(docker_proxy.list_images("http://127.0.0.1:2375"))

    def test_docker_proxy_refuses_metadata(self) -> None:
        with pytest.raises(docker_proxy.DockerProxyError):
            asyncio.run(docker_proxy.list_images("http://169.254.169.254:2375"))
