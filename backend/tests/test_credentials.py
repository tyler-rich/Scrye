"""Tests for transient scan-time credential materialization.

Covers the security-critical behavior in ``app.scanners.credentials``: the
Docker config document shape (auths vs credHelpers), that the transient config
file is written then **shredded** (removed) on context exit, git auth resolution
per provider, and that credential-embedded clone URLs are redacted from logs.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from app.core.logging import redact, strip_url_credentials
from app.db.models import GitProvider, RegistryAuthType
from app.scanners.credentials import (
    GitAuth,
    RegistryAuth,
    build_docker_config,
    docker_config_env,
    git_clone_auth,
)


def test_build_docker_config_username_password() -> None:
    auth = RegistryAuth(
        registry_host="ghcr.io",
        auth_type=RegistryAuthType.USERNAME_PASSWORD,
        username="alice",
        secret="s3cr3t",
    )
    config = build_docker_config(auth)
    blob = config["auths"]["ghcr.io"]["auth"]
    assert base64.b64decode(blob).decode() == "alice:s3cr3t"


def test_build_docker_config_token_defaults_username() -> None:
    auth = RegistryAuth(
        registry_host="registry.example.com",
        auth_type=RegistryAuthType.TOKEN,
        secret="tok",
    )
    blob = build_docker_config(auth)["auths"]["registry.example.com"]["auth"]
    assert base64.b64decode(blob).decode() == "token:tok"


def test_build_docker_config_credential_helper() -> None:
    auth = RegistryAuth(
        registry_host="123.dkr.ecr.us-east-1.amazonaws.com",
        auth_type=RegistryAuthType.AWS_ECR,
    )
    config = build_docker_config(auth)
    assert config == {"credHelpers": {auth.registry_host: "ecr-login"}}
    assert "auths" not in config


def test_build_docker_config_requires_secret_for_static_auth() -> None:
    auth = RegistryAuth(registry_host="x", auth_type=RegistryAuthType.TOKEN)
    with pytest.raises(ValueError):
        build_docker_config(auth)


def test_docker_config_env_materializes_then_shreds() -> None:
    auth = RegistryAuth(
        registry_host="ghcr.io",
        auth_type=RegistryAuthType.USERNAME_PASSWORD,
        username="alice",
        secret="s3cr3t",
    )
    captured_dir: str | None = None
    with docker_config_env(auth) as env:
        captured_dir = env["DOCKER_CONFIG"]
        config_file = Path(captured_dir) / "config.json"
        assert config_file.is_file()
        # File is mode 0600 (owner-only).
        assert (config_file.stat().st_mode & 0o777) == 0o600
        document = json.loads(config_file.read_text())
        assert document["auths"]["ghcr.io"]["auth"]
    # After the context exits the whole directory is gone (shredded).
    assert captured_dir is not None
    assert not Path(captured_dir).exists()


def test_docker_config_env_shreds_on_exception() -> None:
    auth = RegistryAuth(
        registry_host="ghcr.io",
        auth_type=RegistryAuthType.TOKEN,
        secret="tok",
    )
    captured_dir: str | None = None
    with pytest.raises(RuntimeError):
        with docker_config_env(auth) as env:
            captured_dir = env["DOCKER_CONFIG"]
            raise RuntimeError("boom")
    assert captured_dir is not None
    assert not Path(captured_dir).exists()


def test_git_clone_auth_github_uses_env_token() -> None:
    url, env = git_clone_auth(
        "https://github.com/org/repo.git",
        GitAuth(provider=GitProvider.GITHUB, token="ghp_x"),
    )
    assert url == "https://github.com/org/repo.git"  # unchanged; no creds in URL
    assert env == {"GITHUB_TOKEN": "ghp_x"}


def test_git_clone_auth_gitlab_uses_env_token() -> None:
    url, env = git_clone_auth(
        "https://gitlab.com/org/repo.git",
        GitAuth(provider=GitProvider.GITLAB, token="glpat"),
    )
    assert env == {"GITLAB_TOKEN": "glpat"}
    assert "glpat" not in url


def test_git_clone_auth_generic_embeds_credentials() -> None:
    url, env = git_clone_auth(
        "https://git.example.com/team/repo.git",
        GitAuth(provider=GitProvider.GENERIC, token="tok", username="deploy"),
    )
    assert env == {}
    assert url == "https://deploy:tok@git.example.com/team/repo.git"


def test_git_clone_auth_generic_without_username() -> None:
    url, _ = git_clone_auth(
        "https://git.example.com/team/repo.git",
        GitAuth(provider=GitProvider.GENERIC, token="tok"),
    )
    assert url == "https://tok@git.example.com/team/repo.git"


def test_git_clone_auth_leaves_non_http_scheme_alone() -> None:
    url, _ = git_clone_auth(
        "ssh://git@host/repo.git",
        GitAuth(provider=GitProvider.GENERIC, token="tok"),
    )
    assert url == "ssh://git@host/repo.git"


def test_url_credentials_are_redacted_from_logs() -> None:
    text = "cloning https://deploy:tok@git.example.com/team/repo.git failed"
    assert "tok" not in strip_url_credentials(text)
    assert "tok" not in redact(text)
    assert "git.example.com" in strip_url_credentials(text)  # host preserved
