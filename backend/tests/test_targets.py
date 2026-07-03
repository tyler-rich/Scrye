"""Tests for scan-time target and credential resolution."""

from __future__ import annotations

import pytest

from app.core import config
from app.core.secret_store import AAD_GIT_TOKEN, AAD_REGISTRY_SECRET, encrypt_secret
from app.db.models import GitCredential, GitProvider, Registry, RegistryAuthType
from app.scanners import targets
from app.scanners.targets import (
    TargetError,
    resolve_filesystem_path,
    resolve_git_auth,
    resolve_registry_auth,
)


def test_resolve_registry_auth_decrypts_secret(db) -> None:
    registry = Registry(
        name="ghcr",
        registry_host="ghcr.io",
        auth_type=RegistryAuthType.USERNAME_PASSWORD,
        username="alice",
        secret_ciphertext=encrypt_secret("s3cr3t", aad=AAD_REGISTRY_SECRET),
        enabled=True,
    )
    db.add(registry)
    db.commit()

    auth = resolve_registry_auth(db, {"registry_id": registry.id})
    assert auth is not None
    assert auth.registry_host == "ghcr.io"
    assert auth.username == "alice"
    assert auth.secret == "s3cr3t"


def test_resolve_registry_auth_none_without_id(db) -> None:
    assert resolve_registry_auth(db, {}) is None


def test_resolve_registry_auth_rejects_disabled(db) -> None:
    registry = Registry(
        name="off",
        registry_host="ghcr.io",
        auth_type=RegistryAuthType.TOKEN,
        secret_ciphertext=encrypt_secret("t", aad=AAD_REGISTRY_SECRET),
        enabled=False,
    )
    db.add(registry)
    db.commit()
    with pytest.raises(TargetError):
        resolve_registry_auth(db, {"registry_id": registry.id})


def test_resolve_registry_auth_helper_needs_no_secret(db) -> None:
    registry = Registry(
        name="ecr",
        registry_host="123.dkr.ecr.us-east-1.amazonaws.com",
        auth_type=RegistryAuthType.AWS_ECR,
        enabled=True,
    )
    db.add(registry)
    db.commit()
    auth = resolve_registry_auth(db, {"registry_id": registry.id})
    assert auth is not None and auth.secret is None


def test_resolve_git_auth_decrypts_token(db) -> None:
    credential = GitCredential(
        name="gh",
        provider=GitProvider.GITHUB,
        token_ciphertext=encrypt_secret("ghp_x", aad=AAD_GIT_TOKEN),
    )
    db.add(credential)
    db.commit()
    auth = resolve_git_auth(db, {"git_credential_id": credential.id})
    assert auth is not None
    assert auth.provider is GitProvider.GITHUB
    assert auth.token == "ghp_x"


def test_resolve_git_auth_missing_credential(db) -> None:
    with pytest.raises(TargetError):
        resolve_git_auth(db, {"git_credential_id": 9999})


def test_resolve_filesystem_disabled_by_default(monkeypatch) -> None:
    monkeypatch.setattr(targets, "get_settings", lambda: config.Settings(filesystem_scan_roots=[]))
    with pytest.raises(TargetError):
        resolve_filesystem_path("/anything")


def test_resolve_filesystem_rejects_out_of_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    monkeypatch.setattr(
        targets, "get_settings", lambda: config.Settings(filesystem_scan_roots=[str(root)])
    )
    with pytest.raises(TargetError):
        resolve_filesystem_path(str(tmp_path / "outside"))


def test_resolve_filesystem_accepts_path_within_root(monkeypatch, tmp_path) -> None:
    root = tmp_path / "allowed"
    sub = root / "project"
    sub.mkdir(parents=True)
    monkeypatch.setattr(
        targets, "get_settings", lambda: config.Settings(filesystem_scan_roots=[str(root)])
    )
    assert resolve_filesystem_path(str(sub)) == str(sub.resolve())
