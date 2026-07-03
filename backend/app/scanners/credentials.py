"""Transient credential materialization for scan-time authentication.

Per the locked secrets design (docs/PLAN.md §4.2, §6), stored credentials are
decrypted **only at scan time**, materialized into short-lived files under the
container's **tmpfs** ``/tmp`` mount, used to authenticate the scanner
subprocess, and then **shredded** immediately after. Nothing here touches the
database or persists plaintext.

Two mechanisms:

- **Container registries** (Trivy/Grype image scans) authenticate through a
  Docker config file. :func:`docker_config_env` writes a transient
  ``config.json`` (an ``auths`` blob for static creds/tokens, or a
  ``credHelpers`` entry for ECR/GCR/ACR) into tmpfs, yields
  ``{"DOCKER_CONFIG": <dir>}`` for the subprocess environment, and shreds the
  directory on exit.
- **Private git repositories** (Trivy ``repo`` scans) authenticate via the
  provider's documented env token, or — for a generic host — a credential
  embedded in the HTTPS clone URL. :func:`git_clone_auth` returns the (possibly
  rewritten) URL plus any env overlay; the credential is never written to disk.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import shutil
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlparse, urlunparse

from app.db.models import CREDENTIAL_HELPERS, GitProvider, RegistryAuthType

#: Default username when a token-auth registry has no explicit username.
_DEFAULT_TOKEN_USERNAME = "token"


@dataclass(frozen=True)
class RegistryAuth:
    """Resolved (plaintext, scan-time) registry credential.

    ``secret`` is ``None`` for credential-helper auth types, which delegate to a
    helper binary rather than carrying a stored secret.
    """

    registry_host: str
    auth_type: RegistryAuthType
    username: str | None = None
    secret: str | None = None


@dataclass(frozen=True)
class GitAuth:
    """Resolved (plaintext, scan-time) git credential."""

    provider: GitProvider
    token: str
    username: str | None = None


def build_docker_config(auth: RegistryAuth) -> dict:
    """Build the Docker ``config.json`` document for a registry credential.

    Args:
        auth: The resolved registry credential.

    Returns:
        A dict serializable to a Docker ``config.json``: an ``auths`` entry for
        static creds/tokens, or a ``credHelpers`` entry for helper-based auth.

    Raises:
        ValueError: If a secret-bearing auth type is missing its secret.
    """
    helper = CREDENTIAL_HELPERS.get(auth.auth_type)
    if helper is not None:
        return {"credHelpers": {auth.registry_host: helper}}

    if auth.secret is None:
        raise ValueError(f"Auth type {auth.auth_type.value!r} requires a secret.")
    username = auth.username or (
        _DEFAULT_TOKEN_USERNAME if auth.auth_type is RegistryAuthType.TOKEN else ""
    )
    blob = base64.b64encode(f"{username}:{auth.secret}".encode()).decode("ascii")
    return {"auths": {auth.registry_host: {"auth": blob}}}


def _shred_file(path: Path) -> None:
    """Best-effort secure delete: overwrite the file's bytes, then unlink it."""
    with contextlib.suppress(OSError):
        length = path.stat().st_size
        if length:
            with open(path, "r+b") as handle:
                handle.write(os.urandom(length))
                handle.flush()
                os.fsync(handle.fileno())
    with contextlib.suppress(OSError):
        path.unlink()


@contextlib.contextmanager
def docker_config_env(auth: RegistryAuth) -> Iterator[dict[str, str]]:
    """Materialize a transient Docker config and yield the subprocess env overlay.

    Writes ``config.json`` (mode ``0600``) into a fresh tmpfs directory, yields
    ``{"DOCKER_CONFIG": <dir>}`` for the scanner subprocess, and shreds the file
    and directory on exit — including when the scan is cancelled or raises.

    Args:
        auth: The resolved registry credential.

    Yields:
        An environment overlay pointing Docker-aware scanners at the config.
    """
    tmpdir = Path(tempfile.mkdtemp(prefix="scrye-dockercfg-"))
    config_path = tmpdir / "config.json"
    try:
        payload = json.dumps(build_docker_config(auth)).encode("utf-8")
        # O_CREAT with 0600 so the credential file is never group/world readable.
        fd = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
        yield {"DOCKER_CONFIG": str(tmpdir)}
    finally:
        _shred_file(config_path)
        with contextlib.suppress(OSError):
            shutil.rmtree(tmpdir, ignore_errors=True)


def _embed_git_credentials(url: str, username: str | None, token: str) -> str:
    """Return ``url`` with ``username:token`` (or ``token``) embedded as userinfo.

    Only HTTPS/HTTP URLs are rewritten; any other scheme is returned unchanged
    (SSH and similar do not carry HTTP userinfo).
    """
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return url
    safe_token = quote(token, safe="")
    userinfo = f"{quote(username, safe='')}:{safe_token}" if username else safe_token
    host = parsed.hostname
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return urlunparse(parsed._replace(netloc=f"{userinfo}@{host}"))


def git_clone_auth(url: str, auth: GitAuth) -> tuple[str, dict[str, str]]:
    """Resolve git authentication for a private ``trivy repo`` clone.

    Args:
        url: The clean HTTPS repository URL (as stored and displayed).
        auth: The resolved git credential.

    Returns:
        A tuple ``(clone_url, env_overlay)``. For GitHub/GitLab the URL is
        unchanged and the token is supplied via the provider's env var; for a
        generic host the credential is embedded in the returned URL and the env
        overlay is empty. The returned URL may contain the token, so callers
        must not log or store it — pass the original ``url`` for display.
    """
    if auth.provider is GitProvider.GITHUB:
        return url, {"GITHUB_TOKEN": auth.token}
    if auth.provider is GitProvider.GITLAB:
        return url, {"GITLAB_TOKEN": auth.token}
    return _embed_git_credentials(url, auth.username, auth.token), {}
