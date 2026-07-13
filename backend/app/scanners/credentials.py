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
- **Private git repositories** (Trivy ``repo`` scans) authenticate by provider.
  GitHub/GitLab use Trivy's native ``GITHUB_TOKEN`` / ``GITLAB_TOKEN`` env vars
  (:func:`git_env_token`); the token rides in the child environment, never in
  argv. A **generic** host has no such env channel — and Trivy clones with
  ``go-git``, which ignores ``GIT_ASKPASS`` / credential helpers / ``.netrc`` —
  so :func:`generic_repo_checkout` clones it ourselves with the system ``git``
  binary: the credential is delivered through a transient tmpfs ``GIT_ASKPASS``
  helper (never in argv, never persisted), and Trivy then scans the local
  checkout. See docs/PLAN.md §14 (Phase 3 Security Review #2 resolution).
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import shutil
import tempfile
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from app.core.config import get_settings
from app.db.models import CREDENTIAL_HELPERS, GitProvider, RegistryAuthType
from app.scanners.base import SCRATCH_SUBDIR, ScannerError, run_command

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


def is_http_url(url: str) -> bool:
    """Return True when ``url`` uses an ``http``/``https`` scheme."""
    return urlparse(url).scheme in {"http", "https"}


def is_remote_repo_url(url: str) -> bool:
    """Return True when ``url`` is a remote git clone URL, not a local path.

    A repository scan runs ``trivy repo`` against the target, and Trivy's ``repo``
    subcommand accepts a **local filesystem path**, not just a remote URL. A bare
    path like ``/data`` or ``/run/secrets`` would make Trivy walk the container
    filesystem and surface its contents as downloadable scan output, bypassing the
    ``SCRYE_FILESYSTEM_SCAN_ROOTS`` allowlist that gates local-path scanning. Only
    a target with a remote clone scheme — ``http``/``https`` (see
    :func:`is_http_url`), ``ssh``, or ``git`` — is a genuine remote repository.
    """
    return is_http_url(url) or urlparse(url).scheme in {"ssh", "git"}


def git_env_token(auth: GitAuth) -> dict[str, str]:
    """Return Trivy's native token env overlay for a hosted git provider.

    GitHub/GitLab clones authenticate through the ``GITHUB_TOKEN`` /
    ``GITLAB_TOKEN`` variables Trivy reads — the token stays in the child
    environment and never touches the process argv. Generic hosts have no such
    variable and are handled by :func:`generic_repo_checkout` instead, so this
    returns an empty overlay for them.

    Args:
        auth: The resolved git credential.

    Returns:
        ``{"GITHUB_TOKEN": ...}`` / ``{"GITLAB_TOKEN": ...}``, or ``{}``.
    """
    if auth.provider is GitProvider.GITHUB:
        return {"GITHUB_TOKEN": auth.token}
    if auth.provider is GitProvider.GITLAB:
        return {"GITLAB_TOKEN": auth.token}
    return {}


#: GIT_ASKPASS helper. It carries no secret itself — it echoes the credential
#: from the clone subprocess's own environment (which git passes to the askpass
#: child), so the token never appears in argv, in the script file, or in the
#: parent process environment. git *execs* this program, so the file must be
#: executable (0700), not a plain 0600 data file.
_ASKPASS_SCRIPT = (
    "#!/bin/sh\n"
    'case "$1" in\n'
    "  Username*) printf '%s' \"$SCRYE_GIT_USERNAME\" ;;\n"
    "  Password*) printf '%s' \"$SCRYE_GIT_PASSWORD\" ;;\n"
    "esac\n"
)

#: Per-scan option keys that select a git ref. Our clone materializes the ref
#: directly, so they are stripped before Trivy scans the local checkout.
REPO_REF_KEYS = ("branch", "commit", "tag")


async def _run_git_clone(
    url: str, options: dict, checkout: Path, *, env: dict[str, str], timeout: int
) -> None:
    """Clone ``url`` into ``checkout`` at the requested ref, credential off-argv.

    The clean ``url`` (no embedded credential) is the only URL on argv; the
    credential reaches ``git`` solely through ``env`` (the ``GIT_ASKPASS`` helper
    and its ``SCRYE_GIT_*`` inputs).

    Raises:
        ScannerError: If ``git`` is missing, the clone/checkout fails, or it
            times out. The message is operator-safe and never echoes git's
            stderr (which can contain the request URL).
    """
    ref = options.get("branch") or options.get("tag")
    commit = options.get("commit")
    argv = ["git", "clone", "--quiet"]
    if not commit:
        # Shallow-clone the tip (optionally of a named branch/tag). A specific
        # commit may not be at any tip, so that case clones fully then checks out.
        argv += ["--depth", "1"]
        if ref:
            argv += ["--branch", str(ref)]
    argv += ["--", url, str(checkout)]

    result = await run_command(argv, timeout=timeout, env=env)
    if result.returncode != 0:
        raise ScannerError(
            "Failed to clone the private repository. Check the URL, ref, and credential."
        )
    if commit:
        checked_out = await run_command(
            ["git", "-C", str(checkout), "checkout", "--quiet", str(commit)],
            timeout=timeout,
            env=env,
        )
        if checked_out.returncode != 0:
            raise ScannerError("Failed to check out the requested commit in the repository.")


@contextlib.asynccontextmanager
async def generic_repo_checkout(
    url: str, auth: GitAuth, options: dict, *, timeout: int
) -> AsyncIterator[str]:
    """Clone a generic-host private repo and yield the checkout path.

    Materializes a transient ``GIT_ASKPASS`` helper (mode ``0700``) in a fresh
    RAM-backed **tmpfs** directory (the credential never touches disk), clones
    ``url`` with the system ``git`` binary — the credential travels only in the
    clone subprocess environment, never in argv — checks out the requested ref,
    and yields the local checkout for Trivy to scan. Both directories are shredded
    and removed on exit, including when the clone or the subsequent scan raises or
    is cancelled.

    The **checkout** is placed on the writable ``/cache`` scratch volume, not the
    tmpfs ``/tmp``: a repository working tree can be arbitrarily large, and the
    tmpfs is a small (200 MB) RAM-backed mount whose size counts against the
    container memory limit, so a large clone there would ``ENOSPC`` / risk an OOM
    (the same hardened-runtime constraint that routes the scanner caches to
    ``/cache``). The tiny credential helper stays in tmpfs.

    Args:
        url: The clean HTTPS repository URL (as stored and displayed).
        auth: The resolved generic-host git credential.
        options: The scan options (read for the branch/commit/tag ref).
        timeout: Per-operation wall-clock timeout in seconds.

    Yields:
        The absolute path of the local checkout.
    """
    # Credential helper: RAM-backed tmpfs (default temp dir), never disk.
    cred_dir = Path(tempfile.mkdtemp(prefix="scrye-gitcred-"))
    script_path = cred_dir / "askpass.sh"
    # Checkout: the disk-backed cache volume, sized for large working trees.
    scratch_root = get_settings().scanner_cache_dir / SCRATCH_SUBDIR
    scratch_root.mkdir(parents=True, exist_ok=True)
    clone_dir = Path(tempfile.mkdtemp(prefix="scrye-gitclone-", dir=scratch_root))
    checkout = clone_dir / "checkout"
    try:
        # 0700: git *execs* the askpass helper, so it must be executable; still
        # owner-only, never group/world readable or executable.
        fd = os.open(script_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o700)
        with os.fdopen(fd, "w") as handle:
            handle.write(_ASKPASS_SCRIPT)

        # Mirror the historical URL-userinfo semantics: with a username, it is the
        # basic-auth user and the token is the password; without one, the token
        # itself is the user (as `https://<token>@host` did) and the password is
        # empty. Delivered via env only — never argv.
        if auth.username:
            git_username, git_password = auth.username, auth.token
        else:
            git_username, git_password = auth.token, ""
        env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "GIT_ASKPASS": str(script_path),
            "GIT_TERMINAL_PROMPT": "0",  # never fall through to an interactive prompt
            "GIT_CONFIG_GLOBAL": "/dev/null",  # ignore any ambient credential.helper
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "SCRYE_GIT_USERNAME": git_username,
            "SCRYE_GIT_PASSWORD": git_password,
        }
        await _run_git_clone(url, options, checkout, env=env, timeout=timeout)
        yield str(checkout)
    finally:
        _shred_file(script_path)
        with contextlib.suppress(OSError):
            shutil.rmtree(cred_dir, ignore_errors=True)
        with contextlib.suppress(OSError):
            shutil.rmtree(clone_dir, ignore_errors=True)
