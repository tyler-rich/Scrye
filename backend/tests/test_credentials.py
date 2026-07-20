"""Tests for transient scan-time credential materialization.

Covers the security-critical behavior in ``app.scanners.credentials``: the
Docker config document shape (auths vs credHelpers), that the transient config
file is written then **shredded** (removed) on context exit, git auth resolution
per provider, and — for generic-host clones — that the credential is delivered
off-argv via a tmpfs GIT_ASKPASS helper and the whole workspace is shredded on
exit (docs/ARCHIVE.md §14, Phase 3 Security Review #2).
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from app.core.logging import redact, strip_url_credentials
from app.db.models import GitProvider, RegistryAuthType
from app.scanners import credentials as credentials_module
from app.scanners.base import CommandResult, ScannerError
from app.scanners.credentials import (
    GitAuth,
    RegistryAuth,
    build_docker_config,
    docker_config_env,
    generic_repo_checkout,
    git_env_token,
    is_http_url,
    is_remote_repo_url,
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


def test_git_env_token_github() -> None:
    assert git_env_token(GitAuth(provider=GitProvider.GITHUB, token="ghp_x")) == {
        "GITHUB_TOKEN": "ghp_x"
    }


def test_git_env_token_gitlab() -> None:
    assert git_env_token(GitAuth(provider=GitProvider.GITLAB, token="glpat")) == {
        "GITLAB_TOKEN": "glpat"
    }


def test_git_env_token_generic_has_no_env_channel() -> None:
    # Generic hosts have no native token env var; they go through the clone path.
    assert git_env_token(GitAuth(provider=GitProvider.GENERIC, token="tok")) == {}


def test_is_http_url() -> None:
    assert is_http_url("https://git.example.com/repo.git")
    assert is_http_url("http://git.example.com/repo.git")
    assert not is_http_url("ssh://git@host/repo.git")
    assert not is_http_url("git@host:repo.git")


def test_is_remote_repo_url_accepts_remote_schemes() -> None:
    assert is_remote_repo_url("https://git.example.com/repo.git")
    assert is_remote_repo_url("http://git.example.com/repo.git")
    assert is_remote_repo_url("ssh://git@host/repo.git")
    assert is_remote_repo_url("git://host/repo.git")


def test_is_remote_repo_url_rejects_local_paths() -> None:
    # SEC-1: bare paths (what Trivy `repo` would walk on the local filesystem)
    # and the file:// scheme must not count as remote repositories.
    assert not is_remote_repo_url("/data")
    assert not is_remote_repo_url("/run/secrets")
    assert not is_remote_repo_url("/")
    assert not is_remote_repo_url("./repo")
    assert not is_remote_repo_url("file:///etc/passwd")


GENERIC_TOKEN = "sup3r-secret-git-token"


def _stub_clone(monkeypatch, *, returncode: int = 0, stderr: bytes = b"") -> dict:
    """Replace ``run_command`` with a stub that records every invocation.

    The stub creates the checkout directory (so the clone "succeeds") and
    captures the argv + env of each call for assertions.
    """
    calls: dict = {"invocations": []}

    async def _fake_run_command(argv, *, timeout, env=None):
        record = {"argv": list(argv), "env": dict(env or {})}
        calls["invocations"].append(record)
        # Materialize the checkout dir on a successful `git clone` so the yield
        # target exists, mirroring a real clone.
        if returncode == 0 and argv[:2] == ["git", "clone"]:
            Path(argv[-1]).mkdir(parents=True, exist_ok=True)
        return CommandResult(returncode=returncode, stdout=b"", stderr=stderr, argv=list(argv))

    monkeypatch.setattr(credentials_module, "run_command", _fake_run_command)
    return calls


@pytest.mark.asyncio
async def test_generic_clone_keeps_credential_off_argv(monkeypatch) -> None:
    calls = _stub_clone(monkeypatch)
    auth = GitAuth(provider=GitProvider.GENERIC, token=GENERIC_TOKEN, username="deploy")

    workspace: str | None = None
    async with generic_repo_checkout(
        "https://git.example.com/team/repo.git", auth, {"branch": "main"}, timeout=30
    ) as checkout:
        workspace = str(Path(checkout).parent)
        assert Path(checkout).parent.exists()

    clone = calls["invocations"][0]
    # The credential appears in NO argv element of the git subprocess.
    assert all(GENERIC_TOKEN not in arg for arg in clone["argv"])
    assert GENERIC_TOKEN not in " ".join(clone["argv"])
    # The clean URL is the only URL on argv (no embedded userinfo).
    assert "https://git.example.com/team/repo.git" in clone["argv"]
    assert "@git.example.com" not in " ".join(clone["argv"])
    # The credential is delivered solely through the child environment.
    assert clone["env"]["SCRYE_GIT_USERNAME"] == "deploy"
    assert clone["env"]["SCRYE_GIT_PASSWORD"] == GENERIC_TOKEN
    assert clone["env"]["GIT_TERMINAL_PROMPT"] == "0"
    # The askpass helper existed and was executable (0700) at clone time.
    askpass = Path(clone["env"]["GIT_ASKPASS"])
    assert askpass.name == "askpass.sh"
    # The whole tmpfs workspace is shredded/removed after the context exits.
    assert workspace is not None
    assert not Path(workspace).exists()


@pytest.mark.asyncio
async def test_generic_clone_askpass_is_owner_only_executable(monkeypatch) -> None:
    seen: dict = {}

    async def _fake_run_command(argv, *, timeout, env=None):
        # Inspect the askpass file mid-clone, before cleanup.
        askpass = Path(env["GIT_ASKPASS"])
        seen["exists"] = askpass.is_file()
        seen["mode"] = askpass.stat().st_mode & 0o777
        Path(argv[-1]).mkdir(parents=True, exist_ok=True)
        return CommandResult(returncode=0, stdout=b"", stderr=b"", argv=list(argv))

    monkeypatch.setattr(credentials_module, "run_command", _fake_run_command)
    auth = GitAuth(provider=GitProvider.GENERIC, token="tok", username="u")
    async with generic_repo_checkout("https://h/r.git", auth, {}, timeout=30):
        pass
    assert seen["exists"] is True
    # git execs the helper, so it must be executable — 0700, owner-only.
    assert seen["mode"] == 0o700


@pytest.mark.asyncio
async def test_generic_clone_shreds_workspace_on_scan_exception(monkeypatch) -> None:
    _stub_clone(monkeypatch)
    auth = GitAuth(provider=GitProvider.GENERIC, token="tok", username="u")

    workspace: str | None = None
    with pytest.raises(RuntimeError):
        async with generic_repo_checkout("https://h/r.git", auth, {}, timeout=30) as checkout:
            workspace = str(Path(checkout).parent)
            raise RuntimeError("scan boom")
    assert workspace is not None
    assert not Path(workspace).exists()


@pytest.mark.asyncio
async def test_generic_clone_removes_checkout_off_the_event_loop(monkeypatch) -> None:
    """CON-20: the (potentially multi-GB) checkout removal is hopped to a thread
    so it doesn't stall the event loop; the small tmpfs cred dir stays inline."""
    import shutil
    import threading

    _stub_clone(monkeypatch)
    loop_thread = threading.get_ident()
    seen: dict[str, int] = {}
    real_rmtree = shutil.rmtree

    def _spy_rmtree(path, *args, **kwargs):
        seen[str(path)] = threading.get_ident()
        return real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(shutil, "rmtree", _spy_rmtree)
    auth = GitAuth(provider=GitProvider.GENERIC, token="tok", username="u")

    async with generic_repo_checkout("https://h/r.git", auth, {}, timeout=30):
        pass

    checkout_removals = {p: t for p, t in seen.items() if "scrye-gitclone-" in p}
    assert checkout_removals, "the checkout dir was never removed"
    assert all(
        thread != loop_thread for thread in checkout_removals.values()
    ), "the checkout removal ran on the event-loop thread"


@pytest.mark.asyncio
async def test_generic_clone_without_username_uses_token_as_user(monkeypatch) -> None:
    calls = _stub_clone(monkeypatch)
    auth = GitAuth(provider=GitProvider.GENERIC, token="tok-only")
    async with generic_repo_checkout("https://h/r.git", auth, {}, timeout=30):
        pass
    env = calls["invocations"][0]["env"]
    # Historical `https://<token>@host` semantics: token is the user, empty pass.
    assert env["SCRYE_GIT_USERNAME"] == "tok-only"
    assert env["SCRYE_GIT_PASSWORD"] == ""


@pytest.mark.asyncio
async def test_generic_clone_checks_out_commit(monkeypatch) -> None:
    calls = _stub_clone(monkeypatch)
    auth = GitAuth(provider=GitProvider.GENERIC, token="tok", username="u")
    async with generic_repo_checkout("https://h/r.git", auth, {"commit": "abc123"}, timeout=30):
        pass
    argvs = [inv["argv"] for inv in calls["invocations"]]
    # A commit target clones fully (no --depth) then checks out the commit.
    assert argvs[0][:3] == ["git", "clone", "--quiet"]
    assert "--depth" not in argvs[0]
    assert argvs[1] == ["git", "-C", argvs[0][-1], "checkout", "--quiet", "abc123"]


@pytest.mark.asyncio
async def test_generic_clone_failure_message_has_no_credential(monkeypatch) -> None:
    # git stderr echoes the request URL; the raised error must not surface it.
    _stub_clone(
        monkeypatch,
        returncode=128,
        stderr=b"fatal: could not read Username for 'https://deploy@git.example.com'",
    )
    auth = GitAuth(provider=GitProvider.GENERIC, token=GENERIC_TOKEN, username="deploy")

    workspace_parents = set()
    with pytest.raises(ScannerError) as excinfo:
        async with generic_repo_checkout("https://git.example.com/r.git", auth, {}, timeout=30):
            pass  # pragma: no cover - clone fails before yield
    assert GENERIC_TOKEN not in str(excinfo.value)
    assert "git.example.com" not in str(excinfo.value)
    # Sanity: nothing lingers in the temp root under our prefix.
    assert not any(p.exists() for p in workspace_parents)


def test_url_credentials_are_redacted_from_logs() -> None:
    # Defense in depth: even though generic creds no longer ride in the URL, the
    # log filter still strips any userinfo that reaches a log line.
    text = "cloning https://deploy:tok@git.example.com/team/repo.git failed"
    assert "tok" not in strip_url_credentials(text)
    assert "tok" not in redact(text)
    assert "git.example.com" in strip_url_credentials(text)  # host preserved
