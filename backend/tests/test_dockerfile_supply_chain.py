"""Regression guards for the Dockerfile's supply-chain controls.

These string-level checks pin the build-time integrity guarantees so a future
Dockerfile edit can't silently drop them:

- backend dependencies are installed from the hash-pinned lock with
  ``pip install --require-hashes`` (SC-1), never a bare ``pip install .`` that
  would resolve unpinned transitives fresh from PyPI at build time.
- the scanner binaries' checksum files are cosign-signature-verified before the
  sha256sum check (SC-8).
"""

from __future__ import annotations

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = _REPO_ROOT / "docker" / "Dockerfile"
REQUIREMENTS_LOCK = _REPO_ROOT / "backend" / "requirements.lock"


def _dockerfile_text() -> str:
    """Return the Dockerfile contents."""
    return DOCKERFILE.read_text(encoding="utf-8")


def test_requirements_lock_is_committed_and_hash_pinned() -> None:
    assert REQUIREMENTS_LOCK.is_file(), "backend/requirements.lock must be committed (SC-1)"
    text = REQUIREMENTS_LOCK.read_text(encoding="utf-8")
    # A generated-by-uv header and at least one --hash entry: the lock must carry
    # per-artifact hashes so `pip install --require-hashes` can verify every wheel.
    assert "--hash=sha256:" in text, "requirements.lock must carry per-package hashes"
    # Every pinned direct dependency must be exact (== ), never a range.
    assert "fastapi==" in text and "cryptography==" in text


def test_backend_deps_install_with_require_hashes() -> None:
    text = _dockerfile_text()
    assert "--require-hashes" in text, (
        "the backend dependency install must use `pip install --require-hashes` so "
        "unpinned/unverified transitive packages can't enter the image (SC-1)"
    )
    assert "requirements.lock" in text, (
        "the image must install backend dependencies from the committed "
        "requirements.lock, not resolve them fresh from PyPI"
    )


def test_scanner_checksums_are_cosign_verified() -> None:
    text = _dockerfile_text()
    assert "cosign verify-blob" in text, (
        "each scanner's checksums.txt must be cosign-signature-verified before the "
        "sha256sum check (SC-8) so a compromised release can't regenerate a matching "
        "same-origin checksum"
    )
    # The verification must be identity- and issuer-pinned (keyless), not blind.
    assert "--certificate-identity-regexp" in text
    assert "token.actions.githubusercontent.com" in text
    # cosign itself is pinned by digest, not fetched loose at build time.
    assert "ghcr.io/sigstore/cosign/cosign" in text and "@sha256:" in text


def test_backend_bare_pip_install_dot_is_scoped_to_no_deps() -> None:
    # The application package itself is installed with --no-deps so the resolver
    # can't reach back out to PyPI for an unpinned copy of a runtime dependency
    # after the hash-verified lock install.
    text = _dockerfile_text()
    assert "pip install --no-deps ." in text, (
        "the app package install must be `pip install --no-deps .` so runtime "
        "deps come only from the hash-verified lock"
    )
