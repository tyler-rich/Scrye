"""Regression guards for the Dockerfile's supply-chain controls.

These string-level checks pin the build-time integrity guarantees so a future
Dockerfile edit can't silently drop them:

- backend dependencies are installed from the hash-pinned lock with
  ``pip install --require-hashes`` (SC-1), never a bare ``pip install .`` that
  would resolve unpinned transitives fresh from PyPI at build time.
- the scanner binaries' checksum files are cosign-signature-verified before the
  sha256sum check (SC-8).
- the runtime image does not ship the backend test suite or dev scripts (SC-14).
- the app package is built with ``--no-build-isolation`` against the hash-pinned
  setuptools from the lock, so no build-time dependency floats (SC-12).
"""

from __future__ import annotations

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = _REPO_ROOT / "docker" / "Dockerfile"
DOCKERIGNORE = _REPO_ROOT / ".dockerignore"
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


def test_buildkit_syntax_frontend_is_digest_pinned() -> None:
    # SC-9: the `# syntax=` BuildKit frontend must be digest-pinned, not resolved
    # by mutable tag at build time.
    text = _dockerfile_text()
    first_line = text.splitlines()[0]
    assert first_line.startswith("# syntax=docker/dockerfile:"), first_line
    assert "@sha256:" in first_line, "the BuildKit syntax frontend must be pinned by digest (SC-9)"


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


def test_backend_dev_only_trees_excluded_from_runtime_image() -> None:
    # SC-14: the final stage copies backend/ wholesale into the runtime image,
    # so the backend test suite and dev-only scripts (env-example generator)
    # must be kept out of the build context to avoid shipping needless bloat and
    # attack surface on the published scanner image. Docker only honors the root
    # .dockerignore for the build context (a backend/.dockerignore would be a
    # silent no-op), so the exclusion lives there.
    ignore_text = DOCKERIGNORE.read_text(encoding="utf-8")
    assert "backend/tests/" in ignore_text, (
        "the backend test suite must be excluded from the build context so it "
        "never ships in the runtime image (SC-14)"
    )
    assert "backend/scripts/" in ignore_text, (
        "the backend dev scripts must be excluded from the build context so they "
        "never ship in the runtime image (SC-14)"
    )
    # The runtime image still needs the schema/app trees the final COPY brings in.
    dockerfile_text = _dockerfile_text()
    assert "COPY --chown=1000:1000 backend/ /app/backend/" in dockerfile_text


def test_backend_app_install_is_no_deps_and_no_build_isolation() -> None:
    # The application package itself is installed with --no-deps so the resolver
    # can't reach back out to PyPI for an unpinned copy of a runtime dependency
    # after the hash-verified lock install, and with --no-build-isolation so the
    # PEP 517 build reuses the hash-verified setuptools already installed from the
    # lock instead of fetching an unpinned, unhashed copy into an isolated build
    # environment (SC-12).
    text = _dockerfile_text()
    assert "pip install --no-deps --no-build-isolation ." in text, (
        "the app package install must be `pip install --no-deps --no-build-isolation .` so "
        "runtime deps come only from the hash-verified lock and the build backend is the "
        "hash-verified setuptools from the lock, not an unpinned isolated-build fetch (SC-12)"
    )


def test_build_backend_setuptools_is_hash_pinned_in_lock() -> None:
    # SC-12: the PEP 517 build backend must be hash-pinned in the lock (flowed in
    # via the `build` dependency group), so `--no-build-isolation` above has a
    # verified setuptools to build against and no build-time dependency floats.
    lock_text = REQUIREMENTS_LOCK.read_text(encoding="utf-8")
    assert "setuptools==" in lock_text, (
        "requirements.lock must pin the setuptools build backend exactly (SC-12); "
        "regenerate it with `uv pip compile ... --group build`"
    )
    # The pinned setuptools entry must carry per-artifact hashes like every other
    # locked package (the entry sits between its `setuptools==` line and the next
    # dependency, so at least one --hash follows it).
    setuptools_block = lock_text.split("setuptools==", 1)[1]
    assert (
        "--hash=sha256:" in setuptools_block.split("\n    # via", 1)[0]
    ), "the locked setuptools must be hash-pinned (SC-12)"
