"""Drift guard for the app version string.

The version is declared independently in three places — ``app.__version__``
(what the running app reports on ``/healthz``, the About tab, the OpenAPI
document, backup bundles and the ``scrye_build_info`` metric),
``backend/pyproject.toml`` (packaging metadata) and
``frontend/package.json``/``package-lock.json`` (npm metadata). Nothing derives
one from another, so a release that bumps only some of them ships an app that
misreports its own version. These tests fail on exactly that.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

from app import __version__

_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_pyproject_version_matches_the_package() -> None:
    """Packaging metadata agrees with what the app reports at runtime."""
    with (_REPO_ROOT / "backend" / "pyproject.toml").open("rb") as fh:
        pyproject = tomllib.load(fh)
    assert pyproject["project"]["version"] == __version__


def test_frontend_package_version_matches_the_package() -> None:
    """The SPA's npm metadata agrees with the backend's version."""
    package = json.loads((_REPO_ROOT / "frontend" / "package.json").read_text())
    assert package["version"] == __version__


def test_frontend_lockfile_version_matches_the_package() -> None:
    """``npm version`` writes both the manifest and the lockfile; keep them paired."""
    lock = json.loads((_REPO_ROOT / "frontend" / "package-lock.json").read_text())
    assert lock["version"] == __version__
    assert lock["packages"][""]["version"] == __version__
