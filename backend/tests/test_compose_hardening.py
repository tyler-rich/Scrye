"""Regression guards for the hardened Compose runtime constraints.

The scanners fail at runtime with ``mkdir /tmp/trivy-XXXXXXXXX: permission
denied`` when the tmpfs ``/tmp`` is left root-owned under a non-root ``user:`` —
a freshly mounted tmpfs is owned by uid 0, so a uid-1000 process (and the
in-memory credential materialization) cannot write to it. These string-level
checks pin the ownership/volume options so that hardening can't silently regress
the next time the Compose file is edited.
"""

from __future__ import annotations

from pathlib import Path

COMPOSE = Path(__file__).resolve().parents[2] / "docker" / "docker-compose.yml"


def _scrye_tmp_mount() -> str:
    """Return the scrye service's ``/tmp`` tmpfs mount line."""
    lines = [
        line.strip()
        for line in COMPOSE.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("- /tmp:")
    ]
    assert lines, "no scrye /tmp tmpfs mount (`- /tmp:...`) found in docker-compose.yml"
    return lines[0]


def test_tmp_tmpfs_is_owned_by_the_app_uid() -> None:
    mount = _scrye_tmp_mount()
    assert "uid=1000" in mount and "gid=1000" in mount, (
        "the /tmp tmpfs must be owned by the container uid (1000); a root-owned "
        f"tmpfs leaves a non-root process unable to write to /tmp: {mount!r}"
    )


def test_cache_volume_is_mounted_for_scanner_databases() -> None:
    text = COMPOSE.read_text(encoding="utf-8")
    # The writable, persistent cache volume is where the scanners' vuln DBs and
    # temp extraction land instead of the read-only $HOME/.cache or the tmpfs.
    assert "scrye_cache:/cache" in text, "the /cache volume must be mounted for scanner caches"
