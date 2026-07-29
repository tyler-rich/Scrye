"""Tests for the container entrypoint's data-directory preflight.

The preflight exists because an unwritable ``/data`` used to surface only as
``sqlite3.OperationalError: unable to open database file`` from Alembic, which
names neither the path nor the fix. The usual cause is a bind-mounted host
directory whose ownership doesn't match the container uid — the common NAS
misconfiguration — and it is the same first-run-blocker class as a missing master
key.

**What these tests actually run.** ``docker/entrypoint.sh`` is executed for real,
with ``sh``, against real directory permissions, with two deliberate
substitutions so it can run outside the image:

- ``cd /app/backend`` is rewritten to a temp directory (that path exists only in
  the image);
- ``alembic`` and ``uvicorn`` are stubbed on ``PATH``, so "did the preflight stop
  the boot before migrations?" is observable as the absence of a marker file the
  Alembic stub writes.

Every line under test — the probe, the ordering, and the message text — is the
shipped one, unmodified. This is not a substitute for running the image; CI's
image job covers that.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ENTRYPOINT = Path(__file__).resolve().parents[2] / "docker" / "entrypoint.sh"

#: Root bypasses directory permission bits, so an "unwritable" directory is still
#: writable for uid 0 and the preflight would (correctly) pass. CI runs tests as a
#: normal user, which is where these cases are exercised.
running_as_root = os.geteuid() == 0


@pytest.fixture
def harness(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Return (runnable entrypoint copy, stub bin dir, alembic marker path)."""
    workdir = tmp_path / "backend"
    workdir.mkdir()

    script = ENTRYPOINT.read_text(encoding="utf-8")
    assert "cd /app/backend" in script, "entrypoint no longer cds to /app/backend"
    runnable = tmp_path / "entrypoint.sh"
    runnable.write_text(script.replace("cd /app/backend", f'cd "{workdir}"'), encoding="utf-8")
    runnable.chmod(0o755)

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "alembic-ran"
    (bin_dir / "alembic").write_text(
        f'#!/bin/sh\necho "stub alembic $*"\n: > "{marker}"\n', encoding="utf-8"
    )
    (bin_dir / "uvicorn").write_text('#!/bin/sh\necho "stub uvicorn $*"\n', encoding="utf-8")
    for stub in ("alembic", "uvicorn"):
        (bin_dir / stub).chmod(0o755)

    return runnable, bin_dir, marker


def _run(runnable: Path, bin_dir: Path, data_path: Path) -> subprocess.CompletedProcess[str]:
    """Run the entrypoint with the stubs on PATH and the given database path."""
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "SCRYE_DATABASE_PATH": str(data_path),
    }
    return subprocess.run(
        ["sh", str(runnable)], capture_output=True, text=True, env=env, timeout=30
    )


def test_entrypoint_is_valid_shell() -> None:
    """The shipped script parses (guards a typo in the preflight from shipping)."""
    sh = shutil.which("sh")
    assert sh is not None
    assert subprocess.run([sh, "-n", str(ENTRYPOINT)], capture_output=True).returncode == 0


def test_preflight_runs_before_migrations() -> None:
    """Ordering is the whole point: the check must precede `alembic upgrade head`."""
    script = ENTRYPOINT.read_text(encoding="utf-8")
    probe = script.index(".scrye-write-probe")
    migrate = script.index("alembic upgrade head")
    assert probe < migrate, "the writability probe must run before Alembic touches SQLite"


def test_writable_data_dir_proceeds_to_migrations(harness: tuple[Path, Path, Path]) -> None:
    runnable, bin_dir, marker = harness
    data_dir = runnable.parent / "data"
    data_dir.mkdir()

    result = _run(runnable, bin_dir, data_dir / "scrye.db")

    assert result.returncode == 0, result.stderr
    assert marker.exists(), "migrations did not run on a writable data directory"
    assert "stub uvicorn" in result.stdout, "the server was never started"
    leftovers = list(data_dir.glob(".scrye-write-probe*"))
    assert not leftovers, f"the probe file was not cleaned up: {leftovers}"


def test_missing_data_dir_fails_with_the_path(harness: tuple[Path, Path, Path]) -> None:
    runnable, bin_dir, marker = harness
    missing = runnable.parent / "not-mounted"

    result = _run(runnable, bin_dir, missing / "scrye.db")

    assert result.returncode != 0
    assert not marker.exists(), "migrations ran despite an absent data directory"
    assert str(missing) in result.stderr
    assert "does not exist" in result.stderr


@pytest.mark.skipif(running_as_root, reason="root bypasses directory permission bits")
def test_unwritable_data_dir_fails_before_migrations(harness: tuple[Path, Path, Path]) -> None:
    """The regression this preflight exists for: stop with a message, not a stack trace."""
    runnable, bin_dir, marker = harness
    data_dir = runnable.parent / "data"
    data_dir.mkdir(mode=0o555)

    result = _run(runnable, bin_dir, data_dir / "scrye.db")

    assert result.returncode != 0
    assert not marker.exists(), "migrations ran despite an unwritable data directory"
    assert "unable to open database file" not in (result.stdout + result.stderr)


@pytest.mark.skipif(running_as_root, reason="root bypasses directory permission bits")
def test_unwritable_message_names_path_uid_and_the_fix(
    harness: tuple[Path, Path, Path],
) -> None:
    """The message has to be actionable on its own — it is all the operator gets."""
    runnable, bin_dir, _ = harness
    data_dir = runnable.parent / "data"
    data_dir.mkdir(mode=0o555)

    stderr = _run(runnable, bin_dir, data_dir / "scrye.db").stderr

    assert str(data_dir) in stderr, "the message must name the directory"
    assert f"uid {os.geteuid()}:{os.getegid()}" in stderr, "it must name the container uid:gid"
    assert f"chown -R {os.geteuid()}:{os.getegid()}" in stderr, "it must give the concrete fix"
    assert "user:" in stderr, "it must mention matching the container user as the alternative"
