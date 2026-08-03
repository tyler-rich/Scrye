"""Regression guard: a symlink out of a filesystem scan root must not be walked.

Issue #135. ``resolve_filesystem_path()`` (``app/scanners/targets.py``) validates the
*target argument* of a filesystem scan against ``SCRYE_FILESYSTEM_SCAN_ROOTS`` and is
never re-applied while the scanner walks the tree. Containment of a symlink planted
**inside** an allowed root is therefore not enforced by Scrye at all — it is inherited
entirely from Syft's directory resolver, which re-roots every link target under the scan
directory because ``basePath()`` defaults ``base`` to the scan location:

    // syft/source/directorysource/directory_source_provider.go
    // FIXME why is the base always being set instead of left as empty string?

If that FIXME is ever actioned and ``base`` is left ``""``, the re-rooting branch in
``addSymlinkToIndex`` is skipped and ``indexAllRoots`` adds out-of-root link targets as
*additional roots to index* — the escape becomes real silently, on a routine scanner
version bump, with no code change on Scrye's side. These tests are the thing that
notices. See ``docs/ARCHIVE.md`` §14 (2026-08-02) for the full evidence chain.

**Why Syft is the probe rather than Grype.** Scrye runs ``grype -o json -- dir:<path>``,
and Grype's ``dir:`` source *is* Syft's directory source — the containment code under
test is identical. Grype is not usable as the instrument here because its JSON carries
only vulnerability *matches*, so observing "which packages were catalogued" through it
would require both fixtures to contain packages with live CVEs and would make the
assertion depend on a vulnerability database that changes daily. Syft's JSON lists the
catalogue directly and needs no database, so the test is deterministic and offline. The
substitution is pinned rather than assumed: ``test_grype_embeds_the_pinned_syft`` asserts
Grype's embedded Syft version equals the Syft binary being probed, and
``test_scrye_scans_filesystems_through_the_directory_source`` asserts Scrye still reaches
that code path via ``dir:``.

**Controls.** A containment assertion that only checks for an *absence* can pass while
testing nothing — during the 2026-08-02 verification a probe came back negative purely
because the planted file was named ``hardlink-lock.json``, which the JavaScript cataloger
does not glob. Two controls run alongside the main assertion, in the same session:

* a positive control — the in-root package **is** catalogued in the same scan; and
* a sensitivity control — widening ``--base-path`` so re-rooting no longer confines to
  the scan root makes the out-of-root package appear, proving the fixture's absence is
  containment rather than a cataloger blind spot.

**Hardlinks are deliberately out of scope.** A hardlink from inside an allowed root to an
out-of-root file *is* followed, and that is correct behaviour, not a bypass: a hardlink is
a second name for one inode rather than a reference containment could resolve, creating
one needs write access inside the root plus read access to the source, and it cannot cross
filesystems. Nothing here asserts against it.

**Running it.** The tests need the real pinned ``syft``/``grype`` binaries, so the plain
``pytest`` run in CI's backend job skips them. They are *run* in the ``image`` job, which
extracts the binaries the built image actually ships — cosign- and checksum-verified at
build time — and sets ``SCRYE_TEST_REQUIRE_SCANNER_BINARIES``, which turns the skip into a
failure so the guard cannot quietly stop running (``.github/workflows/ci.yml``). Locally,
point ``SCRYE_SYFT_BINARY``/``SCRYE_GRYPE_BINARY`` at the pinned binaries (see
``CONTRIBUTING.md`` § Testing).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from app.core.config import get_settings
from app.scanners import grype
from app.scanners.base import CommandResult, inherited_env, scanner_cache_env

_REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = _REPO_ROOT / "docker" / "Dockerfile"

#: Set to any non-empty value to make a missing scanner binary a failure rather
#: than a skip. CI sets it so this guard can never quietly stop running.
REQUIRE_BINARIES_ENV = "SCRYE_TEST_REQUIRE_SCANNER_BINARIES"

#: Package planted inside the allowed root — the positive control.
IN_ROOT_PACKAGE = ("left-pad", "1.3.0")

#: Package planted outside the allowed root — must never be catalogued.
OUT_OF_ROOT_PACKAGE = ("lodash", "4.17.15")

#: Wall-clock ceiling for a scanner invocation over a two-file fixture.
_TIMEOUT_SECONDS = 120


def _pinned_version(arg_name: str) -> str:
    """Return the version the Dockerfile pins for a scanner ``ARG``."""
    match = re.search(
        rf"^ARG\s+{re.escape(arg_name)}=(\S+)\s*$",
        DOCKERFILE.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    assert match, f"docker/Dockerfile no longer pins {arg_name}"
    return match.group(1)


def _binary(setting_value: str, name: str) -> str:
    """Resolve a scanner binary, skipping (or failing) when it is unavailable."""
    resolved = setting_value if "/" in setting_value else shutil.which(setting_value)
    if resolved and Path(resolved).is_file() and os.access(resolved, os.X_OK):
        return resolved
    message = (
        f"the pinned {name} binary is required for the issue-#135 containment guard "
        f"but was not found (looked for {setting_value!r})"
    )
    if os.environ.get(REQUIRE_BINARIES_ENV):
        pytest.fail(f"{REQUIRE_BINARIES_ENV} is set and {message}")
    pytest.skip(message)


@pytest.fixture
def syft_binary() -> str:
    """Path to the Syft binary under test."""
    return _binary(get_settings().syft_binary, "syft")


@pytest.fixture
def grype_binary() -> str:
    """Path to the Grype binary under test."""
    return _binary(get_settings().grype_binary, "grype")


def _scanner_env() -> dict[str, str]:
    """Child environment for an offline scanner run.

    Reuses Scrye's own cache/temp redirection so the probe writes where a real scan
    writes, and suppresses both scanners' interactive update checks so no network
    call is attempted.
    """
    env = inherited_env()
    env.update(scanner_cache_env())
    env["SYFT_CHECK_FOR_APP_UPDATE"] = "false"
    env["GRYPE_CHECK_FOR_APP_UPDATE"] = "false"
    return env


def _run(argv: list[str]) -> dict[str, Any]:
    """Run a scanner command and parse its JSON stdout."""
    result = subprocess.run(
        argv,
        capture_output=True,
        env=_scanner_env(),
        timeout=_TIMEOUT_SECONDS,
        check=False,
    )
    assert (
        result.returncode == 0
    ), f"{argv[0]} exited {result.returncode}: {result.stderr.decode(errors='replace')[-2000:]}"
    return json.loads(result.stdout)


def _catalogue(syft: str, root: Path, *, base_path: Path | None = None) -> set[tuple[str, str]]:
    """Return the ``(name, version)`` set Syft catalogues under ``root``.

    Args:
        syft: Path to the Syft binary.
        root: Directory to scan, addressed as ``dir:<path>`` exactly as Scrye
            addresses a filesystem target.
        base_path: Optional explicit ``--base-path``. Scrye never passes one — it is
            used only by the sensitivity control, to move the re-rooting anchor above
            the scan root and prove the probe can see an escape when one happens.
    """
    argv = [syft, "-q", "-o", "json"]
    if base_path is not None:
        argv += ["--base-path", str(base_path)]
    argv += [f"dir:{root}"]
    document = _run(argv)
    return {(str(a["name"]), str(a["version"])) for a in document["artifacts"]}


def _locations(syft: str, root: Path) -> list[str]:
    """Return every location path Syft reports for packages under ``root``."""
    document = _run([syft, "-q", "-o", "json", f"dir:{root}"])
    return [str(loc["path"]) for artifact in document["artifacts"] for loc in artifact["locations"]]


def _lockfile(package: tuple[str, str]) -> str:
    """Render a minimal npm lockfile declaring a single package."""
    name, version = package
    return json.dumps(
        {"name": "fixture", "lockfileVersion": 1, "dependencies": {name: {"version": version}}}
    )


@pytest.fixture
def escape_fixture(tmp_path: Path) -> tuple[Path, Path]:
    """Build an allowed scan root seeded with symlinks pointing out of it.

    Layout (``allowed/`` is the scan root, ``outside/`` is off-limits)::

        allowed/app/package-lock.json          left-pad 1.3.0   (positive control)
        allowed/abs-dir-link              ->   <tmp>/outside
        allowed/rel-dir-link              ->   ../outside
        allowed/abs-file-link/package-lock.json -> <tmp>/outside/package-lock.json
        allowed/rel-file-link/package-lock.json -> ../../outside/package-lock.json
        allowed/etc-link                  ->   /etc
        outside/package-lock.json              lodash 4.17.15   (must stay unseen)

    The two file symlinks are named ``package-lock.json`` on purpose: a link the
    JavaScript cataloger would not glob could not be followed even if containment
    broke, so it would prove nothing.

    Returns:
        The allowed root and the out-of-root directory.
    """
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    (allowed / "app").mkdir(parents=True)
    outside.mkdir()

    (allowed / "app" / "package-lock.json").write_text(_lockfile(IN_ROOT_PACKAGE))
    (outside / "package-lock.json").write_text(_lockfile(OUT_OF_ROOT_PACKAGE))

    (allowed / "abs-dir-link").symlink_to(outside)
    (allowed / "rel-dir-link").symlink_to(Path("..") / "outside")
    (allowed / "etc-link").symlink_to("/etc")

    (allowed / "abs-file-link").mkdir()
    (allowed / "abs-file-link" / "package-lock.json").symlink_to(outside / "package-lock.json")
    (allowed / "rel-file-link").mkdir()
    (allowed / "rel-file-link" / "package-lock.json").symlink_to(
        Path("..") / ".." / "outside" / "package-lock.json"
    )
    return allowed, outside


# --- The guard ---------------------------------------------------------------


def test_out_of_root_symlink_targets_are_not_catalogued(
    syft_binary: str, escape_fixture: tuple[Path, Path]
) -> None:
    """A symlink out of the scan root must contribute nothing to the catalogue.

    Carries its own positive control: the in-root package must be present in the
    *same* scan, so the absence below cannot be an empty result masquerading as
    containment.
    """
    allowed, _ = escape_fixture
    catalogue = _catalogue(syft_binary, allowed)

    assert IN_ROOT_PACKAGE in catalogue, (
        "positive control failed: the in-root package was not catalogued, so this run "
        "proves nothing about containment"
    )
    assert OUT_OF_ROOT_PACKAGE not in catalogue, (
        "an out-of-root symlink target was catalogued — the filesystem scan root is no "
        "longer contained. See issue #135: re-assess against the inventory-disclosure "
        "ceiling and consider passing Syft an explicit --base-path or pinning the scanner."
    )
    assert catalogue == {IN_ROOT_PACKAGE}, f"unexpected packages catalogued: {catalogue}"


def test_reported_locations_stay_inside_the_scan_root(
    syft_binary: str, escape_fixture: tuple[Path, Path]
) -> None:
    """Every reported location must be a path relative to the scan root."""
    allowed, outside = escape_fixture
    for path in _locations(syft_binary, allowed):
        assert not path.startswith(str(outside)), f"location escaped the scan root: {path}"
        assert "outside" not in path, f"location escaped the scan root: {path}"


# --- Controls ----------------------------------------------------------------


def test_out_of_root_manifest_is_catalogable_on_its_own(
    syft_binary: str, escape_fixture: tuple[Path, Path]
) -> None:
    """Scanned directly, the out-of-root manifest yields its package.

    Guards the methodology failure recorded in ``docs/ARCHIVE.md`` §14: a negative
    from a cataloger-based probe means nothing unless the planted filename is one the
    cataloger actually globs.
    """
    _, outside = escape_fixture
    assert OUT_OF_ROOT_PACKAGE in _catalogue(syft_binary, outside)


def test_probe_detects_an_escape_when_re_rooting_is_widened(
    syft_binary: str, escape_fixture: tuple[Path, Path]
) -> None:
    """Sensitivity control: the assertion above can fail.

    Moving the re-rooting anchor one level above the scan root with ``--base-path``
    is the closest reachable analogue of the upstream FIXME being actioned: link
    targets resolve outside the scanned directory instead of collapsing into it.
    The out-of-root package then *is* catalogued — so the main test's absence is
    containment doing work, not the probe being blind.
    """
    allowed, _ = escape_fixture
    widened = _catalogue(syft_binary, allowed, base_path=allowed.parent)
    assert OUT_OF_ROOT_PACKAGE in widened, (
        "the probe did not surface an out-of-root package even with re-rooting widened; "
        "it can no longer detect the regression it exists to catch"
    )


# --- Premises the substitution rests on --------------------------------------


def test_syft_binary_is_the_version_the_image_pins(syft_binary: str) -> None:
    """The probed Syft must be the version the image ships."""
    document = _run([syft_binary, "version", "-o", "json"])
    assert document["version"] == _pinned_version("SYFT_VERSION")


def test_grype_embeds_the_pinned_syft(grype_binary: str) -> None:
    """Grype's ``dir:`` walk must be the same Syft the probe exercises.

    This is the link that lets a Syft-based probe stand in for Scrye's Grype
    invocation. If a scanner bump breaks it, the guard above is testing code Scrye
    does not run, and this fails first.
    """
    document = _run([grype_binary, "version", "-o", "json"])
    assert document["version"] == _pinned_version("GRYPE_VERSION")
    assert document["syftVersion"] == f"v{_pinned_version('SYFT_VERSION')}"


@pytest.mark.asyncio
async def test_scrye_scans_filesystems_through_the_directory_source(monkeypatch, tmp_path) -> None:
    """Scrye must still reach the walk under test via ``dir:``.

    Needs no binary: it pins the premise that a filesystem scan is a Syft directory
    source at all. Were Scrye to address filesystem targets some other way, the
    containment guard above would stop describing production behaviour.
    """
    captured: dict[str, list[str]] = {}

    async def _capture(argv: list[str], *, timeout: int, env: dict[str, str] | None = None):
        captured["argv"] = argv
        return CommandResult(returncode=0, stdout=b'{"matches": []}', stderr=b"", argv=argv)

    monkeypatch.setattr(grype, "resolve_binary", lambda name_or_path: "/usr/local/bin/grype")
    monkeypatch.setattr(grype, "run_command", _capture)
    await grype.GrypeScanner().scan_filesystem(str(tmp_path), {})

    assert captured["argv"][-1] == f"dir:{tmp_path}"
