"""Scanner base types: subprocess execution, normalized findings, registry.

The concrete scanners (:mod:`app.scanners.trivy`, :mod:`app.scanners.grype`)
build an argument vector, run the binary via :func:`run_command`, and parse the
JSON on stdout into a :class:`ScanExecution`. Keeping the subprocess call in one
place (``run_command``) gives tests a single seam to stub — no real binaries are
needed to exercise the worker or the parsers.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
from abc import ABC
from dataclasses import dataclass, field
from typing import Any

from app.core.config import get_settings
from app.db.models import Scanner, Severity


class ScannerError(RuntimeError):
    """Raised when a scanner cannot be run or its output cannot be parsed.

    The message is safe to surface to operators and to store on the scan row —
    it never contains secret material (image scans carry no credentials).
    """


class ScannerOutputError(ScannerError):
    """Raised when a scanner ran but emitted output we cannot parse.

    Covers both invalid JSON and valid JSON of the wrong shape (a top-level
    null/array, a string where an object is expected, ...). The raw stdout
    bytes ride along so the worker can still persist them as the scan's raw
    artifact — without that, a malformed-output failure leaves nothing on disk
    to diagnose.
    """

    def __init__(self, message: str, raw_output: bytes = b"") -> None:
        """Store the operator-safe message and the raw scanner stdout."""
        super().__init__(message)
        self.raw_output = raw_output


@dataclass(frozen=True)
class NormalizedFinding:
    """A single finding after normalization into Scrye's shared model.

    Trivy and Grype findings both collapse into this shape so they render in one
    table regardless of which engine produced them.
    """

    finding_class: str
    severity: Severity
    vuln_id: str | None = None
    pkg_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    title: str | None = None
    description: str | None = None
    location: str | None = None
    primary_url: str | None = None


@dataclass
class ScanExecution:
    """The full result of running one scan: raw bytes + parsed findings."""

    raw_output: bytes
    findings: list[NormalizedFinding]
    severity_counts: dict[Severity, int]
    command: list[str]
    scanner_version: str | None = None


@dataclass
class CommandResult:
    """Outcome of a completed subprocess."""

    returncode: int
    stdout: bytes
    stderr: bytes
    argv: list[str] = field(default_factory=list)


async def run_command(
    argv: list[str],
    *,
    timeout: int,
    env: dict[str, str] | None = None,
) -> CommandResult:
    """Run a subprocess to completion, capturing stdout/stderr.

    Args:
        argv: The full argument vector (``argv[0]`` is the executable).
        timeout: Wall-clock timeout in seconds; the process is killed on expiry.
        env: Optional environment overlay for the child process.

    Returns:
        A :class:`CommandResult` with the captured output.

    Raises:
        ScannerError: If the executable is missing or the run times out.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
    except FileNotFoundError as exc:
        raise ScannerError(f"Scanner executable not found: {argv[0]!r}.") from exc
    except OSError as exc:
        raise ScannerError(f"Failed to launch scanner {argv[0]!r}: {exc}.") from exc

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError as exc:
        proc.kill()
        await proc.wait()
        raise ScannerError(f"Scan timed out after {timeout}s.") from exc
    except asyncio.CancelledError:
        # Worker shutdown cancelled us: don't leave the child process orphaned.
        proc.kill()
        with contextlib.suppress(ProcessLookupError):
            await proc.wait()
        raise

    return CommandResult(
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout=stdout,
        stderr=stderr,
        argv=argv,
    )


def resolve_binary(name_or_path: str) -> str:
    """Resolve a scanner binary name to an absolute path.

    Bare names are looked up on ``PATH``; explicit paths are returned as-is so a
    missing file surfaces as a clear :class:`ScannerError` at run time.

    Args:
        name_or_path: A binary name (``"trivy"``) or a filesystem path.

    Returns:
        The resolved executable path.

    Raises:
        ScannerError: If a bare name cannot be found on ``PATH``.
    """
    if "/" in name_or_path:
        return name_or_path
    resolved = shutil.which(name_or_path)
    if resolved is None:
        raise ScannerError(
            f"Scanner binary {name_or_path!r} was not found on PATH. "
            "Install it or set the corresponding *_BINARY setting."
        )
    return resolved


#: Per-engine cache subdirectory names under the writable cache volume.
TRIVY_CACHE_SUBDIR = "trivy"
GRYPE_CACHE_SUBDIR = "grype"
SCRATCH_SUBDIR = "tmp"


def scanner_cache_env() -> dict[str, str]:
    """Return the env overlay pointing every bundled scanner at the cache volume.

    Under the hardened runtime the container runs as a **non-root uid** on a
    **read-only root filesystem**, and ``/tmp`` is a small owner-only tmpfs. That
    makes a scanner's default cache location (``$HOME/.cache`` — e.g.
    ``/app/.cache``) unwritable, so a vuln-DB write or even a ``trivy --version
    --format json`` DB-freshness read fails with ``mkdir /app/.cache: read-only
    file system``; and the tmpfs is both too small for a multi-hundred-MB DB and,
    unless its ownership matches the app uid, unwritable at all
    (``mkdir /tmp/trivy-XXXXXXXXX: permission denied``).

    Redirect **all** of it onto the persistent, writable cache volume via
    environment variables, so the fix covers every invocation uniformly — image/
    repo/filesystem/SBOM scans **and** the lightweight version / DB-status probes
    — without threading a flag through each call site:

    - ``TMPDIR`` → a scratch dir on the volume (keeps large temp extraction off
      the tiny tmpfs);
    - ``HOME`` / ``XDG_CACHE_HOME`` → the volume root, so any ``$HOME/.cache``
      fallback also lands somewhere writable;
    - ``TRIVY_CACHE_DIR`` / ``GRYPE_DB_CACHE_DIR`` → explicit per-engine cache /
      DB directories.

    The vulnerability DB therefore downloads once and persists across restarts
    (the volume outlives the container) instead of re-downloading into a
    transient or broken location. Directories are created if missing — the cache
    volume starts empty.

    Returns:
        An environment overlay to layer onto every scanner subprocess.
    """
    base = get_settings().scanner_cache_dir
    tmp_dir = base / SCRATCH_SUBDIR
    trivy_dir = base / TRIVY_CACHE_SUBDIR
    grype_dir = base / GRYPE_CACHE_SUBDIR
    for path in (tmp_dir, trivy_dir, grype_dir):
        path.mkdir(parents=True, exist_ok=True)
    return {
        "TMPDIR": str(tmp_dir),
        "HOME": str(base),
        "XDG_CACHE_HOME": str(base),
        "TRIVY_CACHE_DIR": str(trivy_dir),
        "GRYPE_DB_CACHE_DIR": str(grype_dir / "db"),
    }


def tally_severities(findings: list[NormalizedFinding]) -> dict[Severity, int]:
    """Count findings per severity level (levels with zero are included)."""
    counts: dict[Severity, int] = {level: 0 for level in Severity}
    for finding in findings:
        counts[finding.severity] += 1
    return counts


#: Case-insensitive lookup from a scanner's severity string to the normalized
#: enum. The six-level superset covers both engines — Trivy simply never emits
#: NEGLIGIBLE — so both scanners share one mapping and can't drift apart.
SEVERITY_BY_NAME: dict[str, Severity] = {level.value.upper(): level for level in Severity}

#: Max characters kept for a finding description before clipping.
DESCRIPTION_LIMIT = 4000


def severity_from_string(raw: Any) -> Severity:
    """Normalize a scanner severity string to the shared enum (default UNKNOWN)."""
    return SEVERITY_BY_NAME.get(str(raw).upper(), Severity.UNKNOWN)


def clip(value: Any, limit: int) -> str | None:
    """Return ``value`` as a stripped string clipped to ``limit`` chars, or None."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text if len(text) <= limit else text[: limit - 1] + "…"


def check_success(result: CommandResult, engine: str) -> None:
    """Raise a :class:`ScannerError` when a scanner subprocess exited non-zero.

    Shared by every engine so the "exited with code N: <stderr>" message stays
    uniform (the stderr detail is operator-safe; repo-scan errors are further
    redacted by the worker before storage).
    """
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip() or "no error output"
        raise ScannerError(f"{engine} exited with code {result.returncode}: {detail}")


def _wrong_shape(engine: str, detail: str) -> ScannerOutputError:
    """Build the uniform wrong-shape error for ``engine``."""
    return ScannerOutputError(f"{engine} produced JSON of an unexpected shape: {detail}.")


def load_json_output(raw: bytes, engine: str) -> dict[str, Any]:
    """Parse scanner stdout into a top-level JSON object.

    Empty output is treated as an empty report. Invalid JSON *and* valid JSON
    that is not an object (``null``, an array, a bare string...) both raise
    :class:`ScannerOutputError` carrying ``raw``, so the failure is a
    diagnosable scan error instead of an ``AttributeError`` deep in a parser.
    """
    try:
        document = json.loads(raw or b"{}")
    except json.JSONDecodeError as exc:
        raise ScannerOutputError(
            f"{engine} produced output that is not valid JSON: {exc}.", raw
        ) from exc
    if not isinstance(document, dict):
        raise ScannerOutputError(
            f"{engine} produced JSON of an unexpected shape: expected a top-level "
            f"object, got {type(document).__name__}.",
            raw,
        )
    return document


def object_entries(value: Any, field_name: str, engine: str) -> list[dict[str, Any]]:
    """Validate an optional array-of-objects field and return its entries.

    ``None`` (absent/null) means "no entries". Anything that is not a list of
    objects raises :class:`ScannerOutputError` rather than crashing later on a
    ``.get`` against a non-dict entry.
    """
    if value is None:
        return []
    if not isinstance(value, list):
        raise _wrong_shape(engine, f"{field_name!r} should be an array, got {type(value).__name__}")
    for entry in value:
        if not isinstance(entry, dict):
            raise _wrong_shape(
                engine, f"{field_name!r} entries should be objects, got {type(entry).__name__}"
            )
    return value


def object_field(value: Any, field_name: str, engine: str) -> dict[str, Any]:
    """Validate an optional object field; ``None`` becomes an empty dict."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise _wrong_shape(
            engine, f"{field_name!r} should be an object, got {type(value).__name__}"
        )
    return value


def string_entries(value: Any, field_name: str, engine: str) -> list[str]:
    """Validate an optional array-of-strings field; scalar entries are coerced.

    Guards against a string (or object) where an array is expected — iterating
    a string would silently yield per-character garbage (e.g. a ``fix.versions``
    of ``"1.2.3"`` rendering as ``1, ., 2, ., 3``) instead of failing.
    """
    if value is None:
        return []
    if not isinstance(value, list):
        raise _wrong_shape(engine, f"{field_name!r} should be an array, got {type(value).__name__}")
    out: list[str] = []
    for entry in value:
        if not isinstance(entry, str | int | float):
            raise _wrong_shape(
                engine, f"{field_name!r} entries should be strings, got {type(entry).__name__}"
            )
        out.append(str(entry))
    return out


def inherited_env() -> dict[str, str]:
    """Return the parent environment with Scrye's own config vars removed.

    Scanner subprocesses have no need for Scrye's ``SCRYE_*`` configuration (which
    names the master-key secret file, the database path, sidecar URLs, etc.).
    Dropping them keeps a bundled binary — or a scanner plugin / template code
    path — from reading the application's config surface, while preserving the
    generic environment (``PATH``, ``HOME``, TLS/proxy vars, locale) the scanners
    genuinely rely on for network and filesystem access.
    """
    return {name: value for name, value in os.environ.items() if not name.startswith("SCRYE_")}


def build_env(*overlays: dict[str, str] | None) -> dict[str, str] | None:
    """Merge environment overlays onto the (Scrye-config-stripped) process env.

    Returns ``None`` when no overlay contributes anything, so the caller can let
    the child simply inherit the parent environment.

    Args:
        overlays: Zero or more optional ``{name: value}`` overlays, applied in
            order (later ones win).

    Returns:
        The child environment, or ``None`` if every overlay was empty.
    """
    if not any(overlays):
        return None
    env = inherited_env()
    for overlay in overlays:
        if overlay:
            env.update(overlay)
    return env


class BaseScanner(ABC):
    """Base for a scanner engine, dispatched by target type.

    Each engine implements the target kinds it supports (docs/PLAN.md §4);
    unsupported combinations raise a clear :class:`ScannerError` rather than
    silently doing nothing. ``env`` is an optional environment **overlay**
    (e.g. transient registry/git credentials) applied on top of the process
    environment for the scanner subprocess.
    """

    scanner: Scanner

    def _unsupported(self, target_kind: str) -> ScannerError:
        """Build the error for a target kind this engine does not support."""
        return ScannerError(f"{self.scanner.value} does not support {target_kind} targets.")

    async def scan_image(
        self, target: str, options: dict[str, Any], *, env: dict[str, str] | None = None
    ) -> ScanExecution:
        """Scan a container image reference."""
        raise self._unsupported("image")

    async def scan_repo(
        self, target: str, options: dict[str, Any], *, env: dict[str, str] | None = None
    ) -> ScanExecution:
        """Scan a git repository (``target`` is the clone URL)."""
        raise self._unsupported("repository")

    async def scan_filesystem(
        self, target: str, options: dict[str, Any], *, env: dict[str, str] | None = None
    ) -> ScanExecution:
        """Scan a filesystem directory (``target`` is an absolute path)."""
        raise self._unsupported("filesystem")

    async def scan_sbom(
        self, target: str, options: dict[str, Any], *, env: dict[str, str] | None = None
    ) -> ScanExecution:
        """Scan an existing SBOM file (``target`` is an absolute path)."""
        raise self._unsupported("SBOM")


def get_scanner(scanner: Scanner) -> BaseScanner:
    """Return the scanner implementation for ``scanner``.

    Imports are local to avoid a circular import at module load time
    (the concrete scanners import :mod:`app.scanners.base`).
    """
    if scanner is Scanner.TRIVY:
        from app.scanners.trivy import TrivyScanner

        return TrivyScanner()
    if scanner is Scanner.GRYPE:
        from app.scanners.grype import GrypeScanner

        return GrypeScanner()
    raise ScannerError(f"No scanner implementation for {scanner!r}.")
