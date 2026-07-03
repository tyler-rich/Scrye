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
import os
import shutil
from abc import ABC
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.db.models import Scanner, Severity


class ScannerError(RuntimeError):
    """Raised when a scanner cannot be run or its output cannot be parsed.

    The message is safe to surface to operators and to store on the scan row —
    it never contains secret material (image scans carry no credentials).
    """


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


def scanner_scratch(engine: str) -> tuple[Path, dict[str, str]]:
    """Return an engine's writable cache directory and a scratch env overlay.

    Under the hardened runtime the container runs as a **non-root uid** on a
    **read-only root filesystem**, and ``/tmp`` is a small owner-only tmpfs.
    That makes a scanner's default cache location (``$HOME/.cache`` — which
    resolves under the read-only ``/`` when the numeric ``user:`` leaves ``HOME``
    unset) unwritable, and the tmpfs is both too small for a multi-hundred-MB
    vulnerability DB and, unless its ownership matches the app uid, unwritable at
    all — the ``mkdir /tmp/trivy-XXXXXXXXX: permission denied`` failure.

    Point each engine at a private subdirectory of the persistent, writable
    cache volume for its database, and redirect the subprocess ``TMPDIR`` to a
    sibling scratch dir on that same volume so large temporary extraction never
    lands on the tiny tmpfs (and the DB survives restarts instead of being
    re-downloaded every run). Both directories are created if missing — the
    cache volume starts empty.

    Args:
        engine: Short engine name (``"trivy"`` / ``"grype"`` / ``"syft"``), used
            as the per-engine cache subdirectory name.

    Returns:
        ``(cache_dir, env_overlay)`` where ``cache_dir`` is the engine's cache
        directory and ``env_overlay`` sets ``TMPDIR`` to the shared scratch dir.
    """
    base = get_settings().scanner_cache_dir
    cache_dir = base / engine
    tmp_dir = base / "tmp"
    for path in (cache_dir, tmp_dir):
        path.mkdir(parents=True, exist_ok=True)
    return cache_dir, {"TMPDIR": str(tmp_dir)}


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


def build_env(*overlays: dict[str, str] | None) -> dict[str, str] | None:
    """Merge environment overlays onto the process env.

    Returns ``None`` when no overlay contributes anything, so the caller can let
    the child simply inherit the parent environment.

    Args:
        overlays: Zero or more optional ``{name: value}`` overlays, applied in
            order (later ones win).

    Returns:
        The full child environment, or ``None`` if every overlay was empty.
    """
    if not any(overlays):
        return None
    env = dict(os.environ)
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
