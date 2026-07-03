"""Runtime system/scanner information for the About & health settings tab.

Reports the bundled scanner versions by invoking each binary's version command
with a short timeout, plus basic host facts. Everything here is read-only and
carries no secrets; a missing binary degrades to ``available=False`` rather than
raising, so the About tab still renders on a partial install.
"""

from __future__ import annotations

import asyncio
import json
import platform
from dataclasses import dataclass
from typing import Any

from app.core.config import get_settings
from app.scanners.base import (
    ScannerError,
    build_env,
    resolve_binary,
    run_command,
    scanner_cache_env,
)

#: Version-probe argument (after the binary) for each scanner.
_VERSION_ARGS: dict[str, list[str]] = {
    "trivy": ["--version", "--format", "json"],
    "grype": ["version"],
    "syft": ["version"],
}
_PROBE_TIMEOUT_SECONDS = 10


@dataclass(frozen=True)
class ScannerInfo:
    """Availability and version of one bundled scanner binary."""

    name: str
    available: bool
    version: str | None
    detail: str | None = None


def _first_version_line(text: str) -> str | None:
    """Extract a best-effort version string from a scanner's version output."""
    for line in text.splitlines():
        stripped = line.strip()
        lowered = stripped.lower()
        if lowered.startswith("version:"):
            return stripped.split(":", 1)[1].strip()
        if stripped.lower().startswith(("trivy ", "grype ", "syft ")):
            return stripped.split(" ", 1)[1].strip()
    first = text.strip().splitlines()[0].strip() if text.strip() else ""
    return first or None


async def _probe_scanner(name: str, binary: str) -> ScannerInfo:
    """Run one scanner's version command and parse the result."""
    try:
        executable = resolve_binary(binary)
    except ScannerError as exc:
        return ScannerInfo(name=name, available=False, version=None, detail=str(exc))
    try:
        # Point the probe at the writable cache volume: `trivy --version
        # --format json` reads the vuln-DB metadata under its cache dir, which
        # otherwise defaults to the read-only $HOME/.cache (mkdir /app/.cache:
        # read-only file system).
        result = await run_command(
            [executable, *_VERSION_ARGS[name]],
            timeout=_PROBE_TIMEOUT_SECONDS,
            env=build_env(scanner_cache_env()),
        )
    except (ScannerError, OSError) as exc:
        return ScannerInfo(name=name, available=False, version=None, detail=str(exc))
    if result.returncode != 0:
        return ScannerInfo(name=name, available=False, version=None, detail="version probe failed")
    output = result.stdout.decode("utf-8", "replace") or result.stderr.decode("utf-8", "replace")
    return ScannerInfo(name=name, available=True, version=_first_version_line(output))


async def scanner_versions() -> list[ScannerInfo]:
    """Probe all bundled scanners concurrently and return their info."""
    settings = get_settings()
    binaries = {
        "trivy": settings.trivy_binary,
        "grype": settings.grype_binary,
        "syft": settings.syft_binary,
    }
    return list(
        await asyncio.gather(*(_probe_scanner(name, binary) for name, binary in binaries.items()))
    )


def host_info() -> dict[str, str]:
    """Return non-sensitive host/runtime facts for the About tab."""
    return {
        "python_version": platform.python_version(),
        "platform": platform.platform(terse=True),
    }


@dataclass(frozen=True)
class ScannerDbInfo:
    """Vulnerability-DB freshness for one scanner (dashboard widget)."""

    name: str
    available: bool
    #: When the vuln DB was last built/updated (ISO string), if known.
    updated_at: str | None = None
    #: When the scanner next expects to refresh the DB (ISO string), if known.
    next_update: str | None = None
    detail: str | None = None


def _parse_trivy_db(payload: dict[str, Any]) -> ScannerDbInfo:
    """Extract vuln-DB freshness from ``trivy --version --format json`` output."""
    vuln_db = payload.get("VulnerabilityDB")
    if not isinstance(vuln_db, dict):
        return ScannerDbInfo(name="trivy", available=False, detail="no vulnerability DB present")
    updated = vuln_db.get("UpdatedAt") or vuln_db.get("DownloadedAt")
    return ScannerDbInfo(
        name="trivy",
        available=True,
        updated_at=str(updated) if updated else None,
        next_update=str(vuln_db["NextUpdate"]) if vuln_db.get("NextUpdate") else None,
    )


async def _probe_trivy_db() -> ScannerDbInfo:
    """Probe Trivy's vulnerability-DB freshness (best-effort)."""
    settings = get_settings()
    try:
        binary = resolve_binary(settings.trivy_binary)
        result = await run_command(
            [binary, "--version", "--format", "json"],
            timeout=_PROBE_TIMEOUT_SECONDS,
            env=build_env(scanner_cache_env()),
        )
    except (ScannerError, OSError) as exc:
        return ScannerDbInfo(name="trivy", available=False, detail=str(exc))
    try:
        payload = json.loads(result.stdout or b"{}")
    except json.JSONDecodeError:
        return ScannerDbInfo(name="trivy", available=False, detail="unparseable version output")
    return _parse_trivy_db(payload if isinstance(payload, dict) else {})


async def _probe_grype_db() -> ScannerDbInfo:
    """Probe Grype's vulnerability-DB freshness via ``grype db status``."""
    settings = get_settings()
    try:
        binary = resolve_binary(settings.grype_binary)
        result = await run_command(
            [binary, "db", "status", "-o", "json"],
            timeout=_PROBE_TIMEOUT_SECONDS,
            env=build_env(scanner_cache_env()),
        )
    except (ScannerError, OSError) as exc:
        return ScannerDbInfo(name="grype", available=False, detail=str(exc))
    try:
        payload = json.loads(result.stdout or b"{}")
    except json.JSONDecodeError:
        return ScannerDbInfo(name="grype", available=False, detail="unparseable db status")
    if not isinstance(payload, dict):
        return ScannerDbInfo(name="grype", available=False, detail="unexpected db status")
    # Field names vary across Grype releases; accept the common spellings.
    built = payload.get("built") or payload.get("from")
    error = payload.get("error")
    available = not error and bool(built)
    return ScannerDbInfo(
        name="grype",
        available=available,
        updated_at=str(built) if built else None,
        detail=str(error) if error else None,
    )


async def scanner_db_status() -> list[ScannerDbInfo]:
    """Probe both scanners' vulnerability-DB freshness concurrently."""
    return list(await asyncio.gather(_probe_trivy_db(), _probe_grype_db()))
