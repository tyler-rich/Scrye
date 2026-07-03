"""Runtime system/scanner information for the About & health settings tab.

Reports the bundled scanner versions by invoking each binary's version command
with a short timeout, plus basic host facts. Everything here is read-only and
carries no secrets; a missing binary degrades to ``available=False`` rather than
raising, so the About tab still renders on a partial install.
"""

from __future__ import annotations

import asyncio
import platform
from dataclasses import dataclass

from app.core.config import get_settings
from app.scanners.base import ScannerError, resolve_binary, run_command

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
        result = await run_command(
            [executable, *_VERSION_ARGS[name]], timeout=_PROBE_TIMEOUT_SECONDS
        )
    except ScannerError as exc:
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
