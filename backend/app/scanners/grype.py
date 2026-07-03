"""Grype image scanner: orchestrate ``grype <image> -o json`` and parse it.

Grype's scope is vulnerability matching only (docs/PLAN.md §4.2), so every match
normalizes into a ``vulnerability`` finding. The raw JSON is returned untouched
for storage as the source-of-truth artifact.
"""

from __future__ import annotations

import json
import os
from typing import Any

from app.core.config import get_settings
from app.db.models import FindingClass, Scanner
from app.scanners.base import (
    DESCRIPTION_LIMIT,
    ImageScanner,
    NormalizedFinding,
    ScanExecution,
    ScannerError,
    clip,
    resolve_binary,
    run_command,
    severity_from_string,
    tally_severities,
)


def build_command(binary: str, target: str) -> list[str]:
    """Build the ``grype`` argument vector for an image scan."""
    return [binary, target, "-o", "json"]


def scan_env() -> dict[str, str]:
    """Return the child environment for Grype.

    Suppresses the interactive app-update check so batch runs stay quiet; the DB
    still auto-updates (offline/air-gapped DB import is a later phase).
    """
    env = dict(os.environ)
    env["GRYPE_CHECK_FOR_APP_UPDATE"] = "false"
    return env


def _fixed_version(fix: Any) -> str | None:
    """Extract a human-readable fixed version from a Grype ``fix`` object."""
    if not isinstance(fix, dict):
        return None
    versions = fix.get("versions") or []
    if versions:
        return clip(", ".join(str(v) for v in versions), 128)
    return None


def _location(artifact: dict[str, Any]) -> str | None:
    """Derive a location string from a Grype artifact's first location/type."""
    for loc in artifact.get("locations") or []:
        path = loc.get("path")
        if path:
            return clip(path, 512)
    return clip(artifact.get("type"), 512)


def parse_output(raw: bytes) -> tuple[list[NormalizedFinding], str | None]:
    """Parse Grype JSON output into normalized findings.

    Args:
        raw: The raw stdout bytes from ``grype -o json``.

    Returns:
        A tuple of (normalized findings, grype version or ``None``).

    Raises:
        ScannerError: If the output is not valid JSON.
    """
    try:
        document = json.loads(raw or b"{}")
    except json.JSONDecodeError as exc:
        raise ScannerError(f"Grype produced output that is not valid JSON: {exc}.") from exc

    version = None
    descriptor = document.get("descriptor")
    if isinstance(descriptor, dict):
        version = clip(descriptor.get("version"), 32)

    findings: list[NormalizedFinding] = []
    for match in document.get("matches") or []:
        vuln = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        urls = vuln.get("urls") or []
        findings.append(
            NormalizedFinding(
                finding_class=FindingClass.VULNERABILITY.value,
                severity=severity_from_string(vuln.get("severity")),
                vuln_id=clip(vuln.get("id"), 128),
                pkg_name=clip(artifact.get("name"), 255),
                installed_version=clip(artifact.get("version"), 128),
                fixed_version=_fixed_version(vuln.get("fix")),
                title=clip(vuln.get("id"), 512),
                description=clip(vuln.get("description"), DESCRIPTION_LIMIT),
                location=_location(artifact),
                primary_url=clip(vuln.get("dataSource") or (urls[0] if urls else None), 512),
            )
        )
    return findings, version


class GrypeImageScanner(ImageScanner):
    """Scans a container image with ``grype`` (vulnerabilities only)."""

    scanner = Scanner.GRYPE

    async def scan_image(self, target: str, options: dict[str, Any]) -> ScanExecution:
        """Run Grype against ``target`` and normalize the matches.

        Raises:
            ScannerError: If the binary is missing, times out, or exits non-zero.
        """
        settings = get_settings()
        binary = resolve_binary(settings.grype_binary)
        argv = build_command(binary, target)
        result = await run_command(argv, timeout=settings.scan_timeout_seconds, env=scan_env())
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", "replace").strip() or "no error output"
            raise ScannerError(f"Grype exited with code {result.returncode}: {detail}")

        findings, version = parse_output(result.stdout)
        return ScanExecution(
            raw_output=result.stdout,
            findings=findings,
            severity_counts=tally_severities(findings),
            command=argv,
            scanner_version=version,
        )
