"""Trivy image scanner: orchestrate ``trivy image`` and parse its JSON.

Runs all selected scanners (vuln / misconfig / secret / license) in one pass and
normalizes every result class into Scrye's shared finding model. The raw JSON is
returned untouched for storage as the source-of-truth artifact.
"""

from __future__ import annotations

import json
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

# The ``--scanners`` / ``--severity`` token sets below must stay aligned with the
# ``TrivyScannerName`` / ``TrivySeverity`` Literals in app.api.scan_schemas, which
# validate the request; build_command silently drops any token not listed here.

#: Trivy scanner tokens for the ``--scanners`` flag, in canonical order.
TRIVY_SCANNERS: tuple[str, ...] = ("vuln", "misconfig", "secret", "license")

#: Trivy severity tokens for the ``--severity`` flag, in canonical order.
TRIVY_SEVERITIES: tuple[str, ...] = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def build_command(binary: str, target: str, options: dict[str, Any]) -> list[str]:
    """Build the ``trivy image`` argument vector.

    Args:
        binary: Resolved Trivy executable path.
        target: The image reference to scan.
        options: Validated scan options (scanners, severity, ignore_unfixed).

    Returns:
        The full argv list.
    """
    settings = get_settings()
    scanners = options.get("scanners") or list(TRIVY_SCANNERS)
    severities = options.get("severity") or list(TRIVY_SEVERITIES)
    # Preserve canonical ordering regardless of how options were supplied.
    scanners = [s for s in TRIVY_SCANNERS if s in scanners]
    severities = [s for s in TRIVY_SEVERITIES if s in severities]

    argv = [
        binary,
        "image",
        "--quiet",
        "--format",
        "json",
        "--scanners",
        ",".join(scanners),
        "--severity",
        ",".join(severities),
    ]
    if options.get("ignore_unfixed"):
        argv.append("--ignore-unfixed")
    if settings.trivy_server_url:
        argv += ["--server", settings.trivy_server_url]
    argv.append(target)
    return argv


def parse_output(raw: bytes) -> list[NormalizedFinding]:
    """Parse Trivy JSON output into normalized findings.

    Args:
        raw: The raw stdout bytes from ``trivy image --format json``.

    Returns:
        The normalized findings across every result class.

    Raises:
        ScannerError: If the output is not valid JSON.
    """
    try:
        document = json.loads(raw or b"{}")
    except json.JSONDecodeError as exc:
        raise ScannerError(f"Trivy produced output that is not valid JSON: {exc}.") from exc

    findings: list[NormalizedFinding] = []
    for result in document.get("Results") or []:
        target = result.get("Target")
        findings.extend(_parse_vulnerabilities(result.get("Vulnerabilities"), target))
        findings.extend(_parse_misconfigurations(result.get("Misconfigurations"), target))
        findings.extend(_parse_secrets(result.get("Secrets"), target))
        findings.extend(_parse_licenses(result.get("Licenses"), target))
    return findings


def _parse_vulnerabilities(items: Any, target: str | None) -> list[NormalizedFinding]:
    """Normalize a Trivy result's ``Vulnerabilities`` array."""
    out: list[NormalizedFinding] = []
    for item in items or []:
        out.append(
            NormalizedFinding(
                finding_class=FindingClass.VULNERABILITY.value,
                severity=severity_from_string(item.get("Severity")),
                vuln_id=clip(item.get("VulnerabilityID"), 128),
                pkg_name=clip(item.get("PkgName"), 255),
                installed_version=clip(item.get("InstalledVersion"), 128),
                fixed_version=clip(item.get("FixedVersion"), 128),
                title=clip(item.get("Title") or item.get("VulnerabilityID"), 512),
                description=clip(item.get("Description"), DESCRIPTION_LIMIT),
                location=clip(target, 512),
                primary_url=clip(item.get("PrimaryURL"), 512),
            )
        )
    return out


def _parse_misconfigurations(items: Any, target: str | None) -> list[NormalizedFinding]:
    """Normalize a Trivy result's ``Misconfigurations`` array (only failures)."""
    out: list[NormalizedFinding] = []
    for item in items or []:
        # Trivy reports PASS/FAIL/EXCEPTION statuses; only failures are findings.
        if str(item.get("Status", "")).upper() not in {"", "FAIL"}:
            continue
        out.append(
            NormalizedFinding(
                finding_class=FindingClass.MISCONFIGURATION.value,
                severity=severity_from_string(item.get("Severity")),
                vuln_id=clip(item.get("ID") or item.get("AVDID"), 128),
                title=clip(item.get("Title"), 512),
                description=clip(item.get("Message") or item.get("Description"), DESCRIPTION_LIMIT),
                location=clip(target, 512),
                primary_url=clip(item.get("PrimaryURL"), 512),
            )
        )
    return out


def _parse_secrets(items: Any, target: str | None) -> list[NormalizedFinding]:
    """Normalize a Trivy result's ``Secrets`` array."""
    out: list[NormalizedFinding] = []
    for item in items or []:
        start = item.get("StartLine")
        location = target
        if target and start is not None:
            location = f"{target}:{start}"
        out.append(
            NormalizedFinding(
                finding_class=FindingClass.SECRET.value,
                severity=severity_from_string(item.get("Severity")),
                vuln_id=clip(item.get("RuleID"), 128),
                title=clip(item.get("Title") or item.get("Category"), 512),
                # Never store the matched secret value; the category/title is enough.
                description=clip(item.get("Category"), DESCRIPTION_LIMIT),
                location=clip(location, 512),
            )
        )
    return out


def _parse_licenses(items: Any, target: str | None) -> list[NormalizedFinding]:
    """Normalize a Trivy result's ``Licenses`` array."""
    out: list[NormalizedFinding] = []
    for item in items or []:
        name = item.get("Name")
        out.append(
            NormalizedFinding(
                finding_class=FindingClass.LICENSE.value,
                severity=severity_from_string(item.get("Severity")),
                vuln_id=clip(name, 128),
                pkg_name=clip(item.get("PkgName"), 255),
                title=clip(name, 512),
                description=clip(item.get("Category"), DESCRIPTION_LIMIT),
                location=clip(item.get("FilePath") or target, 512),
                primary_url=clip(item.get("Link"), 512),
            )
        )
    return out


class TrivyImageScanner(ImageScanner):
    """Scans a container image with ``trivy image`` (all selected scanners)."""

    scanner = Scanner.TRIVY

    async def scan_image(self, target: str, options: dict[str, Any]) -> ScanExecution:
        """Run Trivy against ``target`` and normalize the results.

        Raises:
            ScannerError: If the binary is missing, times out, or exits non-zero.
        """
        settings = get_settings()
        binary = resolve_binary(settings.trivy_binary)
        argv = build_command(binary, target, options)
        result = await run_command(argv, timeout=settings.scan_timeout_seconds)
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", "replace").strip() or "no error output"
            raise ScannerError(f"Trivy exited with code {result.returncode}: {detail}")

        findings = parse_output(result.stdout)
        return ScanExecution(
            raw_output=result.stdout,
            findings=findings,
            severity_counts=tally_severities(findings),
            command=argv,
        )
