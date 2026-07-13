"""Trivy image scanner: orchestrate ``trivy image`` and parse its JSON.

Runs all selected scanners (vuln / misconfig / secret / license) in one pass and
normalizes every result class into Scrye's shared finding model. The raw JSON is
returned untouched for storage as the source-of-truth artifact.
"""

from __future__ import annotations

import json
from typing import Any

import anyio.to_thread

from app.core.config import get_settings
from app.db.models import FindingClass, Scanner
from app.scanners.base import (
    DESCRIPTION_LIMIT,
    BaseScanner,
    NormalizedFinding,
    ScanExecution,
    ScannerError,
    ScannerOutputError,
    build_env,
    check_success,
    clip,
    load_json_output,
    object_entries,
    resolve_binary,
    run_command,
    scanner_cache_env,
    severity_from_string,
    tally_severities,
)

#: Engine name used in operator-facing error messages.
_ENGINE = "Trivy"

#: Timeout for the lightweight ``trivy --version`` probe (not the scan itself).
_VERSION_PROBE_TIMEOUT_SECONDS = 10

# The ``--scanners`` / ``--severity`` token sets below must stay aligned with the
# ``TrivyScannerName`` / ``TrivySeverity`` Literals in app.api.scan_schemas, which
# validate the request; build_command silently drops any token not listed here.

#: Trivy scanner tokens for the ``--scanners`` flag, in canonical order.
TRIVY_SCANNERS: tuple[str, ...] = ("vuln", "misconfig", "secret", "license")

#: Trivy severity tokens for the ``--severity`` flag, in canonical order.
TRIVY_SEVERITIES: tuple[str, ...] = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def _common_flags(options: dict[str, Any], cache_dir: str | None = None) -> list[str]:
    """Build the flags shared by ``trivy image`` and ``trivy repo``.

    Covers output format, scanner selection, severity filter, ``ignore_unfixed``,
    an explicit ``--cache-dir`` (so the vuln DB lands on the writable cache
    volume rather than the read-only default ``$HOME/.cache``), and the optional
    shared Trivy-server vuln-DB cache. Selections are re-ordered into canonical
    order and unknown tokens dropped, so the argv is stable regardless of how
    options were supplied.
    """
    settings = get_settings()
    scanners = options.get("scanners") or list(TRIVY_SCANNERS)
    severities = options.get("severity") or list(TRIVY_SEVERITIES)
    scanners = [s for s in TRIVY_SCANNERS if s in scanners]
    severities = [s for s in TRIVY_SEVERITIES if s in severities]

    flags = [
        "--quiet",
        "--format",
        "json",
        "--scanners",
        ",".join(scanners),
        "--severity",
        ",".join(severities),
    ]
    if cache_dir:
        flags += ["--cache-dir", cache_dir]
    if options.get("ignore_unfixed"):
        flags.append("--ignore-unfixed")
    if settings.trivy_server_url:
        flags += ["--server", settings.trivy_server_url]
    return flags


def build_command(
    binary: str, target: str, options: dict[str, Any], cache_dir: str | None = None
) -> list[str]:
    """Build the ``trivy image`` argument vector.

    Args:
        binary: Resolved Trivy executable path.
        target: The image reference to scan.
        options: Validated scan options (scanners, severity, ignore_unfixed).
        cache_dir: Optional explicit ``--cache-dir`` (a writable location for the
            vulnerability DB); omitted from argv when ``None``.

    Returns:
        The full argv list.
    """
    return [binary, "image", *_common_flags(options, cache_dir), "--", target]


def build_repo_command(
    binary: str, target: str, options: dict[str, Any], cache_dir: str | None = None
) -> list[str]:
    """Build the ``trivy repo`` argument vector.

    Args:
        binary: Resolved Trivy executable path.
        target: The repository clone URL.
        options: Validated scan options; may carry a single ``branch``,
            ``commit``, or ``tag`` to check out.
        cache_dir: Optional explicit ``--cache-dir`` (a writable location for the
            vulnerability DB); omitted from argv when ``None``.

    Returns:
        The full argv list.
    """
    argv = [binary, "repo", *_common_flags(options, cache_dir)]
    for flag in ("branch", "commit", "tag"):
        value = options.get(flag)
        if value:
            argv += [f"--{flag}", str(value)]
            break  # Trivy accepts only one ref selector; first set wins.
    # `--` terminates flag parsing so a target can never be read as an option.
    argv += ["--", target]
    return argv


def parse_output(raw: bytes) -> list[NormalizedFinding]:
    """Parse Trivy JSON output into normalized findings.

    Args:
        raw: The raw stdout bytes from ``trivy image --format json``.

    Returns:
        The normalized findings across every result class.

    Raises:
        ScannerOutputError: If the output is not valid JSON, or is valid JSON of
            the wrong shape (non-object document, non-array ``Results``,
            non-object entries). The raw bytes ride on the error so the worker
            can persist them for diagnosis.
    """
    try:
        document = load_json_output(raw, _ENGINE)
        findings: list[NormalizedFinding] = []
        for result in object_entries(document.get("Results"), "Results", _ENGINE):
            target = result.get("Target")
            findings.extend(_parse_vulnerabilities(result.get("Vulnerabilities"), target))
            findings.extend(_parse_misconfigurations(result.get("Misconfigurations"), target))
            findings.extend(_parse_secrets(result.get("Secrets"), target))
            findings.extend(_parse_licenses(result.get("Licenses"), target))
        return findings
    except ScannerOutputError as exc:
        exc.raw_output = raw
        raise


def _parse_vulnerabilities(items: Any, target: str | None) -> list[NormalizedFinding]:
    """Normalize a Trivy result's ``Vulnerabilities`` array."""
    out: list[NormalizedFinding] = []
    for item in object_entries(items, "Vulnerabilities", _ENGINE):
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
    for item in object_entries(items, "Misconfigurations", _ENGINE):
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
    for item in object_entries(items, "Secrets", _ENGINE):
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
    for item in object_entries(items, "Licenses", _ENGINE):
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


async def probe_version(binary: str, env: dict[str, str] | None) -> str | None:
    """Return the Trivy engine version via ``trivy --version --format json``.

    Trivy's scan report carries no engine version (its ``SchemaVersion`` is the
    report format, not the binary), so — unlike Grype's ``descriptor`` block —
    the version must come from a separate probe. Best-effort: any failure
    returns ``None`` rather than failing the scan the version annotates.
    """
    try:
        result = await run_command(
            [binary, "--version", "--format", "json"],
            timeout=_VERSION_PROBE_TIMEOUT_SECONDS,
            env=build_env(env),
        )
        if result.returncode != 0:
            return None
        payload = json.loads(result.stdout or b"{}")
    except (ScannerError, OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    return clip(payload.get("Version"), 32)


class TrivyScanner(BaseScanner):
    """Scans images and git repositories with Trivy (all selected scanners)."""

    scanner = Scanner.TRIVY

    async def _execute(self, argv: list[str], *, env: dict[str, str] | None) -> ScanExecution:
        """Run a Trivy argv to completion and normalize its JSON output.

        Raises:
            ScannerError: If the binary is missing, times out, or exits non-zero.
        """
        version = await probe_version(argv[0], env)
        result = await run_command(
            argv, timeout=get_settings().scan_timeout_seconds, env=build_env(env)
        )
        check_success(result, _ENGINE)

        # Parse + normalize (json.loads over up to SCRYE_SCANNER_MAX_OUTPUT_BYTES
        # plus the per-finding loop) is seconds of pure CPU on a large report; hop
        # it off the loop so a big scan can't freeze every request — including the
        # container healthcheck's /healthz poll — during the parse (CON-4). Matches
        # the anyio.to_thread.run_sync pattern CON-5 used for blocking DB work.
        findings = await anyio.to_thread.run_sync(parse_output, result.stdout)
        return ScanExecution(
            raw_output=result.stdout,
            findings=findings,
            severity_counts=tally_severities(findings),
            command=argv,
            scanner_version=version,
        )

    async def scan_image(
        self, target: str, options: dict[str, Any], *, env: dict[str, str] | None = None
    ) -> ScanExecution:
        """Run ``trivy image`` against ``target`` and normalize the results."""
        binary = resolve_binary(get_settings().trivy_binary)
        cache_env = scanner_cache_env()
        argv = build_command(binary, target, options, cache_env["TRIVY_CACHE_DIR"])
        return await self._execute(argv, env={**cache_env, **(env or {})})

    async def scan_repo(
        self, target: str, options: dict[str, Any], *, env: dict[str, str] | None = None
    ) -> ScanExecution:
        """Run ``trivy repo`` against ``target`` (a clone URL) and normalize it."""
        binary = resolve_binary(get_settings().trivy_binary)
        cache_env = scanner_cache_env()
        argv = build_repo_command(binary, target, options, cache_env["TRIVY_CACHE_DIR"])
        return await self._execute(argv, env={**cache_env, **(env or {})})
