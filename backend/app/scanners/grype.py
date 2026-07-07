"""Grype image scanner: orchestrate ``grype <image> -o json`` and parse it.

Grype's scope is vulnerability matching only (docs/PLAN.md §4.2), so every match
normalizes into a ``vulnerability`` finding. The raw JSON is returned untouched
for storage as the source-of-truth artifact.
"""

from __future__ import annotations

from typing import Any

from app.core.config import get_settings
from app.db.models import FindingClass, Scanner
from app.scanners.base import (
    DESCRIPTION_LIMIT,
    BaseScanner,
    NormalizedFinding,
    ScanExecution,
    ScannerOutputError,
    check_success,
    clip,
    inherited_env,
    load_json_output,
    object_entries,
    object_field,
    resolve_binary,
    run_command,
    scanner_cache_env,
    severity_from_string,
    string_entries,
    tally_severities,
)
from app.scanners.grype_policy import GRYPE_CONFIG_OVERLAY_KEY

#: Engine name used in operator-facing error messages.
_ENGINE = "Grype"

#: Env var that disables Grype's interactive app-update check for batch runs.
_UPDATE_CHECK_ENV = {"GRYPE_CHECK_FOR_APP_UPDATE": "false"}

#: ``fix.state`` values surfaced when Grype lists no fixed versions. A plain
#: ``not-fixed``/``unknown`` stays ``None`` (no fix data), but ``wont-fix`` is a
#: vendor decision worth showing — dropping it would be indistinguishable from
#: having no fix information at all.
_SURFACED_FIX_STATES = frozenset({"wont-fix"})


def build_command(binary: str, reference: str, config_path: str | None = None) -> list[str]:
    """Build the ``grype`` argument vector for a source reference.

    Args:
        binary: Resolved Grype executable path.
        reference: A Grype source string — an image ref, ``dir:<path>``, or
            ``sbom:<path>``.
        config_path: Optional path to a materialized Grype config file (the
            global ignore rules, FEAT-6), passed via ``-c``.

    Returns:
        The full argv list.
    """
    argv = [binary]
    if config_path:
        argv += ["-c", config_path]
    # `--` terminates flag parsing so a reference can never be read as an option.
    argv += ["-o", "json", "--", reference]
    return argv


def scan_env(overlay: dict[str, str] | None = None) -> dict[str, str]:
    """Return the child environment for Grype.

    Suppresses the interactive app-update check so batch runs stay quiet (the DB
    still auto-updates; offline/air-gapped DB import is a later phase) and layers
    on any credential overlay (e.g. a transient ``DOCKER_CONFIG``).
    """
    env = inherited_env()
    env.update(_UPDATE_CHECK_ENV)
    if overlay:
        env.update(overlay)
    return env


def _fixed_version(fix: Any) -> str | None:
    """Extract a human-readable fixed version from a Grype ``fix`` object.

    When no fixed versions are listed, a decision-relevant ``fix.state`` (e.g.
    ``wont-fix``) is surfaced instead of being silently dropped.
    """
    fix_obj = object_field(fix, "fix", _ENGINE)
    versions = string_entries(fix_obj.get("versions"), "fix.versions", _ENGINE)
    if versions:
        return clip(", ".join(versions), 128)
    state = str(fix_obj.get("state") or "").strip().lower()
    if state in _SURFACED_FIX_STATES:
        return state
    return None


def _location(artifact: dict[str, Any]) -> str | None:
    """Derive a location string from a Grype artifact's first location/type.

    Note the cross-engine semantic difference: for Grype this is the path of
    the file the vulnerable *package* was cataloged from (or its package type),
    while Trivy's ``location`` is the scanned result target. Both mean "where
    the finding lives", but they are not directly comparable across engines.
    """
    for loc in object_entries(artifact.get("locations"), "artifact.locations", _ENGINE):
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
        ScannerOutputError: If the output is not valid JSON, or is valid JSON of
            the wrong shape (non-object document, non-array ``matches``,
            non-object entries, a string where a list is expected). The raw
            bytes ride on the error so the worker can persist them for
            diagnosis.
    """
    try:
        document = load_json_output(raw, _ENGINE)
        descriptor = object_field(document.get("descriptor"), "descriptor", _ENGINE)
        version = clip(descriptor.get("version"), 32)

        findings: list[NormalizedFinding] = []
        for match in object_entries(document.get("matches"), "matches", _ENGINE):
            vuln = object_field(match.get("vulnerability"), "vulnerability", _ENGINE)
            artifact = object_field(match.get("artifact"), "artifact", _ENGINE)
            urls = string_entries(vuln.get("urls"), "urls", _ENGINE)
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
    except ScannerOutputError as exc:
        exc.raw_output = raw
        raise


class GrypeScanner(BaseScanner):
    """Scans images, filesystems, and SBOMs with Grype (vulnerabilities only)."""

    scanner = Scanner.GRYPE

    async def _execute(self, reference: str, *, env: dict[str, str] | None) -> ScanExecution:
        """Run Grype against a source reference and normalize its matches.

        Raises:
            ScannerError: If the binary is missing, times out, or exits non-zero.
        """
        binary = resolve_binary(get_settings().grype_binary)
        # Point Grype's DB cache and temp extraction at the writable cache volume:
        # under the hardened runtime the default $HOME/.cache is on the read-only
        # root FS and the tmpfs /tmp is too small for Grype's vulnerability DB.
        overlay = {**scanner_cache_env(), **(env or {})}
        # A materialized global-ignore config (FEAT-6) rides in on a private
        # overlay key; pop it and turn it into a `-c <path>` flag so it is applied
        # but never leaks to the child as a bogus env var.
        config_path = overlay.pop(GRYPE_CONFIG_OVERLAY_KEY, None)
        argv = build_command(binary, reference, config_path=config_path)
        result = await run_command(
            argv, timeout=get_settings().scan_timeout_seconds, env=scan_env(overlay)
        )
        check_success(result, _ENGINE)

        findings, version = parse_output(result.stdout)
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
        """Scan a container image reference."""
        return await self._execute(target, env=env)

    async def scan_filesystem(
        self, target: str, options: dict[str, Any], *, env: dict[str, str] | None = None
    ) -> ScanExecution:
        """Scan a filesystem directory (``grype dir:<path>``)."""
        return await self._execute(f"dir:{target}", env=env)

    async def scan_sbom(
        self, target: str, options: dict[str, Any], *, env: dict[str, str] | None = None
    ) -> ScanExecution:
        """Scan an existing SBOM file (``grype sbom:<path>``)."""
        return await self._execute(f"sbom:{target}", env=env)
