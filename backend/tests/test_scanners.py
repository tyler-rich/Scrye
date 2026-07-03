"""Tests for scanner command building and JSON normalization.

These exercise the parsers directly with representative Trivy/Grype JSON so no
real binaries are needed. Command-building tests assert the argument vectors
match the shapes documented in docs/PLAN.md §4.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.db.models import FindingClass, Severity
from app.scanners import base, grype, syft, trivy

# --- Trivy: command building -------------------------------------------------


def test_trivy_command_defaults_to_all_scanners_and_severities() -> None:
    argv = trivy.build_command("/usr/local/bin/trivy", "alpine:3.19", {})
    assert argv[:5] == ["/usr/local/bin/trivy", "image", "--quiet", "--format", "json"]
    assert "--scanners" in argv
    assert argv[argv.index("--scanners") + 1] == "vuln,misconfig,secret,license"
    assert argv[argv.index("--severity") + 1] == "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
    assert argv[-1] == "alpine:3.19"
    assert "--ignore-unfixed" not in argv


def test_trivy_command_honors_selection_and_flags() -> None:
    argv = trivy.build_command(
        "trivy",
        "repo/img:tag",
        {"scanners": ["secret", "vuln"], "severity": ["CRITICAL", "HIGH"], "ignore_unfixed": True},
    )
    # Selection is re-ordered into canonical order regardless of input order.
    assert argv[argv.index("--scanners") + 1] == "vuln,secret"
    assert argv[argv.index("--severity") + 1] == "HIGH,CRITICAL"
    assert "--ignore-unfixed" in argv


def test_trivy_command_adds_server_when_configured(monkeypatch) -> None:
    from app.core import config

    monkeypatch.setattr(
        config, "get_settings", lambda: config.Settings(trivy_server_url="http://trivy:4954")
    )
    monkeypatch.setattr(trivy, "get_settings", config.get_settings)
    argv = trivy.build_command("trivy", "alpine", {})
    assert argv[argv.index("--server") + 1] == "http://trivy:4954"


# --- Trivy: parsing ----------------------------------------------------------

TRIVY_SAMPLE = {
    "SchemaVersion": 2,
    "ArtifactName": "alpine:3.19",
    "Results": [
        {
            "Target": "alpine:3.19 (alpine 3.19.0)",
            "Class": "os-pkgs",
            "Type": "alpine",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-0001",
                    "PkgName": "openssl",
                    "InstalledVersion": "3.1.0",
                    "FixedVersion": "3.1.4",
                    "Severity": "CRITICAL",
                    "Title": "openssl: something bad",
                    "Description": "A bad thing.",
                    "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-0001",
                },
                {
                    "VulnerabilityID": "CVE-2024-0002",
                    "PkgName": "zlib",
                    "InstalledVersion": "1.3",
                    "Severity": "medium",
                },
            ],
        },
        {
            "Target": "Dockerfile",
            "Class": "config",
            "Type": "dockerfile",
            "Misconfigurations": [
                {
                    "ID": "DS002",
                    "Title": "Image user should not be root",
                    "Message": "Specify a non-root USER.",
                    "Severity": "HIGH",
                    "Status": "FAIL",
                    "PrimaryURL": "https://avd.aquasec.com/misconfig/ds002",
                },
                {
                    "ID": "DS026",
                    "Title": "passing check",
                    "Severity": "LOW",
                    "Status": "PASS",
                },
            ],
        },
        {
            "Target": "app/config.yaml",
            "Class": "secret",
            "Secrets": [
                {
                    "RuleID": "aws-access-key-id",
                    "Category": "AWS",
                    "Severity": "CRITICAL",
                    "Title": "AWS Access Key ID",
                    "StartLine": 12,
                    "Match": "AKIA****************",
                }
            ],
        },
        {
            "Target": "usr/share/doc",
            "Class": "license",
            "Licenses": [
                {
                    "Severity": "UNKNOWN",
                    "Category": "restricted",
                    "PkgName": "somepkg",
                    "Name": "GPL-3.0",
                    "Link": "https://spdx.org/licenses/GPL-3.0",
                }
            ],
        },
    ],
}


def test_trivy_parse_normalizes_all_result_classes() -> None:
    findings = trivy.parse_output(json.dumps(TRIVY_SAMPLE).encode())
    classes = {f.finding_class for f in findings}
    assert classes == {
        FindingClass.VULNERABILITY.value,
        FindingClass.MISCONFIGURATION.value,
        FindingClass.SECRET.value,
        FindingClass.LICENSE.value,
    }
    # The passing misconfiguration (Status=PASS) is not a finding.
    assert sum(1 for f in findings if f.finding_class == "misconfiguration") == 1

    vuln = next(f for f in findings if f.vuln_id == "CVE-2024-0001")
    assert vuln.severity is Severity.CRITICAL
    assert vuln.pkg_name == "openssl"
    assert vuln.fixed_version == "3.1.4"

    # Lower-cased severity strings still map.
    assert next(f for f in findings if f.vuln_id == "CVE-2024-0002").severity is Severity.MEDIUM


def test_trivy_parse_never_stores_the_matched_secret_value() -> None:
    findings = trivy.parse_output(json.dumps(TRIVY_SAMPLE).encode())
    secret = next(f for f in findings if f.finding_class == "secret")
    assert secret.severity is Severity.CRITICAL
    assert secret.location == "app/config.yaml:12"
    # The raw match must never leak into a normalized field.
    for value in (secret.description, secret.title, secret.pkg_name):
        assert value is None or "AKIA" not in value


def test_trivy_parse_handles_empty_and_null_results() -> None:
    assert trivy.parse_output(b"{}") == []
    assert trivy.parse_output(json.dumps({"Results": None}).encode()) == []


def test_trivy_parse_rejects_non_json() -> None:
    import pytest

    with pytest.raises(base.ScannerError):
        trivy.parse_output(b"not json at all")


# --- Grype: command building + parsing ---------------------------------------


def test_grype_command_requests_json() -> None:
    assert grype.build_command("grype", "alpine:3.19") == ["grype", "alpine:3.19", "-o", "json"]


def test_grype_env_disables_update_check() -> None:
    assert grype.scan_env()["GRYPE_CHECK_FOR_APP_UPDATE"] == "false"


GRYPE_SAMPLE = {
    "matches": [
        {
            "vulnerability": {
                "id": "CVE-2024-0001",
                "severity": "Critical",
                "description": "A bad thing.",
                "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
                "urls": ["https://example.test/a"],
                "fix": {"versions": ["3.1.4"], "state": "fixed"},
            },
            "artifact": {
                "name": "openssl",
                "version": "3.1.0",
                "type": "apk",
                "locations": [{"path": "/lib/apk/db/installed"}],
            },
        },
        {
            "vulnerability": {
                "id": "GHSA-xxxx",
                "severity": "Negligible",
                "fix": {"versions": [], "state": "not-fixed"},
            },
            "artifact": {"name": "musl", "version": "1.2.4", "type": "apk", "locations": []},
        },
    ],
    "descriptor": {"name": "grype", "version": "0.115.0"},
}


def test_grype_parse_normalizes_matches_and_version() -> None:
    findings, version = grype.parse_output(json.dumps(GRYPE_SAMPLE).encode())
    assert version == "0.115.0"
    assert all(f.finding_class == FindingClass.VULNERABILITY.value for f in findings)

    crit = next(f for f in findings if f.vuln_id == "CVE-2024-0001")
    assert crit.severity is Severity.CRITICAL
    assert crit.pkg_name == "openssl"
    assert crit.installed_version == "3.1.0"
    assert crit.fixed_version == "3.1.4"
    assert crit.location == "/lib/apk/db/installed"

    negligible = next(f for f in findings if f.vuln_id == "GHSA-xxxx")
    assert negligible.severity is Severity.NEGLIGIBLE
    assert negligible.fixed_version is None
    # Falls back to the artifact type when there are no file locations.
    assert negligible.location == "apk"


def test_grype_parse_handles_empty_document() -> None:
    findings, version = grype.parse_output(b"{}")
    assert findings == []
    assert version is None


def test_tally_severities_counts_every_level() -> None:
    findings, _ = grype.parse_output(json.dumps(GRYPE_SAMPLE).encode())
    counts = base.tally_severities(findings)
    assert counts[Severity.CRITICAL] == 1
    assert counts[Severity.NEGLIGIBLE] == 1
    assert counts[Severity.LOW] == 0


# --- Trivy repo command (Phase 3) --------------------------------------------


def test_trivy_repo_command_basic() -> None:
    argv = trivy.build_repo_command("trivy", "https://github.com/org/repo.git", {})
    assert argv[:2] == ["trivy", "repo"]
    assert argv[-1] == "https://github.com/org/repo.git"
    assert argv[argv.index("--scanners") + 1] == "vuln,misconfig,secret,license"


def test_trivy_repo_command_adds_single_ref_selector() -> None:
    argv = trivy.build_repo_command(
        "trivy", "https://x/y.git", {"branch": "main", "commit": "abc123"}
    )
    # Only the first set selector (branch) is emitted; Trivy accepts just one.
    assert "--branch" in argv and argv[argv.index("--branch") + 1] == "main"
    assert "--commit" not in argv
    assert "--tag" not in argv


def test_trivy_repo_command_tag_selector() -> None:
    argv = trivy.build_repo_command("trivy", "https://x/y.git", {"tag": "v1.2.3"})
    assert argv[argv.index("--tag") + 1] == "v1.2.3"


# --- Grype filesystem / SBOM references (Phase 3) ----------------------------


def test_grype_command_accepts_dir_and_sbom_references() -> None:
    assert grype.build_command("grype", "dir:/srv/app") == ["grype", "dir:/srv/app", "-o", "json"]
    assert grype.build_command("grype", "sbom:/tmp/s.json")[1] == "sbom:/tmp/s.json"


def test_grype_scan_env_layers_overlay_over_update_check() -> None:
    env = grype.scan_env({"DOCKER_CONFIG": "/tmp/cfg"})
    assert env["GRYPE_CHECK_FOR_APP_UPDATE"] == "false"
    assert env["DOCKER_CONFIG"] == "/tmp/cfg"


# --- Syft SBOM generation (Phase 3) ------------------------------------------


def test_syft_command_and_default_format() -> None:
    argv = syft.build_command("syft", "alpine:3.19", "cyclonedx-json")
    assert argv == ["syft", "--quiet", "-o", "cyclonedx-json", "alpine:3.19"]


def test_syft_resolve_format_defaults_and_validates() -> None:
    assert syft.resolve_format(None) == "cyclonedx-json"
    assert syft.resolve_format("bogus") == "cyclonedx-json"
    assert syft.resolve_format("spdx-json") == "spdx-json"


# --- Scanner cache/scratch redirection (hardened read-only-rootfs runtime) ----
#
# Regression guard for the `mkdir /tmp/trivy-XXXXXXXXX: permission denied`
# failure: under the hardened Compose config the container runs as a non-root
# uid on a read-only root FS with a small tmpfs /tmp, so the scanners must write
# their vulnerability DB and temp extraction to the writable /cache volume, never
# to the default $HOME/.cache or the shared /tmp.


class _CapturingRun:
    """Async ``run_command`` stand-in that records the last argv + env."""

    def __init__(self, stdout: bytes) -> None:
        self.stdout = stdout
        self.argv: list[str] | None = None
        self.env: dict[str, str] | None = None

    async def __call__(self, argv, *, timeout, env=None) -> base.CommandResult:
        self.argv = argv
        self.env = env
        return base.CommandResult(returncode=0, stdout=self.stdout, stderr=b"", argv=argv)


def _patch_scanner_cache(monkeypatch, cache_root):
    """Point every scanner's cache volume + binary paths at test-safe values."""
    from app.core import config

    settings = config.Settings(
        scanner_cache_dir=cache_root,
        trivy_binary="/usr/local/bin/trivy",
        grype_binary="/usr/local/bin/grype",
        syft_binary="/usr/local/bin/syft",
    )
    for module in (base, trivy, grype, syft):
        monkeypatch.setattr(module, "get_settings", lambda: settings)
    return settings


def test_scanner_scratch_creates_dirs_off_the_shared_tmp(monkeypatch, tmp_path) -> None:
    _patch_scanner_cache(monkeypatch, tmp_path)
    cache_dir, overlay = base.scanner_scratch("trivy")
    assert cache_dir == tmp_path / "trivy"
    assert cache_dir.is_dir()
    assert overlay["TMPDIR"] == str(tmp_path / "tmp")
    assert (tmp_path / "tmp").is_dir()
    # Scratch resolves onto the configured cache volume, not a default location.
    assert Path(overlay["TMPDIR"]).parent == tmp_path


def test_trivy_command_includes_cache_dir_when_given() -> None:
    argv = trivy.build_command("trivy", "alpine", {}, "/cache/trivy")
    assert argv[argv.index("--cache-dir") + 1] == "/cache/trivy"
    assert argv[-1] == "alpine"  # target still last
    repo = trivy.build_repo_command("trivy", "https://x/y.git", {}, "/cache/trivy")
    assert repo[repo.index("--cache-dir") + 1] == "/cache/trivy"


@pytest.mark.asyncio
async def test_trivy_image_scan_redirects_db_cache_and_tmpdir(monkeypatch, tmp_path) -> None:
    _patch_scanner_cache(monkeypatch, tmp_path)
    run = _CapturingRun(json.dumps({"Results": []}).encode())
    monkeypatch.setattr(trivy, "run_command", run)

    await trivy.TrivyScanner().scan_image("alpine:3.19", {})

    assert run.argv[run.argv.index("--cache-dir") + 1] == str(tmp_path / "trivy")
    assert run.env["TMPDIR"] == str(tmp_path / "tmp")


@pytest.mark.asyncio
async def test_trivy_repo_scan_redirects_db_cache_and_tmpdir(monkeypatch, tmp_path) -> None:
    _patch_scanner_cache(monkeypatch, tmp_path)
    run = _CapturingRun(json.dumps({"Results": []}).encode())
    monkeypatch.setattr(trivy, "run_command", run)

    await trivy.TrivyScanner().scan_repo("https://github.com/org/repo.git", {})

    assert run.argv[run.argv.index("--cache-dir") + 1] == str(tmp_path / "trivy")
    assert run.env["TMPDIR"] == str(tmp_path / "tmp")


@pytest.mark.asyncio
async def test_grype_scan_redirects_db_cache_and_tmpdir(monkeypatch, tmp_path) -> None:
    _patch_scanner_cache(monkeypatch, tmp_path)
    run = _CapturingRun(json.dumps({"matches": []}).encode())
    monkeypatch.setattr(grype, "run_command", run)

    await grype.GrypeScanner().scan_image("alpine:3.19", {})

    assert run.env["GRYPE_DB_CACHE_DIR"] == str(tmp_path / "grype" / "db")
    assert run.env["TMPDIR"] == str(tmp_path / "tmp")
    # The update-check suppression is preserved alongside the new overlay.
    assert run.env["GRYPE_CHECK_FOR_APP_UPDATE"] == "false"


@pytest.mark.asyncio
async def test_grype_scan_overlay_does_not_lose_credentials(monkeypatch, tmp_path) -> None:
    _patch_scanner_cache(monkeypatch, tmp_path)
    run = _CapturingRun(json.dumps({"matches": []}).encode())
    monkeypatch.setattr(grype, "run_command", run)

    await grype.GrypeScanner().scan_image("alpine:3.19", {}, env={"DOCKER_CONFIG": "/tmp/cfg"})

    # A registry-credential overlay survives the cache/tmpdir merge.
    assert run.env["DOCKER_CONFIG"] == "/tmp/cfg"
    assert run.env["GRYPE_DB_CACHE_DIR"] == str(tmp_path / "grype" / "db")


@pytest.mark.asyncio
async def test_syft_sbom_redirects_tmpdir(monkeypatch, tmp_path) -> None:
    _patch_scanner_cache(monkeypatch, tmp_path)
    run = _CapturingRun(b"{}")
    monkeypatch.setattr(syft, "run_command", run)

    await syft.generate_sbom("alpine:3.19")

    assert run.env["TMPDIR"] == str(tmp_path / "tmp")
