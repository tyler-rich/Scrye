"""Tests for scanner command building and JSON normalization.

These exercise the parsers directly with representative Trivy/Grype JSON so no
real binaries are needed. Command-building tests assert the argument vectors
match the shapes documented in docs/ARCHIVE.md §4.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.core import system_info
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
    with pytest.raises(base.ScannerError):
        trivy.parse_output(b"not json at all")


# --- Wrong-shape output: valid JSON that is not a Trivy/Grype report ----------
#
# Regression guards: these inputs previously escaped the JSON-decode guard and
# crashed with an unguarded AttributeError (bypassing ScannerError handling and
# skipping raw-output persistence). They must fail as a diagnosable
# ScannerOutputError that carries the raw bytes for the worker to store.


@pytest.mark.parametrize(
    "raw",
    [
        b"null",  # top-level null
        b"[]",  # top-level array
        b'"a string"',  # top-level scalar
        b"42",
        json.dumps({"Results": "not-a-list"}).encode(),
        json.dumps({"Results": {"Target": "x"}}).encode(),
        json.dumps({"Results": ["not-a-dict"]}).encode(),
        json.dumps({"Results": [{"Vulnerabilities": "oops"}]}).encode(),
        json.dumps({"Results": [{"Vulnerabilities": ["not-a-dict"]}]}).encode(),
        json.dumps({"Results": [{"Misconfigurations": 7}]}).encode(),
        json.dumps({"Results": [{"Secrets": {"RuleID": "x"}}]}).encode(),
        json.dumps({"Results": [{"Licenses": [42]}]}).encode(),
    ],
)
def test_trivy_parse_rejects_wrong_shape_json(raw: bytes) -> None:
    with pytest.raises(base.ScannerOutputError) as excinfo:
        trivy.parse_output(raw)
    # The raw output rides on the error so the worker can persist it.
    assert excinfo.value.raw_output == raw
    # The error is a ScannerError (handled by the worker's failure path).
    assert isinstance(excinfo.value, base.ScannerError)


def test_trivy_parse_attaches_raw_even_for_invalid_json() -> None:
    with pytest.raises(base.ScannerOutputError) as excinfo:
        trivy.parse_output(b"not json at all")
    assert excinfo.value.raw_output == b"not json at all"


# --- Shared base helpers (load_json_output / check_success / shape guards) ----


def test_load_json_output_defaults_empty_output_to_empty_report() -> None:
    assert base.load_json_output(b"", "Trivy") == {}
    assert base.load_json_output(b"{}", "Trivy") == {}


def test_load_json_output_names_the_engine_in_errors() -> None:
    with pytest.raises(base.ScannerOutputError, match="Grype"):
        base.load_json_output(b"[]", "Grype")


def test_check_success_raises_with_stderr_detail() -> None:
    result = base.CommandResult(returncode=3, stdout=b"", stderr=b"boom", argv=["trivy"])
    with pytest.raises(base.ScannerError, match="Trivy exited with code 3: boom"):
        base.check_success(result, "Trivy")


def test_check_success_passes_on_zero_exit() -> None:
    base.check_success(base.CommandResult(returncode=0, stdout=b"{}", stderr=b""), "Trivy")


def test_string_entries_rejects_scalar_where_list_expected() -> None:
    with pytest.raises(base.ScannerOutputError, match="fix.versions"):
        base.string_entries("1.2.3", "fix.versions", "Grype")


def test_string_entries_coerces_scalar_items() -> None:
    assert base.string_entries(["1.2.3", 4], "fix.versions", "Grype") == ["1.2.3", "4"]


# --- Grype: command building + parsing ---------------------------------------


def test_grype_command_requests_json() -> None:
    # `--` terminates flag parsing so a reference can never be read as an option.
    assert grype.build_command("grype", "alpine:3.19") == [
        "grype",
        "-o",
        "json",
        "--",
        "alpine:3.19",
    ]


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


@pytest.mark.parametrize(
    "raw",
    [
        b"null",  # top-level null
        b"[]",  # top-level array
        b'"a string"',
        json.dumps({"matches": "not-a-list"}).encode(),
        json.dumps({"matches": ["not-a-dict"]}).encode(),
        json.dumps({"matches": [{"vulnerability": "oops"}]}).encode(),
        json.dumps({"matches": [{"vulnerability": {}, "artifact": "oops"}]}).encode(),
        json.dumps({"descriptor": "grype 0.115.0"}).encode(),
        json.dumps({"matches": [{"artifact": {"locations": [42]}}]}).encode(),
        json.dumps({"matches": [{"artifact": {"locations": "somewhere"}}]}).encode(),
    ],
)
def test_grype_parse_rejects_wrong_shape_json(raw: bytes) -> None:
    with pytest.raises(base.ScannerOutputError) as excinfo:
        grype.parse_output(raw)
    assert excinfo.value.raw_output == raw


def test_grype_parse_rejects_string_urls_instead_of_first_char_garbage() -> None:
    # A string `urls` previously indexed its first *character* into primary_url.
    raw = json.dumps(
        {"matches": [{"vulnerability": {"id": "CVE-1", "urls": "https://x"}, "artifact": {}}]}
    ).encode()
    with pytest.raises(base.ScannerOutputError, match="urls"):
        grype.parse_output(raw)


def test_grype_parse_rejects_string_fix_versions_instead_of_per_char_join() -> None:
    # A string `fix.versions` previously joined per character ("1, ., 2, ., 3").
    raw = json.dumps(
        {
            "matches": [
                {
                    "vulnerability": {"id": "CVE-1", "fix": {"versions": "1.2.3"}},
                    "artifact": {},
                }
            ]
        }
    ).encode()
    with pytest.raises(base.ScannerOutputError, match="fix.versions"):
        grype.parse_output(raw)


def test_grype_parse_surfaces_wont_fix_state() -> None:
    # `fix.state: wont-fix` is a vendor decision — it must be distinguishable
    # from "no fix data at all" (which stays None, as with not-fixed/unknown).
    raw = json.dumps(
        {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-WF",
                        "severity": "High",
                        "fix": {"versions": [], "state": "wont-fix"},
                    },
                    "artifact": {"name": "libbar", "version": "1.0"},
                }
            ]
        }
    ).encode()
    findings, _ = grype.parse_output(raw)
    assert findings[0].fixed_version == "wont-fix"


def test_grype_parse_listed_fix_versions_take_precedence_over_state() -> None:
    raw = json.dumps(
        {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-F",
                        "fix": {"versions": ["2.0", "2.1"], "state": "fixed"},
                    },
                    "artifact": {},
                }
            ]
        }
    ).encode()
    findings, _ = grype.parse_output(raw)
    assert findings[0].fixed_version == "2.0, 2.1"


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
    assert grype.build_command("grype", "dir:/srv/app") == [
        "grype",
        "-o",
        "json",
        "--",
        "dir:/srv/app",
    ]
    assert grype.build_command("grype", "sbom:/tmp/s.json")[-1] == "sbom:/tmp/s.json"


def test_grype_scan_env_layers_overlay_over_update_check() -> None:
    env = grype.scan_env({"DOCKER_CONFIG": "/tmp/cfg"})
    assert env["GRYPE_CHECK_FOR_APP_UPDATE"] == "false"
    assert env["DOCKER_CONFIG"] == "/tmp/cfg"


# --- Syft SBOM generation (Phase 3) ------------------------------------------


def test_syft_command_and_default_format() -> None:
    argv = syft.build_command("syft", "alpine:3.19", "cyclonedx-json")
    assert argv == ["syft", "--quiet", "-o", "cyclonedx-json", "--", "alpine:3.19"]


def test_syft_resolve_format_defaults_and_validates() -> None:
    assert syft.resolve_format(None) == "cyclonedx-json"
    assert syft.resolve_format("bogus") == "cyclonedx-json"
    assert syft.resolve_format("spdx-json") == "spdx-json"


# --- Scanner cache/scratch redirection (hardened read-only-rootfs runtime) ----
#
# Regression guard for two runtime failures under the hardened Compose config
# (non-root uid, read-only root FS, small tmpfs /tmp):
#   * `mkdir /tmp/trivy-XXXXXXXXX: permission denied` (temp dir on the tmpfs), and
#   * `mkdir /app/.cache: read-only file system` (default $HOME/.cache on the
#     read-only root — hit by scans AND the version/DB-status probes).
# Every scanner invocation must be pointed at the writable /cache volume via the
# cache env overlay, never fall back to $HOME/.cache or the shared /tmp.


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


def _patch_scanner_cache(monkeypatch, cache_root, *modules):
    """Point every scanner's cache volume + binary paths at test-safe values."""
    from app.core import config

    settings = config.Settings(
        scanner_cache_dir=cache_root,
        trivy_binary="/usr/local/bin/trivy",
        grype_binary="/usr/local/bin/grype",
        syft_binary="/usr/local/bin/syft",
    )
    for module in (base, trivy, grype, syft, *modules):
        monkeypatch.setattr(module, "get_settings", lambda: settings)
    return settings


def _assert_points_at_cache(env: dict, cache_root) -> None:
    """Assert an env overlay redirects every cache/temp location onto the volume."""
    assert env["TMPDIR"] == str(cache_root / "tmp")
    assert env["HOME"] == str(cache_root)
    assert env["XDG_CACHE_HOME"] == str(cache_root)
    assert env["TRIVY_CACHE_DIR"] == str(cache_root / "trivy")
    assert env["GRYPE_DB_CACHE_DIR"] == str(cache_root / "grype" / "db")
    # None of these fall back to a read-only default like /app/.cache or /root.
    for value in (env["TMPDIR"], env["TRIVY_CACHE_DIR"], env["GRYPE_DB_CACHE_DIR"]):
        assert Path(value).is_relative_to(cache_root)


def test_scanner_cache_env_creates_dirs_and_redirects_all_caches(monkeypatch, tmp_path) -> None:
    _patch_scanner_cache(monkeypatch, tmp_path)
    overlay = base.scanner_cache_env()
    _assert_points_at_cache(overlay, tmp_path)
    # The volume subdirectories are created on demand (the volume starts empty).
    assert (tmp_path / "tmp").is_dir()
    assert (tmp_path / "trivy").is_dir()
    assert (tmp_path / "grype").is_dir()


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

    # Both the explicit flag and the env var point at the writable volume.
    assert run.argv[run.argv.index("--cache-dir") + 1] == str(tmp_path / "trivy")
    _assert_points_at_cache(run.env, tmp_path)


@pytest.mark.asyncio
async def test_trivy_repo_scan_redirects_db_cache_and_tmpdir(monkeypatch, tmp_path) -> None:
    _patch_scanner_cache(monkeypatch, tmp_path)
    run = _CapturingRun(json.dumps({"Results": []}).encode())
    monkeypatch.setattr(trivy, "run_command", run)

    await trivy.TrivyScanner().scan_repo("https://github.com/org/repo.git", {})

    assert run.argv[run.argv.index("--cache-dir") + 1] == str(tmp_path / "trivy")
    _assert_points_at_cache(run.env, tmp_path)


@pytest.mark.asyncio
async def test_grype_scan_redirects_db_cache_and_tmpdir(monkeypatch, tmp_path) -> None:
    _patch_scanner_cache(monkeypatch, tmp_path)
    run = _CapturingRun(json.dumps({"matches": []}).encode())
    monkeypatch.setattr(grype, "run_command", run)

    await grype.GrypeScanner().scan_image("alpine:3.19", {})

    _assert_points_at_cache(run.env, tmp_path)
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

    _assert_points_at_cache(run.env, tmp_path)


@pytest.mark.asyncio
async def test_trivy_db_probe_uses_writable_cache(monkeypatch, tmp_path) -> None:
    """The About/dashboard DB-freshness probe must not touch the read-only root.

    This is the `mkdir /app/.cache: read-only file system` regression: the probe
    runs `trivy --version --format json`, which reads the vuln-DB metadata under
    the cache dir.
    """
    _patch_scanner_cache(monkeypatch, tmp_path, system_info)
    run = _CapturingRun(json.dumps({"Version": "0.72.0"}).encode())
    monkeypatch.setattr(system_info, "run_command", run)

    await system_info._probe_trivy_db()

    assert run.env["TRIVY_CACHE_DIR"] == str(tmp_path / "trivy")
    assert run.env["XDG_CACHE_HOME"] == str(tmp_path)
    assert run.env["HOME"] == str(tmp_path)


@pytest.mark.asyncio
async def test_grype_db_probe_uses_writable_cache(monkeypatch, tmp_path) -> None:
    _patch_scanner_cache(monkeypatch, tmp_path, system_info)
    run = _CapturingRun(json.dumps({"built": "2026-07-03T00:00:00Z"}).encode())
    monkeypatch.setattr(system_info, "run_command", run)

    await system_info._probe_grype_db()

    assert run.env["GRYPE_DB_CACHE_DIR"] == str(tmp_path / "grype" / "db")
    assert run.env["XDG_CACHE_HOME"] == str(tmp_path)


@pytest.mark.asyncio
async def test_version_probe_uses_writable_cache(monkeypatch, tmp_path) -> None:
    _patch_scanner_cache(monkeypatch, tmp_path, system_info)
    run = _CapturingRun(b'{"Version":"0.72.0"}')
    monkeypatch.setattr(system_info, "run_command", run)

    await system_info._probe_scanner("trivy", "/usr/local/bin/trivy")

    assert run.env["TRIVY_CACHE_DIR"] == str(tmp_path / "trivy")


# --- Trivy scanner_version (recorded like Grype's descriptor version) ---------


class _VersionAwareRun:
    """``run_command`` stub answering the version probe and the scan separately."""

    def __init__(self, scan_stdout: bytes, version_stdout: bytes | None) -> None:
        self.scan_stdout = scan_stdout
        self.version_stdout = version_stdout
        self.calls: list[list[str]] = []

    async def __call__(self, argv, *, timeout, env=None) -> base.CommandResult:
        self.calls.append(argv)
        if "--version" in argv:
            if self.version_stdout is None:
                return base.CommandResult(returncode=1, stdout=b"", stderr=b"probe broke")
            return base.CommandResult(returncode=0, stdout=self.version_stdout, stderr=b"")
        return base.CommandResult(returncode=0, stdout=self.scan_stdout, stderr=b"")


@pytest.mark.asyncio
async def test_trivy_scan_records_scanner_version(monkeypatch, tmp_path) -> None:
    # Trivy's report JSON carries no engine version (unlike Grype's descriptor),
    # so the scanner must record it via a `trivy --version` probe.
    _patch_scanner_cache(monkeypatch, tmp_path)
    run = _VersionAwareRun(
        scan_stdout=json.dumps({"Results": []}).encode(),
        version_stdout=json.dumps({"Version": "0.72.0"}).encode(),
    )
    monkeypatch.setattr(trivy, "run_command", run)

    execution = await trivy.TrivyScanner().scan_image("alpine:3.19", {})

    assert execution.scanner_version == "0.72.0"
    # The probe ran alongside — not instead of — the scan itself.
    assert any("image" in argv for argv in run.calls)


@pytest.mark.asyncio
async def test_trivy_version_probe_failure_does_not_fail_the_scan(monkeypatch, tmp_path) -> None:
    _patch_scanner_cache(monkeypatch, tmp_path)
    run = _VersionAwareRun(
        scan_stdout=json.dumps({"Results": []}).encode(),
        version_stdout=None,  # probe exits non-zero
    )
    monkeypatch.setattr(trivy, "run_command", run)

    execution = await trivy.TrivyScanner().scan_image("alpine:3.19", {})

    assert execution.scanner_version is None
    assert execution.findings == []
