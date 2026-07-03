"""Tests for scanner command building and JSON normalization.

These exercise the parsers directly with representative Trivy/Grype JSON so no
real binaries are needed. Command-building tests assert the argument vectors
match the shapes documented in docs/PLAN.md §4.
"""

from __future__ import annotations

import json

from app.db.models import FindingClass, Severity
from app.scanners import base, grype, trivy

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
