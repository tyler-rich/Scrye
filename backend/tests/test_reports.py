"""Unit tests for the report exporters and scan diff (docs/PLAN.md §4.3, §4.4).

These exercise the pure serialization/diff logic against ORM objects built in a
throwaway session — no HTTP, no worker.
"""

from __future__ import annotations

import csv
import io
import json

import pytest
from sqlalchemy.orm import Session

from app.db.models import (
    Finding,
    FindingClass,
    Scan,
    Scanner,
    ScanStatus,
    ScanTag,
    Severity,
    TargetType,
)
from app.reports import ExportFormat, diff_findings, export_history, export_scan
from app.reports.exporters import _csv_safe


def _scan(db: Session, **overrides) -> Scan:
    """Persist and return a Scan with sensible defaults for report tests."""
    defaults = dict(
        scanner=Scanner.TRIVY,
        target_type=TargetType.IMAGE,
        target="alpine:3.19",
        status=ScanStatus.SUCCEEDED,
        options={},
        severity_counts={"high": 1, "medium": 1},
        highest_severity=Severity.HIGH,
        findings_count=2,
        created_by_username="admin",
    )
    defaults.update(overrides)
    scan = Scan(**defaults)
    db.add(scan)
    db.flush()
    return scan


def _finding(scan_id: int, **overrides) -> Finding:
    """Build (unsaved) a Finding for a scan with defaults."""
    defaults = dict(
        scan_id=scan_id,
        finding_class=FindingClass.VULNERABILITY,
        severity=Severity.HIGH,
        vuln_id="CVE-2024-0001",
        pkg_name="libfoo",
        installed_version="1.0",
        fixed_version="1.1",
        title="libfoo flaw",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_scan_json_export_includes_metadata_and_findings(db: Session) -> None:
    scan = _scan(db)
    db.add(ScanTag(scan_id=scan.id, tag="prod"))
    findings = [
        _finding(scan.id, severity=Severity.HIGH, vuln_id="CVE-1"),
        _finding(scan.id, severity=Severity.MEDIUM, vuln_id="CVE-2"),
    ]
    db.add_all(findings)
    db.flush()

    result = export_scan(scan, findings, ExportFormat.JSON)
    assert result.media_type == "application/json"
    assert result.filename == f"scrye-scan-{scan.id}.json"
    payload = json.loads(result.content)
    assert payload["scan"]["id"] == scan.id
    assert payload["scan"]["tags"] == ["prod"]
    # Findings are ordered worst-severity first (HIGH before MEDIUM).
    assert [f["vuln_id"] for f in payload["findings"]] == ["CVE-1", "CVE-2"]


def test_scan_csv_export_one_row_per_finding(db: Session) -> None:
    scan = _scan(db)
    findings = [_finding(scan.id, vuln_id="CVE-1"), _finding(scan.id, vuln_id="CVE-2")]
    db.add_all(findings)
    db.flush()

    result = export_scan(scan, findings, ExportFormat.CSV)
    assert result.media_type == "text/csv"
    rows = list(csv.reader(io.StringIO(result.content.decode())))
    assert rows[0][0] == "finding_id"
    assert len(rows) == 3  # header + 2 findings
    assert {rows[1][3], rows[2][3]} == {"CVE-1", "CVE-2"}


def test_scan_markdown_export_groups_by_severity(db: Session) -> None:
    scan = _scan(db)
    findings = [
        _finding(scan.id, severity=Severity.CRITICAL, vuln_id="CVE-CRIT"),
        _finding(scan.id, severity=Severity.LOW, vuln_id="CVE-LOW"),
    ]
    db.add_all(findings)
    db.flush()

    result = export_scan(scan, findings, ExportFormat.MARKDOWN)
    text = result.content.decode()
    assert result.filename.endswith(".md")
    assert "# Scrye scan report" in text
    assert "### Critical (1)" in text
    assert "### Low (1)" in text
    # Critical section precedes Low.
    assert text.index("### Critical") < text.index("### Low")


def test_markdown_escapes_pipe_characters(db: Session) -> None:
    scan = _scan(db)
    finding = _finding(scan.id, title="danger | injection", vuln_id="CVE-PIPE")
    db.add(finding)
    db.flush()
    text = export_scan(scan, [finding], ExportFormat.MARKDOWN).content.decode()
    assert "danger \\| injection" in text


def test_history_csv_export_one_row_per_scan(db: Session) -> None:
    scan_a = _scan(db, target="alpine:3.19")
    scan_b = _scan(db, target="nginx:1.27", scanner=Scanner.GRYPE)
    db.flush()

    result = export_history([scan_a, scan_b], ExportFormat.CSV)
    rows = list(csv.reader(io.StringIO(result.content.decode())))
    assert rows[0][0] == "scan_id"
    assert len(rows) == 3
    assert result.filename == "scrye-history.csv"


def test_history_json_export_echoes_filters(db: Session) -> None:
    scan = _scan(db)
    db.flush()
    result = export_history([scan], ExportFormat.JSON, filters={"scanner": "trivy"})
    payload = json.loads(result.content)
    assert payload["filters"] == {"scanner": "trivy"}
    assert payload["count"] == 1
    assert payload["scans"][0]["id"] == scan.id


def test_diff_identifies_added_and_removed(db: Session) -> None:
    base = _scan(db, target="app:1")
    compare = _scan(db, target="app:1")
    db.flush()

    base_findings = [
        _finding(base.id, vuln_id="CVE-KEEP", severity=Severity.HIGH),
        _finding(base.id, vuln_id="CVE-FIXED", severity=Severity.CRITICAL),
    ]
    compare_findings = [
        _finding(compare.id, vuln_id="CVE-KEEP", severity=Severity.HIGH),
        _finding(compare.id, vuln_id="CVE-NEW", severity=Severity.MEDIUM),
    ]

    diff = diff_findings(base_findings, compare_findings)
    assert [f.vuln_id for f in diff.added] == ["CVE-NEW"]
    assert [f.vuln_id for f in diff.removed] == ["CVE-FIXED"]
    assert diff.unchanged_count == 1
    # Net severity change: -1 critical (fixed), +1 medium (new).
    assert diff.severity_delta.get("critical") == -1
    assert diff.severity_delta.get("medium") == 1
    assert "high" not in diff.severity_delta  # unchanged severities are dropped


def test_diff_matches_ignoring_package_version_churn(db: Session) -> None:
    base = _scan(db)
    compare = _scan(db)
    db.flush()
    # Same CVE + package, upgraded installed version → still the same finding.
    base_findings = [_finding(base.id, vuln_id="CVE-X", installed_version="1.0")]
    compare_findings = [_finding(compare.id, vuln_id="CVE-X", installed_version="1.2")]
    diff = diff_findings(base_findings, compare_findings)
    assert diff.added_count == 0
    assert diff.removed_count == 0
    assert diff.unchanged_count == 1


# --- CSV / spreadsheet formula-injection prevention --------------------------


@pytest.mark.parametrize("trigger", ["=", "+", "-", "@", "\t", "\r"])
def test_csv_safe_prefixes_every_trigger_character(trigger: str) -> None:
    # A cell that leads with a formula trigger is prefixed with a literal quote.
    payload = f"{trigger}HYPERLINK(0)"
    assert _csv_safe(payload) == f"'{payload}"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "libfoo",
        "1.2.3",
        "CVE-2024-0001",
        "openssl@3",  # '@' only triggers when it is the *first* character
        "a=b",  # '=' mid-string is harmless
        "team-a",  # a hyphen mid-string is a normal name, not a trigger
    ],
)
def test_csv_safe_passes_normal_values_through_unmodified(value: str) -> None:
    assert _csv_safe(value) == value


def test_csv_safe_guards_leading_hyphen_even_when_it_looks_legitimate() -> None:
    # A negative-sounding but legitimate package name still leads with '-', which
    # is a genuine formula trigger — it must be neutralized, not special-cased.
    assert _csv_safe("-rc-tools") == "'-rc-tools"


def test_scan_csv_export_neutralizes_formula_injection(db: Session) -> None:
    scan = _scan(db)
    finding = _finding(
        scan.id,
        vuln_id="CVE-INJECT",
        pkg_name="-danger",
        title='=HYPERLINK("http://evil","click")',
    )
    db.add(finding)
    db.flush()
    rows = list(
        csv.reader(io.StringIO(export_scan(scan, [finding], ExportFormat.CSV).content.decode()))
    )
    row = rows[1]
    assert "'-danger" in row  # pkg_name guarded
    assert any(cell.startswith("'=HYPERLINK") for cell in row)  # title guarded


def test_history_csv_export_neutralizes_formula_injection(db: Session) -> None:
    scan = _scan(db, target="=cmd|calc", created_by_username="+admin")
    db.add(ScanTag(scan_id=scan.id, tag="-prod"))
    db.flush()
    rows = list(csv.reader(io.StringIO(export_history([scan], ExportFormat.CSV).content.decode())))
    row = rows[1]
    assert "'=cmd|calc" in row  # target guarded
    assert "'+admin" in row  # initiator guarded
    assert "'-prod" in row  # joined tags guarded


def test_markdown_export_neutralizes_formula_injection(db: Session) -> None:
    scan = _scan(db)
    finding = _finding(scan.id, vuln_id="=cmd", pkg_name="normalpkg")
    db.add(finding)
    db.flush()
    text = export_scan(scan, [finding], ExportFormat.MARKDOWN).content.decode()
    assert "'=cmd" in text
    assert "normalpkg" in text  # untouched
