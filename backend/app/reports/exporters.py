"""CSV / Markdown / JSON exporters for scans and history (docs/PLAN.md §4.3).

Two report scopes are supported:

* **Per-scan** — the normalized findings of a single scan, plus that scan's
  metadata. CSV is one row per finding; JSON is metadata + findings; Markdown is
  a readable report grouping findings by severity.
* **Filtered history** — the set of scans matching a history filter. CSV is one
  row per scan; JSON is the filter plus scan summaries; Markdown is a summary
  table.

Exporters read persisted models only; no secret material is present on scans,
findings, or their metadata.
"""

from __future__ import annotations

import csv
import enum
import io
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.db.models import SEVERITY_RANK, Finding, Scan, Severity

#: Severity display order, worst first (used to group and order report sections).
_SEVERITY_ORDER: list[Severity] = sorted(
    SEVERITY_RANK, key=lambda s: SEVERITY_RANK[s], reverse=True
)


class ExportFormat(enum.StrEnum):
    """Supported export serializations."""

    JSON = "json"
    CSV = "csv"
    MARKDOWN = "markdown"


#: Media type and file extension for each export format.
EXPORT_FORMATS: dict[ExportFormat, tuple[str, str]] = {
    ExportFormat.JSON: ("application/json", "json"),
    ExportFormat.CSV: ("text/csv", "csv"),
    ExportFormat.MARKDOWN: ("text/markdown", "md"),
}


@dataclass
class ExportResult:
    """A rendered export ready to be returned as an HTTP response."""

    content: bytes
    media_type: str
    filename: str


def _iso(value: datetime | None) -> str | None:
    """Serialize a naive-UTC timestamp to ISO 8601, or ``None``."""
    return value.isoformat() if value is not None else None


#: Leading characters that make a spreadsheet interpret a cell as a formula.
_CSV_INJECTION_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: str) -> str:
    """Neutralize spreadsheet formula injection in a single cell value.

    A CSV/report cell whose first character is one of ``= + - @`` or a tab /
    carriage return is executed as a formula when the file is opened in Excel,
    Google Sheets, or LibreOffice (CSV injection). Prefixing an apostrophe forces
    the cell to be read as literal text; the apostrophe is not shown by the
    spreadsheet, so the visible value is unchanged. Values that do not start with
    a trigger — including ordinary hyphenated names that merely contain ``-`` —
    are returned unmodified. Note there is no exception for leading hyphens: a
    value like ``-rc-tools`` is a genuine trigger and is prefixed.
    """
    if value.startswith(_CSV_INJECTION_PREFIXES):
        return "'" + value
    return value


def _scan_metadata(scan: Scan) -> dict[str, Any]:
    """Build the JSON-serializable metadata dict shared by every scan report."""
    return {
        "id": scan.id,
        "scanner": scan.scanner.value,
        "target_type": scan.target_type.value,
        "target": scan.target,
        "status": scan.status.value,
        "highest_severity": scan.highest_severity.value if scan.highest_severity else None,
        "findings_count": scan.findings_count,
        "severity_counts": dict(scan.severity_counts or {}),
        "scanner_version": scan.scanner_version,
        "created_by": scan.created_by_username,
        "tags": scan.tags,
        "created_at": _iso(scan.created_at),
        "started_at": _iso(scan.started_at),
        "finished_at": _iso(scan.finished_at),
    }


def _finding_dict(finding: Finding) -> dict[str, Any]:
    """Serialize a single normalized finding to a plain dict."""
    return {
        "id": finding.id,
        "finding_class": finding.finding_class.value,
        "severity": finding.severity.value,
        "vuln_id": finding.vuln_id,
        "pkg_name": finding.pkg_name,
        "installed_version": finding.installed_version,
        "fixed_version": finding.fixed_version,
        "title": finding.title,
        "location": finding.location,
        "primary_url": finding.primary_url,
    }


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    """Order findings worst-severity-first, then by identifier, for reports."""
    return sorted(
        findings,
        key=lambda f: (
            -SEVERITY_RANK.get(f.severity, SEVERITY_RANK[Severity.UNKNOWN]),
            f.finding_class.value,
            (f.vuln_id or f.title or "").lower(),
        ),
    )


# --- Per-scan exporters ------------------------------------------------------


def _scan_json(scan: Scan, findings: list[Finding]) -> bytes:
    """Serialize a scan and its findings to indented JSON bytes."""
    payload = {
        "scan": _scan_metadata(scan),
        "findings": [_finding_dict(f) for f in _sorted_findings(findings)],
    }
    return json.dumps(payload, indent=2).encode("utf-8")


_SCAN_CSV_COLUMNS = [
    "finding_id",
    "severity",
    "finding_class",
    "vuln_id",
    "pkg_name",
    "installed_version",
    "fixed_version",
    "title",
    "location",
    "primary_url",
]


def _scan_csv(scan: Scan, findings: list[Finding]) -> bytes:
    """Serialize a scan's findings to CSV bytes (one row per finding)."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(_SCAN_CSV_COLUMNS)
    for finding in _sorted_findings(findings):
        writer.writerow(
            [
                finding.id,
                _csv_safe(finding.severity.value),
                _csv_safe(finding.finding_class.value),
                _csv_safe(finding.vuln_id or ""),
                _csv_safe(finding.pkg_name or ""),
                _csv_safe(finding.installed_version or ""),
                _csv_safe(finding.fixed_version or ""),
                _csv_safe(finding.title or ""),
                _csv_safe(finding.location or ""),
                _csv_safe(finding.primary_url or ""),
            ]
        )
    return buffer.getvalue().encode("utf-8")


def _md_escape(value: str | None) -> str:
    r"""Escape a value for a Markdown table cell and neutralize formula injection.

    Escapes the pipe characters that would break a table cell and flattens all
    line breaks (``\r\n``, ``\n``, and bare ``\r`` — a lone carriage return
    splits a row just like a newline in most renderers), then applies the same
    formula-injection guard as the CSV exporter (:func:`_csv_safe`) so a value
    beginning with ``= + - @`` is inert if the rendered report is later pasted
    or imported into a spreadsheet.
    """
    if not value:
        return ""
    escaped = value.replace("|", "\\|")
    for line_break in ("\r\n", "\n", "\r"):
        escaped = escaped.replace(line_break, " ")
    return _csv_safe(escaped.strip())


def _scan_markdown(scan: Scan, findings: list[Finding]) -> bytes:
    """Serialize a scan to a readable Markdown report grouped by severity.

    Every operator-supplied value (target, initiator, tags) goes through
    :func:`_md_escape` so an embedded newline or pipe cannot break out of its
    heading, bullet, or table cell and inject report structure.
    """
    lines: list[str] = [f"# Scrye scan report — {_md_escape(scan.target)}", ""]
    lines.append(f"- **Scan ID:** {scan.id}")
    lines.append(f"- **Scanner:** {scan.scanner.value}")
    lines.append(f"- **Target type:** {scan.target_type.value}")
    lines.append(f"- **Status:** {scan.status.value}")
    if scan.highest_severity:
        lines.append(f"- **Highest severity:** {scan.highest_severity.value}")
    lines.append(f"- **Findings:** {scan.findings_count}")
    if scan.created_by_username:
        lines.append(f"- **Initiated by:** {_md_escape(scan.created_by_username)}")
    if scan.tags:
        lines.append(f"- **Tags:** {_md_escape(', '.join(scan.tags))}")
    if scan.finished_at:
        lines.append(f"- **Finished:** {_iso(scan.finished_at)}")
    lines.append("")

    counts = scan.severity_counts or {}
    lines.append("## Severity summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for severity in _SEVERITY_ORDER:
        count = counts.get(severity.value, 0)
        if count:
            lines.append(f"| {severity.value} | {count} |")
    lines.append("")

    grouped: dict[Severity, list[Finding]] = {sev: [] for sev in _SEVERITY_ORDER}
    for finding in _sorted_findings(findings):
        grouped[finding.severity].append(finding)

    lines.append("## Findings")
    lines.append("")
    if not findings:
        lines.append("_No findings._")
        lines.append("")
    for severity in _SEVERITY_ORDER:
        group = grouped[severity]
        if not group:
            continue
        lines.append(f"### {severity.value.capitalize()} ({len(group)})")
        lines.append("")
        lines.append("| ID | Class | Package | Installed | Fixed | Title |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for finding in group:
            lines.append(
                "| {id} | {cls} | {pkg} | {installed} | {fixed} | {title} |".format(
                    id=_md_escape(finding.vuln_id) or "—",
                    cls=finding.finding_class.value,
                    pkg=_md_escape(finding.pkg_name) or "—",
                    installed=_md_escape(finding.installed_version) or "—",
                    fixed=_md_escape(finding.fixed_version) or "—",
                    title=_md_escape(finding.title) or "—",
                )
            )
        lines.append("")
    return "\n".join(lines).encode("utf-8")


def export_scan(scan: Scan, findings: list[Finding], fmt: ExportFormat) -> ExportResult:
    """Render a single scan's findings in the requested format."""
    media_type, extension = EXPORT_FORMATS[fmt]
    if fmt is ExportFormat.JSON:
        content = _scan_json(scan, findings)
    elif fmt is ExportFormat.CSV:
        content = _scan_csv(scan, findings)
    else:
        content = _scan_markdown(scan, findings)
    return ExportResult(
        content=content,
        media_type=media_type,
        filename=f"scrye-scan-{scan.id}.{extension}",
    )


# --- Filtered-history exporters ----------------------------------------------


#: Per-severity count columns, worst first — derived from the shared enum so the
#: header and rows can never drift from the severity model (or each other).
_HISTORY_SEVERITY_COLUMNS = [severity.value for severity in _SEVERITY_ORDER]

_HISTORY_CSV_COLUMNS = [
    "scan_id",
    "scanner",
    "target_type",
    "target",
    "status",
    "highest_severity",
    "findings_count",
    *_HISTORY_SEVERITY_COLUMNS,
    "initiator",
    "tags",
    "created_at",
    "started_at",
    "finished_at",
]


def _history_json(scans: list[Scan], filters: dict[str, Any] | None) -> bytes:
    """Serialize a filtered scan set to indented JSON bytes."""
    payload = {
        "filters": filters or {},
        "count": len(scans),
        "scans": [_scan_metadata(s) for s in scans],
    }
    return json.dumps(payload, indent=2).encode("utf-8")


def _history_csv(scans: list[Scan]) -> bytes:
    """Serialize a filtered scan set to CSV bytes (one row per scan)."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(_HISTORY_CSV_COLUMNS)
    for scan in scans:
        counts = scan.severity_counts or {}
        writer.writerow(
            [
                scan.id,
                _csv_safe(scan.scanner.value),
                _csv_safe(scan.target_type.value),
                _csv_safe(scan.target),
                _csv_safe(scan.status.value),
                _csv_safe(scan.highest_severity.value if scan.highest_severity else ""),
                scan.findings_count,
                *(counts.get(column, 0) for column in _HISTORY_SEVERITY_COLUMNS),
                _csv_safe(scan.created_by_username or ""),
                _csv_safe(",".join(scan.tags)),
                _csv_safe(_iso(scan.created_at) or ""),
                _csv_safe(_iso(scan.started_at) or ""),
                _csv_safe(_iso(scan.finished_at) or ""),
            ]
        )
    return buffer.getvalue().encode("utf-8")


def _history_markdown(scans: list[Scan], filters: dict[str, Any] | None) -> bytes:
    """Serialize a filtered scan set to a Markdown summary table."""
    lines: list[str] = ["# Scrye scan history", ""]
    active = {k: v for k, v in (filters or {}).items() if v not in (None, "", [])}
    if active:
        # Filter values carry user input (e.g. the target search text) — escape
        # them so a crafted value cannot inject Markdown structure. Keys are
        # internal filter names and need no escaping.
        lines.append(
            "**Filters:** " + ", ".join(f"{k}={_md_escape(str(v))}" for k, v in active.items())
        )
        lines.append("")
    lines.append(f"**Matching scans:** {len(scans)}")
    lines.append("")
    lines.append("| ID | Scanner | Target | Status | Highest | Findings | By | Created |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for scan in scans:
        highest = scan.highest_severity.value if scan.highest_severity else "—"
        cells = [
            str(scan.id),
            scan.scanner.value,
            _md_escape(scan.target),
            scan.status.value,
            highest,
            str(scan.findings_count),
            _md_escape(scan.created_by_username) or "—",
            _iso(scan.created_at) or "",
        ]
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("")
    return "\n".join(lines).encode("utf-8")


def export_history(
    scans: list[Scan], fmt: ExportFormat, *, filters: dict[str, Any] | None = None
) -> ExportResult:
    """Render a filtered set of scans in the requested format."""
    media_type, extension = EXPORT_FORMATS[fmt]
    if fmt is ExportFormat.JSON:
        content = _history_json(scans, filters)
    elif fmt is ExportFormat.CSV:
        content = _history_csv(scans)
    else:
        content = _history_markdown(scans, filters)
    return ExportResult(
        content=content,
        media_type=media_type,
        filename=f"scrye-history.{extension}",
    )
