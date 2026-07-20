"""Report generation: scan/history exporters and scan diffs (docs/ARCHIVE.md §4.3, §4.4).

This package turns persisted scans and their normalized findings into the
downloadable CSV / Markdown / JSON reports offered per-scan and for filtered
history sets, and computes the finding-level diff between two scans of the same
target (new vs. fixed vulnerabilities over time).
"""

from app.reports.diff import ScanDiff, diff_findings
from app.reports.exporters import (
    EXPORT_FORMATS,
    ExportFormat,
    ExportResult,
    export_history,
    export_scan,
)

__all__ = [
    "EXPORT_FORMATS",
    "ExportFormat",
    "ExportResult",
    "ScanDiff",
    "diff_findings",
    "export_history",
    "export_scan",
]
