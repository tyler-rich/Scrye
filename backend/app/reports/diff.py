"""Finding-level diff between two scans of the same target (docs/PLAN.md §4.4).

Comparing two scans answers "what changed over time": which findings are **new**
(present in the newer scan only), which were **fixed** (present in the older scan
only), and which are **unchanged** (present in both). Findings are matched by a
stable identity key so package-version churn or re-ordering doesn't register as
change.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from app.db.models import SEVERITY_RANK, Finding, Severity


def finding_key(finding: Finding) -> tuple[str, str, str, str]:
    """Return a stable identity for a finding, used to match across scans.

    Vulnerabilities are identified by ``(class, vuln_id, package)`` — the same
    convention the scanners use to dedupe — so a package upgrade that keeps the
    CVE still counts as the *same* finding. Findings without a vuln id
    (misconfigurations, secrets, licenses) fall back to their title/location so
    they still match sensibly.
    """
    cls = finding.finding_class.value
    ident = (finding.vuln_id or finding.title or "").strip().lower()
    pkg = (finding.pkg_name or "").strip().lower()
    location = (finding.location or "").strip().lower()
    # For vuln findings the location rarely disambiguates and is often unset, so
    # only fold it in when there is no vuln id to key on.
    loc_component = "" if finding.vuln_id else location
    return (cls, ident, pkg, loc_component)


def _severity_delta(base: Iterable[Finding], compare: Iterable[Finding]) -> dict[str, int]:
    """Compute the per-severity net change (compare minus base) as a plain dict."""
    delta: dict[str, int] = {}
    for finding in compare:
        delta[finding.severity.value] = delta.get(finding.severity.value, 0) + 1
    for finding in base:
        delta[finding.severity.value] = delta.get(finding.severity.value, 0) - 1
    # Drop no-change entries so the payload only shows what actually moved.
    return {sev: n for sev, n in delta.items() if n != 0}


@dataclass
class ScanDiff:
    """The result of diffing a base scan against a comparison scan."""

    added: list[Finding] = field(default_factory=list)
    removed: list[Finding] = field(default_factory=list)
    unchanged: list[Finding] = field(default_factory=list)
    severity_delta: dict[str, int] = field(default_factory=dict)

    @property
    def added_count(self) -> int:
        """Number of findings new in the comparison scan."""
        return len(self.added)

    @property
    def removed_count(self) -> int:
        """Number of findings fixed (present only in the base scan)."""
        return len(self.removed)

    @property
    def unchanged_count(self) -> int:
        """Number of findings present in both scans."""
        return len(self.unchanged)


def _severity_sort_key(finding: Finding) -> tuple[int, str]:
    """Sort findings worst-severity-first, then by identifier for stability."""
    return (
        -SEVERITY_RANK.get(finding.severity, SEVERITY_RANK[Severity.UNKNOWN]),
        (finding.vuln_id or finding.title or "").lower(),
    )


def diff_findings(base: list[Finding], compare: list[Finding]) -> ScanDiff:
    """Diff ``base`` (older) against ``compare`` (newer) by finding identity.

    Args:
        base: Findings from the base scan (treated as the "before" state).
        compare: Findings from the comparison scan (the "after" state).

    Returns:
        A :class:`ScanDiff` with added/removed/unchanged findings and the
        per-severity net delta. When the same key appears more than once within
        a scan (duplicate rows), the first occurrence represents the group.
    """
    base_by_key: dict[tuple[str, str, str, str], Finding] = {}
    for finding in base:
        base_by_key.setdefault(finding_key(finding), finding)
    compare_by_key: dict[tuple[str, str, str, str], Finding] = {}
    for finding in compare:
        compare_by_key.setdefault(finding_key(finding), finding)

    added = [f for key, f in compare_by_key.items() if key not in base_by_key]
    removed = [f for key, f in base_by_key.items() if key not in compare_by_key]
    unchanged = [f for key, f in compare_by_key.items() if key in base_by_key]

    added.sort(key=_severity_sort_key)
    removed.sort(key=_severity_sort_key)
    unchanged.sort(key=_severity_sort_key)

    return ScanDiff(
        added=added,
        removed=removed,
        unchanged=unchanged,
        severity_delta=_severity_delta(base_by_key.values(), compare_by_key.values()),
    )
