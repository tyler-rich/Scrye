"""Single source of truth for the scanner ↔ target-type compatibility matrix.

Which engine can run against which target type is scanner-domain knowledge, not
router-specific policy. It previously lived duplicated in both the scans and
scan-schedules routers and had already drifted in shape (APIR-10); keeping it
here means adding a new combination (a third engine, Trivy filesystem support,
…) is a one-line change both routers pick up.
"""

from __future__ import annotations

from app.db.models import Scanner, TargetType

#: Which scanners may run against each target type (docs/ARCHIVE.md §4).
SCANNER_TARGET_SUPPORT: dict[TargetType, frozenset[Scanner]] = {
    TargetType.IMAGE: frozenset({Scanner.TRIVY, Scanner.GRYPE}),
    TargetType.REPOSITORY: frozenset({Scanner.TRIVY}),
    TargetType.FILESYSTEM: frozenset({Scanner.GRYPE}),
    TargetType.SBOM: frozenset({Scanner.GRYPE}),
}


def scanner_supports(target_type: TargetType, scanner: Scanner) -> bool:
    """Return whether ``scanner`` can run against ``target_type``."""
    return scanner in SCANNER_TARGET_SUPPORT.get(target_type, frozenset())
