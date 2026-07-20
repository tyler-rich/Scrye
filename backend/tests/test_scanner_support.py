"""Tests for the shared scanner ↔ target-type compatibility matrix (APIR-10).

The matrix is the single source of truth both the scans and scan-schedules
routers consult, so scheduling a scan can't diverge from running it one-off.
"""

from __future__ import annotations

from app.db.models import Scanner, TargetType
from app.scanners.support import SCANNER_TARGET_SUPPORT, scanner_supports


def test_known_combinations() -> None:
    assert scanner_supports(TargetType.IMAGE, Scanner.TRIVY)
    assert scanner_supports(TargetType.IMAGE, Scanner.GRYPE)
    assert scanner_supports(TargetType.REPOSITORY, Scanner.TRIVY)
    assert not scanner_supports(TargetType.REPOSITORY, Scanner.GRYPE)
    assert scanner_supports(TargetType.FILESYSTEM, Scanner.GRYPE)
    assert not scanner_supports(TargetType.FILESYSTEM, Scanner.TRIVY)
    assert scanner_supports(TargetType.SBOM, Scanner.GRYPE)
    assert not scanner_supports(TargetType.SBOM, Scanner.TRIVY)


def test_matrix_covers_every_target_type() -> None:
    """Every target type is represented, so no lookup silently falls through."""
    assert set(SCANNER_TARGET_SUPPORT) == set(TargetType)
