"""Scanner orchestration: run the official binaries and parse their JSON.

Scrye is *scanner-faithful* (CLAUDE.md § Coding standards): it drives the
official ``trivy`` / ``grype`` binaries and parses their JSON output, persisting
the raw output as the source of truth and normalizing it for display. It does
not reimplement any scanner logic.
"""

from app.scanners.base import (
    NormalizedFinding,
    ScanExecution,
    ScannerError,
    get_scanner,
)

__all__ = [
    "NormalizedFinding",
    "ScanExecution",
    "ScannerError",
    "get_scanner",
]
