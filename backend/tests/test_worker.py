"""Tests for the in-process scan worker.

The scanner subprocess is replaced with a fake so the worker's orchestration —
status transitions, artifact storage, finding persistence, failure handling, and
startup recovery — is exercised without any real binaries.
"""

from __future__ import annotations

import json

import pytest

from app.core.artifacts import artifact_path
from app.db.models import Scan, Scanner, ScanStatus, Severity, TargetType
from app.db.session import SessionLocal
from app.scanners import NormalizedFinding, ScanExecution, ScannerError, ScannerOutputError
from app.scanners.base import tally_severities
from app.workers import inprocess
from app.workers.inprocess import InProcessScanWorker


def _make_execution() -> ScanExecution:
    """Build a canned two-finding execution with valid raw JSON bytes."""
    findings = [
        NormalizedFinding(
            finding_class="vulnerability",
            severity=Severity.CRITICAL,
            vuln_id="CVE-2024-0001",
            pkg_name="openssl",
            installed_version="3.1.0",
            fixed_version="3.1.4",
            title="bad",
        ),
        NormalizedFinding(
            finding_class="vulnerability",
            severity=Severity.LOW,
            vuln_id="CVE-2024-0002",
            pkg_name="zlib",
        ),
    ]
    return ScanExecution(
        raw_output=json.dumps({"matches": []}).encode(),
        findings=findings,
        severity_counts=tally_severities(findings),
        command=["grype", "img", "-o", "json"],
        scanner_version="0.115.0",
    )


class _FakeScanner:
    """A scanner stand-in that returns a fixed execution or raises."""

    def __init__(self, execution: ScanExecution | None = None, error: str | None = None) -> None:
        self._execution = execution
        self._error = error

    async def scan_image(
        self, target: str, options: dict, *, env: dict | None = None
    ) -> ScanExecution:
        if self._error is not None:
            raise ScannerError(self._error)
        assert self._execution is not None
        return self._execution


def _queue_scan(db, scanner: Scanner = Scanner.GRYPE) -> int:
    """Insert a queued scan and return its id."""
    scan = Scan(
        scanner=scanner,
        target_type=TargetType.IMAGE,
        target="alpine:3.19",
        status=ScanStatus.QUEUED,
        options={},
        severity_counts={},
    )
    db.add(scan)
    db.commit()
    return scan.id


@pytest.mark.asyncio
async def test_worker_runs_scan_and_persists_results(db, monkeypatch) -> None:
    execution = _make_execution()
    monkeypatch.setattr(inprocess, "get_scanner", lambda scanner: _FakeScanner(execution))

    scan_id = _queue_scan(db)
    worker = InProcessScanWorker(SessionLocal, max_concurrent=2)
    await worker.submit(scan_id)
    await worker.shutdown()

    db.expire_all()
    scan = db.get(Scan, scan_id)
    assert scan.status is ScanStatus.SUCCEEDED
    assert scan.findings_count == 2
    assert scan.highest_severity is Severity.CRITICAL
    assert scan.severity_counts["critical"] == 1
    assert scan.severity_counts["low"] == 1
    assert scan.scanner_version == "0.115.0"
    assert scan.started_at is not None and scan.finished_at is not None
    assert len(scan.findings) == 2
    # Raw artifact stored on disk with matching checksum length.
    assert len(scan.artifacts) == 1
    artifact = scan.artifacts[0]
    assert artifact.filename == "grype.json"
    assert artifact_path(artifact.relative_path).is_file()
    assert len(artifact.sha256) == 64


@pytest.mark.asyncio
async def test_worker_marks_failed_on_scanner_error(db, monkeypatch) -> None:
    monkeypatch.setattr(
        inprocess, "get_scanner", lambda scanner: _FakeScanner(error="Trivy exited with code 1")
    )
    scan_id = _queue_scan(db, Scanner.TRIVY)
    worker = InProcessScanWorker(SessionLocal, max_concurrent=1)
    await worker.submit(scan_id)
    await worker.shutdown()

    db.expire_all()
    scan = db.get(Scan, scan_id)
    assert scan.status is ScanStatus.FAILED
    assert "Trivy exited with code 1" in scan.error
    assert scan.findings_count == 0
    assert scan.artifacts == []


@pytest.mark.asyncio
async def test_worker_persists_raw_output_when_parsing_fails(db, monkeypatch) -> None:
    """Wrong-shape scanner output must fail the scan *and* store the raw bytes.

    Without the stored artifact a malformed-output failure is undiagnosable —
    there is nothing on disk to inspect.
    """
    raw = b'["not", "a", "grype", "report"]'

    class _WrongShapeScanner:
        async def scan_image(self, target, options, *, env=None):
            raise ScannerOutputError(
                "Grype produced JSON of an unexpected shape: expected a top-level "
                "object, got list.",
                raw,
            )

    monkeypatch.setattr(inprocess, "get_scanner", lambda scanner: _WrongShapeScanner())
    scan_id = _queue_scan(db)
    worker = InProcessScanWorker(SessionLocal, max_concurrent=1)
    await worker.submit(scan_id)
    await worker.shutdown()

    db.expire_all()
    scan = db.get(Scan, scan_id)
    assert scan.status is ScanStatus.FAILED
    assert "unexpected shape" in scan.error
    # The raw output is persisted as the scan's raw artifact for diagnosis.
    assert len(scan.artifacts) == 1
    artifact = scan.artifacts[0]
    assert artifact.filename == "grype.json"
    assert artifact_path(artifact.relative_path).read_bytes() == raw


@pytest.mark.asyncio
async def test_worker_skips_canceled_scan(db, monkeypatch) -> None:
    monkeypatch.setattr(inprocess, "get_scanner", lambda scanner: _FakeScanner(_make_execution()))
    scan = Scan(
        scanner=Scanner.GRYPE,
        target_type=TargetType.IMAGE,
        target="alpine",
        status=ScanStatus.CANCELED,
        options={},
        severity_counts={},
    )
    db.add(scan)
    db.commit()

    worker = InProcessScanWorker(SessionLocal, max_concurrent=1)
    await worker.submit(scan.id)
    await worker.shutdown()

    db.expire_all()
    assert db.get(Scan, scan.id).status is ScanStatus.CANCELED


@pytest.mark.asyncio
async def test_worker_does_not_run_a_scan_canceled_before_claim(db, monkeypatch) -> None:
    """A scan flipped to CANCELED before the worker claims it must not run."""
    monkeypatch.setattr(inprocess, "get_scanner", lambda scanner: _FakeScanner(_make_execution()))
    scan_id = _queue_scan(db)
    # Simulate the cancel endpoint winning the race: the row is CANCELED before
    # the worker's guarded queued->running update runs.
    scan = db.get(Scan, scan_id)
    scan.status = ScanStatus.CANCELED
    db.commit()

    worker = InProcessScanWorker(SessionLocal, max_concurrent=1)
    await worker.submit(scan_id)
    await worker.shutdown()

    db.expire_all()
    settled = db.get(Scan, scan_id)
    assert settled.status is ScanStatus.CANCELED
    assert settled.findings_count == 0
    assert settled.artifacts == []


@pytest.mark.asyncio
async def test_worker_recovery_fails_running_and_requeues_queued(db, monkeypatch) -> None:
    execution = _make_execution()
    monkeypatch.setattr(inprocess, "get_scanner", lambda scanner: _FakeScanner(execution))

    running = Scan(
        scanner=Scanner.GRYPE,
        target_type=TargetType.IMAGE,
        target="stuck",
        status=ScanStatus.RUNNING,
        options={},
        severity_counts={},
    )
    queued_id = _queue_scan(db)
    db.add(running)
    db.commit()
    running_id = running.id

    worker = InProcessScanWorker(SessionLocal, max_concurrent=2)
    await worker.recover()
    await worker.shutdown()

    db.expire_all()
    assert db.get(Scan, running_id).status is ScanStatus.FAILED
    assert "restart" in db.get(Scan, running_id).error.lower()
    # The queued scan was re-submitted and completed.
    assert db.get(Scan, queued_id).status is ScanStatus.SUCCEEDED
