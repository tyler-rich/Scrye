"""Tests that blocking DB work is kept off the event loop (CON-5, CON-13, CON-18).

These paths run inside ``async def`` contexts on the single event loop, so a
synchronous DB call arriving while a long writer holds the SQLite write lock
would stall the whole loop inside ``busy_timeout``. The fixes hop that work to a
worker thread; the assertions here pin *where* it runs — the offloaded callable
must execute on a thread other than the loop thread.
"""

from __future__ import annotations

import threading

import pytest

from app.db.models import Scanner
from app.db.session import SessionLocal
from app.workers import db_update, inprocess
from app.workers.inprocess import InProcessScanWorker
from tests.test_worker import _FakeScanner, _make_execution, _queue_scan


@pytest.mark.asyncio
async def test_db_update_reads_policy_off_loop(db, monkeypatch) -> None:
    """``maybe_update_scanner_dbs`` reads its policy in a worker thread."""
    loop_thread = threading.get_ident()
    seen: dict[str, int] = {}
    real = db_update._read_policy

    def spy() -> tuple[bool, int]:
        seen["thread"] = threading.get_ident()
        return real()

    monkeypatch.setattr(db_update, "_read_policy", spy)
    db_update.reset_db_update_state()
    await db_update.maybe_update_scanner_dbs(now=0.0)

    assert seen["thread"] != loop_thread


@pytest.mark.asyncio
async def test_worker_loads_trivy_policy_off_loop(db, monkeypatch) -> None:
    """The worker's per-scan Trivy policy read is hopped off the loop."""
    loop_thread = threading.get_ident()
    seen: dict[str, int] = {}
    real = inprocess.load_trivy_policy

    def spy(session):  # type: ignore[no-untyped-def]
        seen["thread"] = threading.get_ident()
        return real(session)

    monkeypatch.setattr(inprocess, "load_trivy_policy", spy)
    monkeypatch.setattr(inprocess, "get_scanner", lambda s: _FakeScanner(_make_execution()))

    scan_id = _queue_scan(db, scanner=Scanner.TRIVY)
    worker = InProcessScanWorker(SessionLocal, max_concurrent=1)
    await worker.submit(scan_id)
    await worker.shutdown()

    assert seen["thread"] != loop_thread


def test_persist_queued_scan_inserts_and_audits(db) -> None:
    """The extracted sync helper commits the scan and its audit row."""
    from types import SimpleNamespace

    from app.db.models import Scan, ScanStatus, TargetType
    from app.db.models.audit import AuditLog

    actor = SimpleNamespace(user=SimpleNamespace(id=None, username="tester"))

    scan = Scan(
        scanner=Scanner.GRYPE,
        target_type=TargetType.IMAGE,
        target="alpine:3.19",
        status=ScanStatus.QUEUED,
        options={},
        severity_counts={},
    )
    from app.api.scans import _persist_queued_scan

    _persist_queued_scan(db, scan, actor=actor, ip="127.0.0.1")

    assert scan.id is not None
    audit = db.query(AuditLog).filter(AuditLog.action == "scan.created").one()
    assert audit.target_id == str(scan.id)
