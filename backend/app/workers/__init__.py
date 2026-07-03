"""In-process async scan worker (docs/PLAN.md §0.2, §12 Phase 2).

The worker owns scan execution: it is handed a scan id, runs the appropriate
scanner subprocess under a concurrency limit, stores the raw output, and persists
normalized findings. It sits behind the small :class:`~app.workers.base.ScanWorker`
interface so a Redis/arq-backed implementation could replace it later without
touching the API layer (Redis/arq is explicitly out of scope for v1).
"""

from app.workers.base import ScanWorker
from app.workers.inprocess import InProcessScanWorker

__all__ = ["InProcessScanWorker", "ScanWorker"]
