"""The worker interface the API depends on.

Keeping this seam thin (submit / recover / shutdown) means the in-process worker
can be swapped for a distributed one later without changing callers. Only the
in-process implementation is built in v1.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class ScanWorker(ABC):
    """Abstract scan executor."""

    @abstractmethod
    async def submit(self, scan_id: int) -> None:
        """Schedule ``scan_id`` for execution (returns once scheduled)."""
        raise NotImplementedError

    @abstractmethod
    async def recover(self) -> None:
        """Reconcile scans left mid-flight by a previous process at startup."""
        raise NotImplementedError

    @abstractmethod
    async def shutdown(self) -> None:
        """Stop accepting work and wait for in-flight scans to settle."""
        raise NotImplementedError

    # The hooks below are optional (default no-ops) so a future distributed
    # worker only has to implement the three core methods above. The in-process
    # worker overrides them for its self-healing watchdog (CON-1/CON-11) and
    # the restore-time execution pause (CON-3).

    async def reconcile_stale(self) -> None:
        """Self-heal scans stranded without a live executor (periodic; optional)."""
        return None

    def pause(self) -> None:
        """Temporarily hold new scan executions (optional; see :meth:`resume`)."""
        return None

    def resume(self) -> None:
        """Resume executions held by :meth:`pause` (optional)."""
        return None
