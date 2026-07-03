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
