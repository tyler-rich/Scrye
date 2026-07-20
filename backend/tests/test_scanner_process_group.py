"""Tests for CON-2/CON-14: process-group kills and ProcessLookupError handling.

``run_command`` must kill the *whole* process group on every abort path
(timeout, output-cap overflow, cancellation) so grandchildren spawned by the
scanner/git binary (e.g. ``git-remote-https``) don't survive with credentials
still in their environment — and the kill itself must tolerate the process
having already exited.
"""

from __future__ import annotations

import asyncio
import os
import time

import pytest

from app.scanners import base
from app.scanners.base import ScannerError, _kill_process_group, run_command


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


async def _wait_until_dead(pid: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _pid_alive(pid):
            return True
        await asyncio.sleep(0.05)
    return not _pid_alive(pid)


class TestProcessGroupKillOnTimeout:
    async def test_timeout_kills_grandchild(self, tmp_path) -> None:
        """A timed-out shell parent's detached grandchild must also die.

        The shell backgrounds a long ``sleep`` (the grandchild), writes its pid
        out, then waits on it — mimicking git backgrounding a helper. A short
        timeout forces ``run_command`` down the ``TimeoutError``/killpg path;
        the grandchild must be gone afterward, not merely the shell.
        """
        pidfile = tmp_path / "grandchild.pid"
        argv = [
            "/bin/sh",
            "-c",
            f"sleep 60 & echo $! > {pidfile}; wait",
        ]

        with pytest.raises(ScannerError, match="timed out"):
            await run_command(argv, timeout=1)

        deadline = time.monotonic() + 5.0
        while not pidfile.exists() and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
        assert pidfile.exists(), "grandchild never reported its pid"

        grandchild_pid = int(pidfile.read_text().strip())
        assert await _wait_until_dead(
            grandchild_pid
        ), "grandchild sleep process survived the timeout kill"


class TestKillProcessGroupSuppression:
    async def test_processlookuperror_is_swallowed(self, monkeypatch) -> None:
        """A group that already exited must not raise out of the kill helper."""

        def _raise(*_args, **_kwargs):
            raise ProcessLookupError

        monkeypatch.setattr(base.os, "killpg", _raise)

        proc = await asyncio.create_subprocess_exec(
            "/bin/true",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.wait()

        _kill_process_group(proc)  # must not raise

    async def test_real_dead_process_group_is_swallowed(self) -> None:
        """No mocking: killpg on an already-reaped group must not raise."""
        proc = await asyncio.create_subprocess_exec(
            "/bin/true",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        await proc.wait()
        await asyncio.sleep(0.1)  # let the now-empty session/pgid fully vanish

        _kill_process_group(proc)  # must not raise
