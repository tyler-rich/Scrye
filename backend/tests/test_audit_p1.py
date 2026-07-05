"""P1 audit-remediation tests: scanner output cap (SCN-1) and upload cap (API-4)."""

from __future__ import annotations

import asyncio
import io

import pytest
from fastapi import HTTPException, UploadFile

from app.api.uploads import read_upload_capped
from app.scanners import base
from app.scanners.base import ScannerOutputError, run_command


class _StubSettings:
    """Minimal settings stub exposing only the output-cap field run_command reads."""

    scanner_max_output_bytes = 1000


class _FakeStream:
    """An asyncio-stream-like object that yields fixed bytes in chunks."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    async def read(self, size: int) -> bytes:
        chunk = self._data[self._pos : self._pos + size]
        self._pos += len(chunk)
        return chunk


class _FakeProc:
    """A minimal stand-in for an asyncio subprocess (no real child spawned).

    Using a fake keeps the output-cap logic under test without depending on a
    real subprocess + child-watcher, which is brittle under a bare
    ``asyncio.run`` in some environments.
    """

    def __init__(self, stdout: bytes, stderr: bytes = b"") -> None:
        self.stdout = _FakeStream(stdout)
        self.stderr = _FakeStream(stderr)
        self.returncode = 0
        self.killed = False

    def kill(self) -> None:
        self.killed = True

    async def wait(self) -> int:
        return self.returncode


class TestScannerOutputCap:
    def test_output_exceeding_cap_is_aborted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SCN-1: output past the cap fails as an output error and kills the child."""
        proc = _FakeProc(stdout=b"x" * 200000)

        async def _fake_exec(*_argv: object, **_kwargs: object) -> _FakeProc:
            return proc

        monkeypatch.setattr(base, "get_settings", lambda: _StubSettings())
        monkeypatch.setattr(base.asyncio, "create_subprocess_exec", _fake_exec)
        with pytest.raises(ScannerOutputError):
            asyncio.run(run_command(["scanner"], timeout=30))
        assert proc.killed is True

    def test_output_within_cap_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Output under the cap is captured normally."""
        proc = _FakeProc(stdout=b"hello\n")

        async def _fake_exec(*_argv: object, **_kwargs: object) -> _FakeProc:
            return proc

        monkeypatch.setattr(base, "get_settings", lambda: _StubSettings())
        monkeypatch.setattr(base.asyncio, "create_subprocess_exec", _fake_exec)
        result = asyncio.run(run_command(["scanner"], timeout=30))
        assert result.stdout == b"hello\n"
        assert proc.killed is False


class TestUploadCap:
    def test_rejects_oversize_by_reported_size(self) -> None:
        """API-4: a reported size over the cap is rejected before reading."""
        upload = UploadFile(filename="big", file=io.BytesIO(b"x" * 5000), size=5000)
        with pytest.raises(HTTPException) as exc:
            asyncio.run(read_upload_capped(upload, 1000, what="Thing"))
        assert exc.value.status_code == 413

    def test_rejects_oversize_while_streaming(self) -> None:
        """Without a reported size, the chunked read still stops past the cap."""
        upload = UploadFile(filename="big", file=io.BytesIO(b"x" * 5000))
        with pytest.raises(HTTPException) as exc:
            asyncio.run(read_upload_capped(upload, 1000, what="Thing"))
        assert exc.value.status_code == 413

    def test_accepts_within_cap(self) -> None:
        """An upload at or under the cap round-trips its bytes."""
        upload = UploadFile(filename="ok", file=io.BytesIO(b"x" * 500))
        assert asyncio.run(read_upload_capped(upload, 1000, what="Thing")) == b"x" * 500
