"""P3 audit-remediation tests: Grype ignore config (FEAT-6) and DB updates (FEAT-4)."""

from __future__ import annotations

import asyncio

import pytest

from app.scanners.grype import build_command
from app.scanners.grype_policy import GRYPE_CONFIG_OVERLAY_KEY, materialize_grype_config
from app.workers import db_update


class TestGrypeIgnoreConfig:
    def test_build_command_inserts_config_flag(self) -> None:
        """FEAT-6: a config path becomes a `-c <path>` flag before the reference."""
        argv = build_command("grype", "alpine:3.19", config_path="/tmp/x/.grype.yaml")
        assert argv == ["grype", "-c", "/tmp/x/.grype.yaml", "-o", "json", "--", "alpine:3.19"]

    def test_build_command_without_config(self) -> None:
        assert build_command("grype", "alpine:3.19") == [
            "grype",
            "-o",
            "json",
            "--",
            "alpine:3.19",
        ]

    def test_materialize_writes_config_and_yields_overlay(self) -> None:
        with materialize_grype_config("ignore:\n  - vulnerability: CVE-2021-0001\n") as overlay:
            path = overlay[GRYPE_CONFIG_OVERLAY_KEY]
            with open(path, encoding="utf-8") as handle:
                assert "CVE-2021-0001" in handle.read()

    def test_materialize_empty_yields_no_overlay(self) -> None:
        with materialize_grype_config("   ") as overlay:
            assert overlay == {}


class TestScannerDbUpdate:
    def test_disabled_policy_does_nothing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        db_update.reset_db_update_state()
        monkeypatch.setattr(db_update, "_read_policy", lambda: (False, 24))
        assert asyncio.run(db_update.maybe_update_scanner_dbs(now=0.0)) is False

    def test_runs_both_engines_when_due_then_skips(self, monkeypatch: pytest.MonkeyPatch) -> None:
        db_update.reset_db_update_state()
        monkeypatch.setattr(db_update, "_read_policy", lambda: (True, 24))
        monkeypatch.setattr(db_update, "resolve_binary", lambda name: f"/usr/bin/{name}")

        calls: list[list[str]] = []

        async def _fake_run(argv, *, timeout, env):
            calls.append(argv)

            class _R:
                returncode = 0

            return _R()

        monkeypatch.setattr(db_update, "run_command", _fake_run)

        # First call is due (no prior run) and updates both engines.
        assert asyncio.run(db_update.maybe_update_scanner_dbs(now=1000.0)) is True
        assert len(calls) == 2
        assert calls[0][1:] == ["image", "--download-db-only"]
        assert calls[1][1:] == ["db", "update"]

        # A second call well within the interval is skipped (no new commands).
        assert asyncio.run(db_update.maybe_update_scanner_dbs(now=1000.0 + 3600)) is False
        assert len(calls) == 2

        # Past the interval it runs again.
        assert asyncio.run(db_update.maybe_update_scanner_dbs(now=1000.0 + 24 * 3600 + 1)) is True
        assert len(calls) == 4

    def test_missing_binary_is_skipped_not_raised(self, monkeypatch: pytest.MonkeyPatch) -> None:
        db_update.reset_db_update_state()
        monkeypatch.setattr(db_update, "_read_policy", lambda: (True, 24))

        def _missing(name: str) -> str:
            raise db_update.ScannerError(f"{name} not found")

        monkeypatch.setattr(db_update, "resolve_binary", _missing)
        # A due run with no binaries present completes without raising.
        assert asyncio.run(db_update.maybe_update_scanner_dbs(now=5.0)) is True
