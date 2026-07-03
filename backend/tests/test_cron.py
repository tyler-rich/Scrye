"""Tests for the dependency-free cron evaluator (app.core.cron)."""

from __future__ import annotations

from datetime import datetime

import pytest

from app.core.cron import CronError, CronExpression, validate_cron


class TestParse:
    def test_wildcards_match_everything(self) -> None:
        cron = CronExpression.parse("* * * * *")
        assert cron.matches(datetime(2026, 7, 3, 8, 30))

    def test_specific_minute_hour(self) -> None:
        cron = CronExpression.parse("0 2 * * *")
        assert cron.matches(datetime(2026, 7, 3, 2, 0))
        assert not cron.matches(datetime(2026, 7, 3, 2, 1))
        assert not cron.matches(datetime(2026, 7, 3, 3, 0))

    def test_step_and_range_and_list(self) -> None:
        cron = CronExpression.parse("*/15 9-17 * * 1,3")
        # Monday 09:15 matches (minute step, hour range, weekday list).
        assert cron.matches(datetime(2026, 7, 6, 9, 15))  # Monday
        # Wednesday 17:00 matches.
        assert cron.matches(datetime(2026, 7, 8, 17, 0))  # Wednesday
        # Tuesday is not in {Mon, Wed}.
        assert not cron.matches(datetime(2026, 7, 7, 9, 15))
        # 09:10 is not a multiple of 15.
        assert not cron.matches(datetime(2026, 7, 6, 9, 10))

    def test_sunday_is_zero(self) -> None:
        cron = CronExpression.parse("0 0 * * 0")
        assert cron.matches(datetime(2026, 7, 5, 0, 0))  # Sunday
        assert not cron.matches(datetime(2026, 7, 6, 0, 0))  # Monday

    def test_dom_or_dow_when_both_restricted(self) -> None:
        # Vixie semantics: dom OR dow when both are restricted.
        cron = CronExpression.parse("0 0 13 * 5")  # 13th OR Friday
        assert cron.matches(datetime(2026, 7, 13, 0, 0))  # the 13th (a Monday)
        assert cron.matches(datetime(2026, 7, 10, 0, 0))  # a Friday
        assert not cron.matches(datetime(2026, 7, 14, 0, 0))  # neither

    @pytest.mark.parametrize(
        "expr",
        [
            "* * * *",
            "60 * * * *",
            "* 24 * * *",
            "* * 0 * *",
            "* * * 13 *",
            "a * * * *",
            "*/0 * * * *",
        ],
    )
    def test_invalid_expressions_raise(self, expr: str) -> None:
        with pytest.raises(CronError):
            CronExpression.parse(expr)


class TestScheduling:
    def test_next_after(self) -> None:
        cron = CronExpression.parse("30 2 * * *")
        nxt = cron.next_after(datetime(2026, 7, 3, 1, 0))
        assert nxt == datetime(2026, 7, 3, 2, 30)

    def test_next_after_rolls_to_next_day(self) -> None:
        cron = CronExpression.parse("0 0 * * *")
        nxt = cron.next_after(datetime(2026, 7, 3, 12, 0))
        assert nxt == datetime(2026, 7, 4, 0, 0)

    def test_is_due_when_window_contains_match(self) -> None:
        cron = CronExpression.parse("0 * * * *")  # top of every hour
        last = datetime(2026, 7, 3, 8, 30)
        now = datetime(2026, 7, 3, 9, 5)
        assert cron.is_due(last, now)

    def test_not_due_when_no_match_in_window(self) -> None:
        cron = CronExpression.parse("0 0 * * *")  # midnight only
        last = datetime(2026, 7, 3, 8, 0)
        now = datetime(2026, 7, 3, 9, 0)
        assert not cron.is_due(last, now)

    def test_validate_cron_normalizes(self) -> None:
        assert validate_cron("  0 2 * * *  ") == "0 2 * * *"
