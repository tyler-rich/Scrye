"""A small, dependency-free 5-field cron evaluator (docs/PLAN.md §12, Phase 6).

Scheduled scans (§4.6/§12) run on a standard cron cadence. Rather than pull in a
third-party cron library, this module implements the common 5-field syntax
(``minute hour day-of-month month day-of-week``) with ``*``, lists (``a,b``),
ranges (``a-b``), and steps (``*/n`` / ``a-b/n``). It supports enough to express
"every night at 02:00", "every 15 minutes", "Mondays at 09:00", etc.

Semantics match Vixie cron: when **both** day-of-month and day-of-week are
restricted (neither is ``*``), a timestamp matches if **either** field matches;
otherwise both must match. Evaluation granularity is one minute — the same as the
maintenance scheduler's tick — so seconds are ignored.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta

#: Inclusive (min, max) legal value for each cron field, in field order.
#: Day-of-week accepts 7 as an alias for Sunday (0), per Vixie/POSIX crontab;
#: it is normalized to 0 after parsing.
_FIELD_BOUNDS: tuple[tuple[int, int], ...] = (
    (0, 59),  # minute
    (0, 23),  # hour
    (1, 31),  # day of month
    (1, 12),  # month
    (0, 7),  # day of week (0 or 7 = Sunday)
)
_FIELD_NAMES = ("minute", "hour", "day-of-month", "month", "day-of-week")

#: Upper bound on how far :meth:`CronExpression.next_after` will search before
#: giving up (a valid cron always matches within a year; this guards typos).
_SEARCH_LIMIT_MINUTES = 366 * 24 * 60


class CronError(ValueError):
    """Raised when a cron expression is malformed."""


def _is_restricted(field: str) -> bool:
    """Return True if a day field constrains matching (Vixie OR/AND semantics).

    A field is *unrestricted* when it derives its whole range from ``*`` — that is
    ``*`` itself or a pure step over the full range (``*/n``). Only then does the
    "both dom and dow restricted → OR" rule treat it as a wildcard. An explicit
    value, list, or range (including ``a-b/n``) is restricted. This matches Vixie
    cron's "star bit", so e.g. ``0 0 */2 * 0`` correctly ANDs (even days that are
    also Sundays) instead of firing on every even day or Sunday.
    """
    field = field.strip()
    return field != "*" and _STEP_STAR_RE.fullmatch(field) is None


#: A pure step over the full range (``*/n``) — treated as unrestricted like ``*``.
_STEP_STAR_RE = re.compile(r"\*/\d+")


def _parse_field(spec: str, low: int, high: int, name: str) -> frozenset[int]:
    """Parse one cron field into the set of matching integers."""
    values: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            raise CronError(f"Empty term in {name} field.")
        has_step = "/" in part
        step = 1
        if has_step:
            base, _, step_str = part.partition("/")
            try:
                step = int(step_str)
            except ValueError as exc:
                raise CronError(f"Invalid step in {name} field: {part!r}.") from exc
            if step <= 0:
                raise CronError(f"Step must be positive in {name} field: {part!r}.")
        else:
            base = part

        if base == "*":
            start, end = low, high
        elif "-" in base:
            start_str, _, end_str = base.partition("-")
            try:
                start, end = int(start_str), int(end_str)
            except ValueError as exc:
                raise CronError(f"Invalid range in {name} field: {part!r}.") from exc
        else:
            try:
                start = int(base)
            except ValueError as exc:
                raise CronError(f"Invalid value in {name} field: {part!r}.") from exc
            # Vixie semantics: a bare value with a step (`N/step`) means `N-max/step`
            # (e.g. `5/15` in the minute field = 5,20,35,50); without a step it is
            # the single value N.
            end = high if has_step else start

        if start > end or start < low or end > high:
            raise CronError(f"{name} value out of range ({low}-{high}): {part!r}.")
        values.update(range(start, end + 1, step))
    return frozenset(values)


@dataclass(frozen=True)
class CronExpression:
    """A parsed 5-field cron expression with a minute-granularity matcher."""

    minutes: frozenset[int]
    hours: frozenset[int]
    days_of_month: frozenset[int]
    months: frozenset[int]
    days_of_week: frozenset[int]
    dom_restricted: bool
    dow_restricted: bool
    raw: str

    @classmethod
    def parse(cls, expression: str) -> CronExpression:
        """Parse a 5-field cron string, raising :class:`CronError` on error."""
        fields = expression.split()
        if len(fields) != 5:
            raise CronError("A cron expression must have exactly 5 fields.")
        parsed = [
            _parse_field(field, low, high, name)
            for field, (low, high), name in zip(fields, _FIELD_BOUNDS, _FIELD_NAMES, strict=True)
        ]
        # Normalize day-of-week 7 (Sunday alias) to 0 so it matches weekday math.
        days_of_week = parsed[4]
        if 7 in days_of_week:
            days_of_week = (days_of_week - {7}) | {0}
        return cls(
            minutes=parsed[0],
            hours=parsed[1],
            days_of_month=parsed[2],
            months=parsed[3],
            days_of_week=days_of_week,
            dom_restricted=_is_restricted(fields[2]),
            dow_restricted=_is_restricted(fields[4]),
            raw=expression.strip(),
        )

    def matches(self, moment: datetime) -> bool:
        """Return True if ``moment`` (truncated to the minute) fires this cron."""
        if moment.minute not in self.minutes:
            return False
        if moment.hour not in self.hours:
            return False
        if moment.month not in self.months:
            return False
        # Python weekday(): Monday=0..Sunday=6; cron uses Sunday=0..Saturday=6.
        cron_dow = (moment.weekday() + 1) % 7
        dom_ok = moment.day in self.days_of_month
        dow_ok = cron_dow in self.days_of_week
        if self.dom_restricted and self.dow_restricted:
            return dom_ok or dow_ok
        return dom_ok and dow_ok

    def next_after(self, after: datetime) -> datetime | None:
        """Return the first minute strictly after ``after`` that matches, or None."""
        candidate = (after + timedelta(minutes=1)).replace(second=0, microsecond=0)
        for _ in range(_SEARCH_LIMIT_MINUTES):
            if self.matches(candidate):
                return candidate
            candidate += timedelta(minutes=1)
        return None

    def is_due(self, last_fired: datetime, now: datetime) -> bool:
        """Return True if a matching minute falls in ``(last_fired, now]``.

        ``last_fired`` should be the last time the schedule ran (or its creation
        time if it has never run). The search window is clamped to at most the
        configured limit so a long downtime can't trigger an unbounded scan.
        """
        window_start = max(last_fired, now - timedelta(minutes=_SEARCH_LIMIT_MINUTES))
        nxt = self.next_after(window_start)
        return nxt is not None and nxt <= now


def validate_cron(expression: str) -> str:
    """Validate and normalize a cron expression, raising :class:`CronError`."""
    return CronExpression.parse(expression).raw
