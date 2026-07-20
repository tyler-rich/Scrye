"""Event-driven notification dispatch for finished scans (docs/ARCHIVE.md §4.6).

Phase 5 built the notification channels and their transports; Phase 6 wires the
actual events. When a scan finishes, the worker calls :func:`dispatch_scan_event`,
which determines the applicable events, finds the enabled channels subscribed to
any of them, and sends each a concise summary. Dispatch is best-effort: a
transport failure is logged, never raised, so a flaky channel can't fail a scan.
"""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.notifications import send_notification
from app.db.models import (
    NotificationChannel,
    NotificationEvent,
    Scan,
    ScanStatus,
    Severity,
)

logger = logging.getLogger(__name__)

#: Severities that qualify a completed scan as "high severity" for dispatch.
_HIGH_SEVERITIES = frozenset({Severity.CRITICAL.value, Severity.HIGH.value})


def scan_events(scan: Scan) -> set[str]:
    """Return the notification events a finished scan qualifies for."""
    events: set[str] = set()
    if scan.status is ScanStatus.FAILED:
        events.add(NotificationEvent.SCAN_FAILED.value)
    elif scan.status is ScanStatus.SUCCEEDED:
        events.add(NotificationEvent.SCAN_COMPLETED.value)
        counts = scan.severity_counts or {}
        if any(counts.get(level, 0) for level in _HIGH_SEVERITIES):
            events.add(NotificationEvent.SCAN_HIGH_SEVERITY.value)
    return events


def _format_message(scan: Scan) -> str:
    """Build a plain-text summary of a finished scan (no secret material)."""
    header = f"Scrye scan #{scan.id} {scan.status.value}"
    detail = f"{scan.scanner.value} · {scan.target_type.value} · {scan.target}"
    if scan.status is ScanStatus.FAILED:
        return f"{header}\n{detail}\nError: {scan.error or 'unknown error'}"

    counts = scan.severity_counts or {}
    highest = scan.highest_severity.value if scan.highest_severity else "none"
    summary = ", ".join(
        f"{level}: {counts.get(level, 0)}"
        for level in (
            Severity.CRITICAL.value,
            Severity.HIGH.value,
            Severity.MEDIUM.value,
            Severity.LOW.value,
        )
        if counts.get(level, 0)
    )
    summary = summary or "no findings"
    return (
        f"{header}\n{detail}\n" f"Findings: {scan.findings_count} (highest: {highest})\n{summary}"
    )


async def dispatch_scan_event(db: Session, scan: Scan) -> int:
    """Send notifications for a finished scan; return how many were sent.

    Best-effort: individual send failures are logged and swallowed so a
    misconfigured channel never affects scan execution.
    """
    events = scan_events(scan)
    if not events:
        return 0

    channels = db.scalars(
        select(NotificationChannel).where(NotificationChannel.enabled.is_(True))
    ).all()
    targets = [c for c in channels if events.intersection(c.events or [])]
    if not targets:
        return 0

    message = _format_message(scan)
    sent = 0
    for channel in targets:
        try:
            result = await send_notification(channel, message)
        except Exception:  # noqa: BLE001 - a channel must never break dispatch
            logger.exception("Notification channel %r raised during dispatch.", channel.name)
            continue
        if result.ok:
            sent += 1
        else:
            logger.warning("Notification to channel %r failed: %s", channel.name, result.detail)
    return sent
