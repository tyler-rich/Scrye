"""Prometheus metrics rendering (docs/ARCHIVE.md §12, Phase 6).

Exposes Scrye's operational state as Prometheus text-format gauges derived from
the database on scrape: scan counts by status/scanner, the current open
critical/high posture, schedule counts, and a build-info series. There are no
in-process counters to maintain — every value is a point-in-time gauge computed
from the same aggregation the dashboard uses — so a plain text renderer (no
client library) keeps the dependency surface minimal (CLAUDE.md § Dependency
hygiene).
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import __version__
from app.core.dashboard import compute_dashboard_cached
from app.db.models import ApiToken, NotificationChannel, User

#: Prometheus text exposition content type (version 0.0.4).
CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def _escape_label(value: str) -> str:
    """Escape a Prometheus label value (backslash, quote, newline)."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _metric(name: str, value: float, labels: dict[str, str] | None = None) -> str:
    """Render one Prometheus sample line."""
    if labels:
        rendered = ",".join(f'{k}="{_escape_label(v)}"' for k, v in labels.items())
        return f"{name}{{{rendered}}} {value}"
    return f"{name} {value}"


def render_metrics(db: Session) -> str:
    """Render all Scrye metrics in Prometheus text-exposition format."""
    # Reuse the short-TTL dashboard cache so a frequent Prometheus scrape does
    # not recompute the full aggregation on every request (API-7).
    data = compute_dashboard_cached(db)
    user_count = db.scalar(select(func.count()).select_from(User)) or 0
    token_count = db.scalar(select(func.count()).select_from(ApiToken)) or 0
    channel_count = db.scalar(select(func.count()).select_from(NotificationChannel)) or 0

    lines: list[str] = []

    lines.append("# HELP scrye_build_info Scrye build information.")
    lines.append("# TYPE scrye_build_info gauge")
    lines.append(_metric("scrye_build_info", 1, {"version": __version__}))

    lines.append("# HELP scrye_scans_total Total scans by status.")
    lines.append("# TYPE scrye_scans_total gauge")
    for status_value, count in sorted(data.scans_by_status.items()):
        lines.append(_metric("scrye_scans_total", count, {"status": status_value}))

    lines.append("# HELP scrye_scans_by_scanner_total Total scans by scanner engine.")
    lines.append("# TYPE scrye_scans_by_scanner_total gauge")
    for scanner_value, count in sorted(data.scans_by_scanner.items()):
        lines.append(_metric("scrye_scans_by_scanner_total", count, {"scanner": scanner_value}))

    lines.append("# HELP scrye_open_findings Open findings from the latest scan per target.")
    lines.append("# TYPE scrye_open_findings gauge")
    lines.append(_metric("scrye_open_findings", data.open_critical, {"severity": "critical"}))
    lines.append(_metric("scrye_open_findings", data.open_high, {"severity": "high"}))

    lines.append("# HELP scrye_scan_schedules Configured scan schedules.")
    lines.append("# TYPE scrye_scan_schedules gauge")
    lines.append(_metric("scrye_scan_schedules", data.schedules_enabled, {"state": "enabled"}))
    lines.append(_metric("scrye_scan_schedules", data.schedules_total, {"state": "total"}))

    lines.append("# HELP scrye_users_total Number of user accounts.")
    lines.append("# TYPE scrye_users_total gauge")
    lines.append(_metric("scrye_users_total", user_count))

    lines.append("# HELP scrye_api_tokens_total Number of personal API tokens.")
    lines.append("# TYPE scrye_api_tokens_total gauge")
    lines.append(_metric("scrye_api_tokens_total", token_count))

    lines.append("# HELP scrye_notification_channels_total Number of notification channels.")
    lines.append("# TYPE scrye_notification_channels_total gauge")
    lines.append(_metric("scrye_notification_channels_total", channel_count))

    return "\n".join(lines) + "\n"
