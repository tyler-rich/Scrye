"""Tests for event-driven notification dispatch (app.core.notification_dispatch)."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

import app.core.notification_dispatch as dispatch_mod
from app.core.notification_dispatch import dispatch_scan_event, scan_events
from app.core.notifications import DeliveryResult
from app.db.models import (
    NotificationChannel,
    NotificationEvent,
    NotificationType,
    Scan,
    Scanner,
    ScanStatus,
    Severity,
    TargetType,
)


def _scan(status: ScanStatus, counts: dict[str, int] | None = None) -> Scan:
    """Build a detached scan row for dispatch tests."""
    return Scan(
        scanner=Scanner.TRIVY,
        target_type=TargetType.IMAGE,
        target="example:latest",
        status=status,
        options={},
        severity_counts=counts or {},
        findings_count=sum((counts or {}).values()),
        highest_severity=Severity.CRITICAL if (counts or {}).get("critical") else None,
        error="boom" if status is ScanStatus.FAILED else None,
    )


class TestScanEvents:
    def test_failed_scan(self) -> None:
        assert scan_events(_scan(ScanStatus.FAILED)) == {NotificationEvent.SCAN_FAILED.value}

    def test_completed_clean_scan(self) -> None:
        assert scan_events(_scan(ScanStatus.SUCCEEDED, {"low": 2})) == {
            NotificationEvent.SCAN_COMPLETED.value
        }

    def test_completed_high_severity(self) -> None:
        events = scan_events(_scan(ScanStatus.SUCCEEDED, {"critical": 1, "high": 3}))
        assert events == {
            NotificationEvent.SCAN_COMPLETED.value,
            NotificationEvent.SCAN_HIGH_SEVERITY.value,
        }

    def test_queued_scan_has_no_events(self) -> None:
        assert scan_events(_scan(ScanStatus.QUEUED)) == set()


class TestDispatch:
    @pytest.mark.asyncio
    async def test_only_subscribed_enabled_channels_notified(
        self, db: Session, monkeypatch
    ) -> None:
        sent: list[str] = []

        async def fake_send(channel, message):
            sent.append(channel.name)
            return DeliveryResult(ok=True, detail="ok")

        monkeypatch.setattr(dispatch_mod, "send_notification", fake_send)

        db.add_all(
            [
                NotificationChannel(
                    name="fails-only",
                    type=NotificationType.WEBHOOK,
                    config={"url": "https://x.test"},
                    events=[NotificationEvent.SCAN_FAILED.value],
                    enabled=True,
                ),
                NotificationChannel(
                    name="completes",
                    type=NotificationType.WEBHOOK,
                    config={"url": "https://y.test"},
                    events=[NotificationEvent.SCAN_COMPLETED.value],
                    enabled=True,
                ),
                NotificationChannel(
                    name="disabled",
                    type=NotificationType.WEBHOOK,
                    config={"url": "https://z.test"},
                    events=[NotificationEvent.SCAN_COMPLETED.value],
                    enabled=False,
                ),
            ]
        )
        scan = _scan(ScanStatus.SUCCEEDED, {"low": 1})
        db.add(scan)
        db.commit()

        count = await dispatch_scan_event(db, scan)
        assert count == 1
        assert sent == ["completes"]

    @pytest.mark.asyncio
    async def test_transport_failure_is_swallowed(self, db: Session, monkeypatch) -> None:
        async def boom(channel, message):
            raise RuntimeError("transport exploded")

        monkeypatch.setattr(dispatch_mod, "send_notification", boom)
        db.add(
            NotificationChannel(
                name="c",
                type=NotificationType.WEBHOOK,
                config={"url": "https://x.test"},
                events=[NotificationEvent.SCAN_FAILED.value],
                enabled=True,
            )
        )
        scan = _scan(ScanStatus.FAILED)
        db.add(scan)
        db.commit()
        # Must not raise, and reports zero successful sends.
        assert await dispatch_scan_event(db, scan) == 0

    @pytest.mark.asyncio
    async def test_no_channels_no_send(self, db: Session) -> None:
        scan = _scan(ScanStatus.SUCCEEDED, {"low": 1})
        db.add(scan)
        db.commit()
        assert await dispatch_scan_event(db, scan) == 0
