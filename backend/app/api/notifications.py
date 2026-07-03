"""Notification channel management (docs/PLAN.md §4.5).

Admin-only CRUD for notification destinations. The per-channel secret is
write-only and field-encrypted; reads return a mask plus a timestamp. A ``test``
action sends a sample message so an admin can confirm connectivity and the
stored credential without waiting for a real event.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.deps import AuthContext, client_ip, require_csrf, require_role
from app.core.audit import record_audit
from app.core.masking import MaskedSecret, masked_secret
from app.core.notifications import send_notification
from app.core.secret_store import AAD_NOTIFICATION_SECRET, encrypt_secret
from app.core.timeutil import utcnow
from app.db.models import (
    SECRET_OPTIONAL_TYPES,
    NotificationChannel,
    NotificationEvent,
    NotificationType,
    Role,
)
from app.db.session import get_db

router = APIRouter(prefix="/notifications", tags=["notifications"])

_admin = require_role(Role.ADMIN)


def _clean_events(events: list[NotificationEvent] | None) -> list[str]:
    """De-duplicate event keys, preserving canonical order."""
    if not events:
        return []
    selected = {e.value for e in events}
    return [e.value for e in NotificationEvent if e.value in selected]


class NotificationChannelOut(BaseModel):
    """Masked read view of a notification channel."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    type: NotificationType
    config: dict[str, Any]
    events: list[NotificationEvent]
    enabled: bool
    secret: MaskedSecret
    created_by_username: str | None
    created_at: datetime
    updated_at: datetime


class NotificationChannelCreateIn(BaseModel):
    """Payload for creating a notification channel."""

    name: str = Field(min_length=1, max_length=128)
    type: NotificationType
    config: dict[str, Any] = Field(default_factory=dict)
    events: list[NotificationEvent] = Field(default_factory=list)
    secret: SecretStr | None = None
    enabled: bool = True


class NotificationChannelUpdateIn(BaseModel):
    """Payload for updating a channel (all fields optional)."""

    name: str | None = Field(default=None, min_length=1, max_length=128)
    config: dict[str, Any] | None = None
    events: list[NotificationEvent] | None = None
    secret: SecretStr | None = None
    enabled: bool | None = None


class NotificationTestOut(BaseModel):
    """Result of a channel connectivity test."""

    ok: bool
    detail: str


def _to_out(channel: NotificationChannel) -> NotificationChannelOut:
    """Build the masked read view of a channel."""
    return NotificationChannelOut(
        id=channel.id,
        name=channel.name,
        type=channel.type,
        config=channel.config or {},
        events=[NotificationEvent(e) for e in (channel.events or [])],
        enabled=channel.enabled,
        secret=masked_secret(channel.secret_updated_at),
        created_by_username=channel.created_by_username,
        created_at=channel.created_at,
        updated_at=channel.updated_at,
    )


def _get_or_404(db: Session, channel_id: int) -> NotificationChannel:
    """Fetch a channel by id or raise 404."""
    channel = db.get(NotificationChannel, channel_id)
    if channel is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Notification channel not found.")
    return channel


@router.get("/events", response_model=list[str])
def list_events(_: AuthContext = Depends(_admin)) -> list[str]:
    """List the notification events a channel can subscribe to."""
    return [e.value for e in NotificationEvent]


@router.get("", response_model=list[NotificationChannelOut])
def list_channels(
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> list[NotificationChannelOut]:
    """List configured notification channels (admin; secrets masked)."""
    rows = db.scalars(select(NotificationChannel).order_by(NotificationChannel.name)).all()
    return [_to_out(c) for c in rows]


@router.post("", response_model=NotificationChannelOut, status_code=status.HTTP_201_CREATED)
def create_channel(
    payload: NotificationChannelCreateIn,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> NotificationChannelOut:
    """Create a notification channel (secret field-encrypted at rest)."""
    if (
        db.scalar(select(NotificationChannel).where(NotificationChannel.name == payload.name))
        is not None
    ):
        raise HTTPException(status.HTTP_409_CONFLICT, detail="A channel with that name exists.")

    secret_value = payload.secret.get_secret_value() if payload.secret else ""
    if not secret_value and payload.type not in SECRET_OPTIONAL_TYPES:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"A secret is required for '{payload.type.value}' channels.",
        )

    channel = NotificationChannel(
        name=payload.name,
        type=payload.type,
        config=payload.config,
        events=_clean_events(payload.events),
        enabled=payload.enabled,
        created_by_id=auth.user.id,
        created_by_username=auth.user.username,
    )
    if secret_value:
        channel.secret_ciphertext = encrypt_secret(secret_value, aad=AAD_NOTIFICATION_SECRET)
        channel.secret_updated_at = utcnow()
    db.add(channel)
    db.flush()
    record_audit(
        db,
        action="notification.created",
        actor=auth.user,
        ip=client_ip(request),
        target_type="notification",
        target_id=str(channel.id),
        details={"name": channel.name, "type": channel.type.value},
    )
    db.commit()
    return _to_out(channel)


@router.patch("/{channel_id}", response_model=NotificationChannelOut)
def update_channel(
    channel_id: int,
    payload: NotificationChannelUpdateIn,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> NotificationChannelOut:
    """Update a channel; omitting ``secret`` keeps the stored one."""
    channel = _get_or_404(db, channel_id)
    changes: dict[str, object] = {}

    if payload.name is not None and payload.name != channel.name:
        if (
            db.scalar(select(NotificationChannel).where(NotificationChannel.name == payload.name))
            is not None
        ):
            raise HTTPException(status.HTTP_409_CONFLICT, detail="A channel with that name exists.")
        channel.name = payload.name
        changes["name"] = payload.name
    if payload.config is not None:
        channel.config = payload.config
        changes["config"] = "updated"
    if payload.events is not None:
        channel.events = _clean_events(payload.events)
        changes["events"] = channel.events
    if payload.enabled is not None:
        channel.enabled = payload.enabled
        changes["enabled"] = payload.enabled
    if payload.secret is not None:
        secret_value = payload.secret.get_secret_value()
        if secret_value:
            channel.secret_ciphertext = encrypt_secret(secret_value, aad=AAD_NOTIFICATION_SECRET)
            channel.secret_updated_at = utcnow()
        else:
            channel.secret_ciphertext = None
            channel.secret_updated_at = None
        changes["secret"] = "updated"  # metadata only; never the value

    if changes:
        record_audit(
            db,
            action="notification.updated",
            actor=auth.user,
            ip=client_ip(request),
            target_type="notification",
            target_id=str(channel.id),
            details=changes,
        )
        db.commit()
    return _to_out(channel)


@router.delete("/{channel_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_channel(
    channel_id: int,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> Response:
    """Delete a notification channel."""
    channel = _get_or_404(db, channel_id)
    record_audit(
        db,
        action="notification.deleted",
        actor=auth.user,
        ip=client_ip(request),
        target_type="notification",
        target_id=str(channel.id),
        details={"name": channel.name},
    )
    db.delete(channel)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{channel_id}/test", response_model=NotificationTestOut)
async def test_channel(
    channel_id: int,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> NotificationTestOut:
    """Send a test message over the channel to validate its configuration."""
    channel = _get_or_404(db, channel_id)
    record_audit(
        db,
        action="notification.tested",
        actor=auth.user,
        ip=client_ip(request),
        target_type="notification",
        target_id=str(channel.id),
    )
    db.commit()
    result = await send_notification(
        channel, "Scrye test notification — your channel is configured correctly."
    )
    return NotificationTestOut(ok=result.ok, detail=result.detail)
