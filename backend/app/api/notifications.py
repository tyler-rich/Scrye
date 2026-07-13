"""Notification channel management (docs/PLAN.md §4.5).

Admin-only CRUD for notification destinations. The per-channel secret is
write-only and field-encrypted; reads return a mask plus a timestamp. A ``test``
action sends a sample message so an admin can confirm connectivity and the
stored credential without waiting for a real event.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.schema_types import UtcDatetime
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


#: Placeholder returned for a webhook/Discord URL on read (the URL is the secret).
_URL_MASK = "••••••"

#: Channel types whose ``config['url']`` is the write-only credential and is
#: therefore stored field-encrypted and masked on read (SEC-1).
_URL_SECRET_TYPES: frozenset[NotificationType] = frozenset(
    {NotificationType.WEBHOOK, NotificationType.DISCORD}
)


def _masked_config(channel: NotificationChannel) -> dict[str, Any]:
    """Return the channel config with any credential-bearing URL masked.

    A webhook/Discord URL embeds its auth token, so it is treated as a write-only
    secret: new rows keep it in the encrypted ``secret`` (not in config), and any
    legacy row that still carries ``config['url']`` shows a mask on read rather
    than the token.
    """
    config = dict(channel.config or {})
    if channel.type in _URL_SECRET_TYPES and config.get("url"):
        config["url"] = _URL_MASK
    return config


def _extract_url_secret(payload_config: dict[str, Any]) -> tuple[dict, str]:
    """Move a credential-bearing URL out of config into the encrypted secret.

    A webhook/Discord URL is the whole credential, so it is stored
    field-encrypted rather than in the plaintext ``config`` column. The returned
    config never carries ``url``; the second element is the URL to store as the
    secret (empty for a masked read round-trip, which leaves the stored secret
    untouched).
    """
    config = dict(payload_config or {})
    url = config.pop("url", None)
    if url == _URL_MASK:
        url = None
    return config, (url or "")


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
    created_at: UtcDatetime
    updated_at: UtcDatetime


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
        config=_masked_config(channel),
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
    config = payload.config
    if payload.type in _URL_SECRET_TYPES:
        # The webhook/Discord URL is the credential: store it encrypted, not in
        # the plaintext config column. It also supersedes any separately-supplied
        # secret for these types (the URL is what we POST to).
        config, url_secret = _extract_url_secret(payload.config)
        secret_value = url_secret or secret_value
    if not secret_value and payload.type not in SECRET_OPTIONAL_TYPES:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"A secret is required for '{payload.type.value}' channels.",
        )

    channel = NotificationChannel(
        name=payload.name,
        type=payload.type,
        config=config,
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
        if channel.type in _URL_SECRET_TYPES:
            # Keep the webhook/Discord URL out of the plaintext config: route a
            # newly-supplied URL into the encrypted secret; a masked round-trip
            # (empty url_secret) leaves the stored secret untouched.
            new_config, url_secret = _extract_url_secret(payload.config)
            channel.config = new_config
            if url_secret:
                channel.secret_ciphertext = encrypt_secret(url_secret, aad=AAD_NOTIFICATION_SECRET)
                channel.secret_updated_at = utcnow()
                changes["secret"] = "updated"
        else:
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
        elif channel.type in SECRET_OPTIONAL_TYPES:
            channel.secret_ciphertext = None
            channel.secret_updated_at = None
        else:
            # Create forbids a channel of this type with no secret; the update
            # path must not be able to reach that state either (APIR-6).
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"A secret is required for '{channel.type.value}' channels.",
            )
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
