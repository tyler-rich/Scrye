"""Notification delivery for the configured channels (docs/PLAN.md §4.5).

Sends a message over one of the supported transports — generic webhook, Discord
webhook, SMTP email, or Matrix room. The per-channel secret (SMTP password,
webhook bearer token, Matrix access token) is decrypted only here, in memory, at
send time, and is never logged. Actual event-driven dispatch (scan-complete
alerts) is Phase 6; this module provides the transport plus the settings-page
"send test" action.
"""

from __future__ import annotations

import smtplib
from dataclasses import dataclass
from email.message import EmailMessage

import anyio.to_thread
import httpx

from app.core.crypto import SecretDecryptError
from app.core.secret_store import AAD_NOTIFICATION_SECRET, decrypt_secret
from app.db.models import NotificationChannel, NotificationType

_HTTP_TIMEOUT_SECONDS = 10
_SMTP_TIMEOUT_SECONDS = 15


@dataclass(frozen=True)
class DeliveryResult:
    """Outcome of a notification send attempt (safe to surface to the UI)."""

    ok: bool
    detail: str


def _channel_secret(channel: NotificationChannel) -> str | None:
    """Decrypt the channel's stored secret, or return ``None`` if unset."""
    if not channel.secret_ciphertext:
        return None
    return decrypt_secret(channel.secret_ciphertext, aad=AAD_NOTIFICATION_SECRET)


async def _send_webhook(channel: NotificationChannel, message: str, secret: str | None) -> None:
    """POST a JSON body to a generic webhook (optional bearer auth)."""
    url = channel.config.get("url")
    if not url:
        raise ValueError("Webhook channel has no 'url' configured.")
    headers = {"Content-Type": "application/json"}
    if secret:
        headers["Authorization"] = f"Bearer {secret}"
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS) as http:
        response = await http.post(url, json={"text": message}, headers=headers)
        response.raise_for_status()


async def _send_discord(channel: NotificationChannel, message: str, secret: str | None) -> None:
    """POST a message to a Discord webhook URL.

    The webhook URL embeds its authentication token, so it is stored as the
    field-encrypted ``secret``; ``config['url']`` is only a fallback for legacy
    rows created before the URL was encrypted.
    """
    url = secret or channel.config.get("url")
    if not url:
        raise ValueError("Discord channel has no webhook URL configured.")
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS) as http:
        response = await http.post(url, json={"content": message})
        response.raise_for_status()


async def _send_matrix(channel: NotificationChannel, message: str, secret: str | None) -> None:
    """Post a text message to a Matrix room via the client-server API."""
    homeserver = str(channel.config.get("homeserver", "")).rstrip("/")
    room_id = channel.config.get("room_id")
    if not homeserver or not room_id:
        raise ValueError("Matrix channel needs 'homeserver' and 'room_id'.")
    if not secret:
        raise ValueError("Matrix channel needs an access token.")
    url = f"{homeserver}/_matrix/client/v3/rooms/{room_id}/send/m.room.message"
    # Pass the access token in the Authorization header, never as a URL query
    # parameter: query-string auth is deprecated by the Matrix spec (v1.1+) and
    # would leak the token into homeserver/proxy access logs and error URLs.
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS) as http:
        response = await http.post(
            url,
            headers={"Authorization": f"Bearer {secret}"},
            json={"msgtype": "m.text", "body": message},
        )
        response.raise_for_status()


def _send_smtp(channel: NotificationChannel, message: str, secret: str | None) -> None:
    """Send an email via SMTP (STARTTLS when the port is not 465)."""
    config = channel.config
    host = config.get("host")
    sender = config.get("from")
    recipient = config.get("to")
    if not host or not sender or not recipient:
        raise ValueError("SMTP channel needs 'host', 'from', and 'to'.")
    port = int(config.get("port", 587))
    username = config.get("username") or sender

    email = EmailMessage()
    email["Subject"] = config.get("subject", "Scrye notification")
    email["From"] = sender
    email["To"] = recipient
    email.set_content(message)

    if port == 465:
        server: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=_SMTP_TIMEOUT_SECONDS)
    else:
        server = smtplib.SMTP(host, port, timeout=_SMTP_TIMEOUT_SECONDS)
    try:
        if port != 465:
            server.starttls()
        if secret:
            server.login(username, secret)
        server.send_message(email)
    finally:
        server.quit()


async def send_notification(channel: NotificationChannel, message: str) -> DeliveryResult:
    """Deliver ``message`` over ``channel``; return a UI-safe result.

    Never raises for ordinary transport failures — those are returned as
    ``DeliveryResult(ok=False, ...)`` — and never includes secret material in the
    detail string.
    """
    try:
        secret = _channel_secret(channel)
    except SecretDecryptError:
        return DeliveryResult(ok=False, detail="Stored secret could not be decrypted.")

    try:
        if channel.type is NotificationType.WEBHOOK:
            await _send_webhook(channel, message, secret)
        elif channel.type is NotificationType.DISCORD:
            await _send_discord(channel, message, secret)
        elif channel.type is NotificationType.MATRIX:
            await _send_matrix(channel, message, secret)
        elif channel.type is NotificationType.SMTP:
            await anyio.to_thread.run_sync(_send_smtp, channel, message, secret)
        else:  # pragma: no cover - exhaustive with the enum
            return DeliveryResult(ok=False, detail=f"Unsupported channel type {channel.type!r}.")
    except ValueError as exc:
        return DeliveryResult(ok=False, detail=str(exc))
    except httpx.HTTPError as exc:
        return DeliveryResult(ok=False, detail=f"HTTP delivery failed: {type(exc).__name__}.")
    except (smtplib.SMTPException, OSError) as exc:
        return DeliveryResult(ok=False, detail=f"SMTP delivery failed: {type(exc).__name__}.")

    return DeliveryResult(ok=True, detail="Message delivered.")
