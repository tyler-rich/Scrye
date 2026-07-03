"""Audit-log recording helper.

All security-relevant actions (logins, failures, logouts, user/role changes,
session revocations, secret writes) go through :func:`record_audit`. Callers
must pass **metadata only** in ``details`` — never secret values.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.db.models import AuditLog, User


def record_audit(
    db: Session,
    *,
    action: str,
    actor: User | None = None,
    ip: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    """Add an audit entry to the current transaction (caller commits).

    Args:
        db: Active database session.
        action: Dotted action name, e.g. ``"auth.login"`` or ``"user.updated"``.
        actor: The acting user, if authenticated.
        ip: Client IP address, when known.
        target_type: Kind of object acted on (e.g. ``"user"``).
        target_id: Identifier of the acted-on object.
        details: Extra metadata — must never contain secret values.

    Returns:
        The pending :class:`AuditLog` row.
    """
    entry = AuditLog(
        action=action,
        actor_id=actor.id if actor else None,
        actor_username=actor.username if actor else None,
        ip=ip,
        target_type=target_type,
        target_id=target_id,
        details=details,
    )
    db.add(entry)
    return entry
