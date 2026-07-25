"""Admin user management (RBAC: admin only)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.pagination import Page, full_page
from app.api.schemas import PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH, NewUserIn, UserOut
from app.auth import service
from app.auth.deps import AuthContext, client_ip, require_csrf, require_role
from app.auth.passwords import hash_password
from app.core.audit import record_audit
from app.db.models import Role, User
from app.db.session import get_db

router = APIRouter(prefix="/users", tags=["users"])

_admin = require_role(Role.ADMIN)


class UserCreateIn(NewUserIn):
    """Admin payload for creating a user with an explicit role."""

    role: Role = Role.VIEWER


class UserUpdateIn(BaseModel):
    """Admin payload for updating a user (all fields optional)."""

    role: Role | None = None
    is_active: bool | None = None
    password: str | None = Field(
        default=None, min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH
    )


@router.get("", response_model=Page[UserOut])
def list_users(
    auth: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> Page[UserOut]:
    """List all user accounts."""
    users = db.scalars(select(User).order_by(User.username)).all()
    return full_page([UserOut.model_validate(u) for u in users])


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreateIn,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> UserOut:
    """Create a user account with the given role."""
    if service.get_user_by_username(db, payload.username) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="Username is already taken.")
    user = service.create_user(
        db, username=payload.username, password=payload.password, role=payload.role
    )
    record_audit(
        db,
        action="user.created",
        actor=auth.user,
        ip=client_ip(request),
        target_type="user",
        target_id=str(user.id),
        details={"username": user.username, "role": user.role.value},
    )
    db.commit()
    return UserOut.model_validate(user)


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    payload: UserUpdateIn,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> UserOut:
    """Update a user's role, active flag, or password.

    Self-lockout guards: an admin cannot change their own role or deactivate
    their own account. Deactivation and password resets revoke the target's
    sessions.
    """
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="User not found.")

    changes: dict[str, object] = {}
    if payload.role is not None and payload.role != user.role:
        if user.id == auth.user.id:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, detail="You cannot change your own role."
            )
        user.role = payload.role
        changes["role"] = payload.role.value

    if payload.is_active is not None and payload.is_active != user.is_active:
        if user.id == auth.user.id:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, detail="You cannot deactivate your own account."
            )
        user.is_active = payload.is_active
        changes["is_active"] = payload.is_active
        if not payload.is_active:
            changes["sessions_revoked"] = service.revoke_all_sessions(db, user)

    if payload.password is not None:
        user.password_hash = hash_password(payload.password)
        changes["password"] = "changed"  # metadata only; never the value
        changes["sessions_revoked"] = service.revoke_all_sessions(db, user)

    if changes:
        record_audit(
            db,
            action="user.updated",
            actor=auth.user,
            ip=client_ip(request),
            target_type="user",
            target_id=str(user.id),
            details=changes,
        )
        db.commit()
    return UserOut.model_validate(user)
