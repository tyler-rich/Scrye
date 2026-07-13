"""Personal API token management (docs/PLAN.md §4.5, §5).

Each user manages their own tokens. A token's role is chosen at mint time and
capped at the creator's role, so a token can never grant more than its owner
has. The plaintext token is returned **once** on creation and never again; reads
show only the prefix and metadata.
"""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.schema_types import UtcDatetime
from app.auth.api_tokens import generate_api_token
from app.auth.deps import AuthContext, client_ip, require_auth, require_csrf
from app.core.audit import record_audit
from app.core.timeutil import utcnow
from app.db.models import ROLE_RANK, ApiToken, Role
from app.db.session import get_db

router = APIRouter(prefix="/api-tokens", tags=["api-tokens"])

#: Bound on a token's optional lifetime.
_MAX_EXPIRY_DAYS = 3650


class ApiTokenOut(BaseModel):
    """Read view of an API token (never includes the plaintext)."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    token_prefix: str
    role: Role
    created_at: UtcDatetime
    last_used_at: UtcDatetime | None
    expires_at: UtcDatetime | None
    revoked_at: UtcDatetime | None


class ApiTokenCreateIn(BaseModel):
    """Payload for minting a new API token."""

    name: str = Field(min_length=1, max_length=128)
    #: Effective role; must be ≤ the caller's role. Defaults to the caller's role.
    role: Role | None = None
    #: Optional lifetime in days; omitted means the token never expires.
    expires_in_days: int | None = Field(default=None, ge=1, le=_MAX_EXPIRY_DAYS)


class ApiTokenCreatedOut(ApiTokenOut):
    """Creation response: the read view plus the one-time plaintext token."""

    token: str


@router.get("", response_model=list[ApiTokenOut])
def list_tokens(
    auth: AuthContext = Depends(require_auth),
    db: Session = Depends(get_db),
) -> list[ApiTokenOut]:
    """List the caller's own API tokens (plaintext never included)."""
    rows = db.scalars(
        select(ApiToken)
        .where(ApiToken.owner_id == auth.user.id)
        .order_by(ApiToken.created_at.desc())
    ).all()
    return [ApiTokenOut.model_validate(r) for r in rows]


@router.post("", response_model=ApiTokenCreatedOut, status_code=status.HTTP_201_CREATED)
def create_token(
    payload: ApiTokenCreateIn,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> ApiTokenCreatedOut:
    """Mint an API token and return its plaintext once."""
    # Cap against the caller's *effective* role, not the owner's account role:
    # a low-privilege bearer token belonging to an admin must not be able to
    # mint a higher-privilege token than the token itself carries (QUA-1).
    role = payload.role or auth.effective_role
    if ROLE_RANK[role] > ROLE_RANK[auth.effective_role]:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail="A token cannot be granted a higher role than your own.",
        )

    generated = generate_api_token()
    expires_at = (
        utcnow() + timedelta(days=payload.expires_in_days) if payload.expires_in_days else None
    )
    token = ApiToken(
        name=payload.name,
        token_prefix=generated.prefix,
        token_hash=generated.token_hash,
        owner_id=auth.user.id,
        owner_username=auth.user.username,
        role=role,
        expires_at=expires_at,
    )
    db.add(token)
    db.flush()
    record_audit(
        db,
        action="api_token.created",
        actor=auth.user,
        ip=client_ip(request),
        target_type="api_token",
        target_id=str(token.id),
        details={"name": token.name, "role": role.value},
    )
    db.commit()
    base = ApiTokenOut.model_validate(token)
    # Return the read view plus the one-time plaintext (never stored, never re-shown).
    return ApiTokenCreatedOut(**base.model_dump(), token=generated.raw)


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_token(
    token_id: int,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> Response:
    """Revoke one of the caller's own API tokens."""
    token = db.get(ApiToken, token_id)
    if token is None or token.owner_id != auth.user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Token not found.")
    if token.revoked_at is None:
        token.revoked_at = utcnow()
        record_audit(
            db,
            action="api_token.revoked",
            actor=auth.user,
            ip=client_ip(request),
            target_type="api_token",
            target_id=str(token.id),
        )
        db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
