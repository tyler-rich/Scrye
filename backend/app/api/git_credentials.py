"""Git-provider credential management (docs/PLAN.md §4.5).

Access tokens for cloning private git repositories are **write-only** and
field-encrypted: accepted on write, stored as ciphertext, and never returned
(reads get a mask). Admins manage credentials and see their full metadata;
operators get only an id/name options list (``GET /git-credentials/options``)
to select a credential when launching a ``trivy repo`` scan (docs/PLAN.md §14).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.target_schemas import (
    CredentialOption,
    GitCredentialCreateIn,
    GitCredentialOut,
    GitCredentialUpdateIn,
)
from app.auth.deps import AuthContext, client_ip, require_csrf, require_role
from app.core.audit import record_audit
from app.core.masking import masked_secret
from app.core.secret_store import AAD_GIT_TOKEN, encrypt_secret
from app.core.timeutil import utcnow
from app.db.models import GitCredential, Role
from app.db.session import get_db

router = APIRouter(prefix="/git-credentials", tags=["git-credentials"])

_operator = require_role(Role.OPERATOR)
_admin = require_role(Role.ADMIN)


def _to_out(credential: GitCredential) -> GitCredentialOut:
    """Build the masked read view of a git credential."""
    return GitCredentialOut(
        id=credential.id,
        name=credential.name,
        provider=credential.provider,
        host=credential.host,
        username=credential.username,
        token=masked_secret(credential.secret_updated_at),
        created_by_username=credential.created_by_username,
        created_at=credential.created_at,
        updated_at=credential.updated_at,
    )


def _get_or_404(db: Session, credential_id: int) -> GitCredential:
    """Fetch a git credential by id or raise 404."""
    credential = db.get(GitCredential, credential_id)
    if credential is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Git credential not found.")
    return credential


@router.get("", response_model=list[GitCredentialOut])
def list_git_credentials(
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> list[GitCredentialOut]:
    """List configured git credentials with full metadata (admin only; tokens masked).

    Metadata (provider, host, username) is credential material, so the full view
    is admin-only. Operators launching a scan use ``GET /git-credentials/options``
    for id/name selection instead (docs/PLAN.md §14).
    """
    rows = db.scalars(select(GitCredential).order_by(GitCredential.name)).all()
    return [_to_out(c) for c in rows]


@router.get("/options", response_model=list[CredentialOption])
def list_git_credential_options(
    _: AuthContext = Depends(_operator),
    db: Session = Depends(get_db),
) -> list[CredentialOption]:
    """List git credentials as id/name pairs for scan-launch selection.

    Operator-accessible and intentionally minimal: no provider, host, username,
    or token — just enough to reference a credential by name when starting a
    ``trivy repo`` scan.
    """
    rows = db.scalars(select(GitCredential).order_by(GitCredential.name)).all()
    return [CredentialOption(id=c.id, name=c.name) for c in rows]


@router.post("", response_model=GitCredentialOut, status_code=status.HTTP_201_CREATED)
def create_git_credential(
    payload: GitCredentialCreateIn,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> GitCredentialOut:
    """Create a git credential (token field-encrypted at rest)."""
    if db.scalar(select(GitCredential).where(GitCredential.name == payload.name)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="A credential with that name exists.")

    credential = GitCredential(
        name=payload.name,
        provider=payload.provider,
        host=payload.host,
        username=payload.username,
        token_ciphertext=encrypt_secret(payload.token.get_secret_value(), aad=AAD_GIT_TOKEN),
        secret_updated_at=utcnow(),
        created_by_id=auth.user.id,
        created_by_username=auth.user.username,
    )
    db.add(credential)
    db.flush()
    record_audit(
        db,
        action="git_credential.created",
        actor=auth.user,
        ip=client_ip(request),
        target_type="git_credential",
        target_id=str(credential.id),
        details={"name": credential.name, "provider": credential.provider.value},
    )
    db.commit()
    return _to_out(credential)


@router.patch("/{credential_id}", response_model=GitCredentialOut)
def update_git_credential(
    credential_id: int,
    payload: GitCredentialUpdateIn,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> GitCredentialOut:
    """Update a git credential; omitting ``token`` keeps the stored one."""
    credential = _get_or_404(db, credential_id)
    changes: dict[str, object] = {}

    if payload.name is not None and payload.name != credential.name:
        if db.scalar(select(GitCredential).where(GitCredential.name == payload.name)) is not None:
            raise HTTPException(
                status.HTTP_409_CONFLICT, detail="A credential with that name exists."
            )
        credential.name = payload.name
        changes["name"] = payload.name
    if payload.host is not None:
        credential.host = payload.host
        changes["host"] = payload.host
    if payload.username is not None:
        credential.username = payload.username
        changes["username"] = "updated"
    if payload.token is not None:
        token_value = payload.token.get_secret_value()
        if not token_value:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Token is empty.")
        credential.token_ciphertext = encrypt_secret(token_value, aad=AAD_GIT_TOKEN)
        credential.secret_updated_at = utcnow()
        changes["token"] = "updated"  # metadata only; never the value

    if changes:
        record_audit(
            db,
            action="git_credential.updated",
            actor=auth.user,
            ip=client_ip(request),
            target_type="git_credential",
            target_id=str(credential.id),
            details=changes,
        )
        db.commit()
    return _to_out(credential)


@router.delete("/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_git_credential(
    credential_id: int,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> Response:
    """Delete a git credential."""
    credential = _get_or_404(db, credential_id)
    record_audit(
        db,
        action="git_credential.deleted",
        actor=auth.user,
        ip=client_ip(request),
        target_type="git_credential",
        target_id=str(credential.id),
        details={"name": credential.name},
    )
    db.delete(credential)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
