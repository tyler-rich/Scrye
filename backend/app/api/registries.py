"""Registry credential management (docs/PLAN.md §4.5).

Container-registry credentials are **write-only** and field-encrypted: the
password/token is accepted on write, stored as ciphertext, and never returned
(reads get a mask). Admins manage registries and see their full metadata;
operators get only an id/name options list (``GET /registries/options``) to
select a credential when launching a scan (docs/PLAN.md §14). A ``test`` action
probes the registry to validate connectivity and the stored credential.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.target_schemas import (
    CredentialOption,
    RegistryCreateIn,
    RegistryOut,
    RegistryTestOut,
    RegistryUpdateIn,
)
from app.auth.deps import AuthContext, client_ip, require_csrf, require_role
from app.core.audit import record_audit
from app.core.crypto import SecretDecryptError
from app.core.masking import masked_secret
from app.core.registry_check import check_registry
from app.core.secret_store import AAD_REGISTRY_SECRET, decrypt_secret, encrypt_secret
from app.core.timeutil import utcnow
from app.db.models import SECRET_BEARING_AUTH_TYPES, Registry, RegistryAuthType, Role
from app.db.session import get_db

router = APIRouter(prefix="/registries", tags=["registries"])

_operator = require_role(Role.OPERATOR)
_admin = require_role(Role.ADMIN)


def _to_out(registry: Registry) -> RegistryOut:
    """Build the masked read view of a registry."""
    return RegistryOut(
        id=registry.id,
        name=registry.name,
        registry_host=registry.registry_host,
        auth_type=registry.auth_type,
        username=registry.username,
        enabled=registry.enabled,
        secret=masked_secret(registry.secret_updated_at),
        created_by_username=registry.created_by_username,
        created_at=registry.created_at,
        updated_at=registry.updated_at,
    )


def _get_or_404(db: Session, registry_id: int) -> Registry:
    """Fetch a registry by id or raise 404."""
    registry = db.get(Registry, registry_id)
    if registry is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Registry not found.")
    return registry


@router.get("", response_model=list[RegistryOut])
def list_registries(
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> list[RegistryOut]:
    """List configured registries with full metadata (admin only; secrets masked).

    Non-secret metadata (host, username) is still credential material, so the
    full view is admin-only. Operators launching a scan use ``GET
    /registries/options`` for id/name selection instead (docs/PLAN.md §14).
    """
    rows = db.scalars(select(Registry).order_by(Registry.name)).all()
    return [_to_out(r) for r in rows]


@router.get("/options", response_model=list[CredentialOption])
def list_registry_options(
    _: AuthContext = Depends(_operator),
    db: Session = Depends(get_db),
) -> list[CredentialOption]:
    """List enabled registries as id/name pairs for scan-launch selection.

    Operator-accessible and intentionally minimal: no host, username, auth type,
    or secret — just enough to reference a credential by name when starting a
    scan.
    """
    rows = db.scalars(select(Registry).where(Registry.enabled).order_by(Registry.name)).all()
    return [CredentialOption(id=r.id, name=r.name) for r in rows]


@router.post("", response_model=RegistryOut, status_code=status.HTTP_201_CREATED)
def create_registry(
    payload: RegistryCreateIn,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> RegistryOut:
    """Create a registry credential (secret field-encrypted at rest)."""
    if db.scalar(select(Registry).where(Registry.name == payload.name)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="A registry with that name exists.")

    registry = Registry(
        name=payload.name,
        registry_host=payload.registry_host,
        auth_type=payload.auth_type,
        username=payload.username,
        enabled=payload.enabled,
        created_by_id=auth.user.id,
        created_by_username=auth.user.username,
    )
    if payload.secret is not None:
        registry.secret_ciphertext = encrypt_secret(
            payload.secret.get_secret_value(), aad=AAD_REGISTRY_SECRET
        )
        registry.secret_updated_at = utcnow()
    db.add(registry)
    db.flush()
    record_audit(
        db,
        action="registry.created",
        actor=auth.user,
        ip=client_ip(request),
        target_type="registry",
        target_id=str(registry.id),
        details={"name": registry.name, "auth_type": registry.auth_type.value},
    )
    db.commit()
    return _to_out(registry)


@router.patch("/{registry_id}", response_model=RegistryOut)
def update_registry(
    registry_id: int,
    payload: RegistryUpdateIn,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> RegistryOut:
    """Update a registry; omitting ``secret`` keeps the stored one."""
    registry = _get_or_404(db, registry_id)
    changes: dict[str, object] = {}

    if payload.name is not None and payload.name != registry.name:
        if db.scalar(select(Registry).where(Registry.name == payload.name)) is not None:
            raise HTTPException(
                status.HTTP_409_CONFLICT, detail="A registry with that name exists."
            )
        registry.name = payload.name
        changes["name"] = payload.name
    if payload.registry_host is not None:
        registry.registry_host = payload.registry_host
        changes["registry_host"] = payload.registry_host
    if payload.username is not None:
        blanking = not payload.username.strip()
        if registry.auth_type is RegistryAuthType.USERNAME_PASSWORD and blanking:
            # Create requires a username for this auth type; don't let update
            # blank it back out (APIR-6).
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Username/password auth requires a username.",
            )
        registry.username = payload.username
        changes["username"] = "updated"
    if payload.enabled is not None:
        registry.enabled = payload.enabled
        changes["enabled"] = payload.enabled
    if payload.secret is not None:
        secret_value = payload.secret.get_secret_value()
        if not secret_value:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Secret is empty.")
        if registry.auth_type not in SECRET_BEARING_AUTH_TYPES:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Auth type '{registry.auth_type.value}' does not take a secret.",
            )
        registry.secret_ciphertext = encrypt_secret(secret_value, aad=AAD_REGISTRY_SECRET)
        registry.secret_updated_at = utcnow()
        changes["secret"] = "updated"  # metadata only; never the value

    if changes:
        record_audit(
            db,
            action="registry.updated",
            actor=auth.user,
            ip=client_ip(request),
            target_type="registry",
            target_id=str(registry.id),
            details=changes,
        )
        db.commit()
    return _to_out(registry)


@router.delete("/{registry_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_registry(
    registry_id: int,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> Response:
    """Delete a registry credential."""
    registry = _get_or_404(db, registry_id)
    record_audit(
        db,
        action="registry.deleted",
        actor=auth.user,
        ip=client_ip(request),
        target_type="registry",
        target_id=str(registry.id),
        details={"name": registry.name},
    )
    db.delete(registry)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{registry_id}/test", response_model=RegistryTestOut)
async def test_registry(
    registry_id: int,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> RegistryTestOut:
    """Probe a registry to validate connectivity and the stored credential."""
    registry = _get_or_404(db, registry_id)
    record_audit(
        db,
        action="registry.tested",
        actor=auth.user,
        ip=client_ip(request),
        target_type="registry",
        target_id=str(registry.id),
    )
    db.commit()

    if registry.auth_type not in SECRET_BEARING_AUTH_TYPES:
        return RegistryTestOut(
            ok=True,
            detail=(
                f"Auth type '{registry.auth_type.value}' delegates to a credential helper at "
                "scan time and cannot be verified here."
            ),
        )
    if not registry.secret_ciphertext:
        return RegistryTestOut(ok=False, detail="No stored credential to test.")
    try:
        secret = decrypt_secret(registry.secret_ciphertext, aad=AAD_REGISTRY_SECRET)
    except SecretDecryptError:
        return RegistryTestOut(ok=False, detail="Stored credential could not be decrypted.")

    result = await check_registry(
        registry_host=registry.registry_host, username=registry.username, secret=secret
    )
    return RegistryTestOut(ok=result.ok, detail=result.detail)
