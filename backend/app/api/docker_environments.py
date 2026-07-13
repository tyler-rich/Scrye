"""Docker-environment management + image enumeration (docs/ARCHIVE.md §3, §4.5).

A Docker environment is a read-only ``docker-socket-proxy`` endpoint Scrye can
query to *enumerate* images for the "scan running images" flow. The app never
mounts the Docker socket (locked decision §0.3); it only lists. Because reaching
a Docker daemon is a meaningful exposure, enumeration is refused until an admin
has acknowledged the residual risk on the environment.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.target_schemas import (
    DockerEnvironmentCreateIn,
    DockerEnvironmentOut,
    DockerEnvironmentUpdateIn,
    DockerImageOut,
)
from app.auth.deps import AuthContext, client_ip, require_csrf, require_role
from app.core.audit import record_audit
from app.core.docker_proxy import DockerProxyError, list_images
from app.db.models import DockerEnvironment, Role
from app.db.session import get_db

router = APIRouter(prefix="/docker-environments", tags=["docker-environments"])

_operator = require_role(Role.OPERATOR)
_admin = require_role(Role.ADMIN)


def _to_out(environment: DockerEnvironment) -> DockerEnvironmentOut:
    """Build the read view of a Docker environment."""
    return DockerEnvironmentOut(
        id=environment.id,
        name=environment.name,
        proxy_url=environment.proxy_url,
        risk_acknowledged=environment.risk_acknowledged,
        enabled=environment.enabled,
        created_by_username=environment.created_by_username,
        created_at=environment.created_at,
        updated_at=environment.updated_at,
    )


def _get_or_404(db: Session, environment_id: int) -> DockerEnvironment:
    """Fetch a Docker environment by id or raise 404."""
    environment = db.get(DockerEnvironment, environment_id)
    if environment is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Docker environment not found.")
    return environment


@router.get("", response_model=list[DockerEnvironmentOut])
def list_environments(
    _: AuthContext = Depends(_operator),
    db: Session = Depends(get_db),
) -> list[DockerEnvironmentOut]:
    """List configured Docker environments."""
    rows = db.scalars(select(DockerEnvironment).order_by(DockerEnvironment.name)).all()
    return [_to_out(e) for e in rows]


@router.post("", response_model=DockerEnvironmentOut, status_code=status.HTTP_201_CREATED)
def create_environment(
    payload: DockerEnvironmentCreateIn,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> DockerEnvironmentOut:
    """Create a Docker environment (read-only socket-proxy endpoint)."""
    if (
        db.scalar(select(DockerEnvironment).where(DockerEnvironment.name == payload.name))
        is not None
    ):
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail="An environment with that name exists."
        )

    environment = DockerEnvironment(
        name=payload.name,
        proxy_url=payload.proxy_url,
        risk_acknowledged=payload.risk_acknowledged,
        enabled=payload.enabled,
        created_by_id=auth.user.id,
        created_by_username=auth.user.username,
    )
    db.add(environment)
    db.flush()
    record_audit(
        db,
        action="docker_environment.created",
        actor=auth.user,
        ip=client_ip(request),
        target_type="docker_environment",
        target_id=str(environment.id),
        details={"name": environment.name, "risk_acknowledged": environment.risk_acknowledged},
    )
    db.commit()
    return _to_out(environment)


@router.patch("/{environment_id}", response_model=DockerEnvironmentOut)
def update_environment(
    environment_id: int,
    payload: DockerEnvironmentUpdateIn,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> DockerEnvironmentOut:
    """Update a Docker environment."""
    environment = _get_or_404(db, environment_id)
    changes: dict[str, object] = {}

    if payload.name is not None and payload.name != environment.name:
        if (
            db.scalar(select(DockerEnvironment).where(DockerEnvironment.name == payload.name))
            is not None
        ):
            raise HTTPException(
                status.HTTP_409_CONFLICT, detail="An environment with that name exists."
            )
        environment.name = payload.name
        changes["name"] = payload.name
    if payload.proxy_url is not None:
        environment.proxy_url = payload.proxy_url
        changes["proxy_url"] = payload.proxy_url
    if payload.risk_acknowledged is not None:
        environment.risk_acknowledged = payload.risk_acknowledged
        changes["risk_acknowledged"] = payload.risk_acknowledged
    if payload.enabled is not None:
        environment.enabled = payload.enabled
        changes["enabled"] = payload.enabled

    if changes:
        record_audit(
            db,
            action="docker_environment.updated",
            actor=auth.user,
            ip=client_ip(request),
            target_type="docker_environment",
            target_id=str(environment.id),
            details=changes,
        )
        db.commit()
    return _to_out(environment)


@router.delete("/{environment_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_environment(
    environment_id: int,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> Response:
    """Delete a Docker environment."""
    environment = _get_or_404(db, environment_id)
    record_audit(
        db,
        action="docker_environment.deleted",
        actor=auth.user,
        ip=client_ip(request),
        target_type="docker_environment",
        target_id=str(environment.id),
        details={"name": environment.name},
    )
    db.delete(environment)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{environment_id}/images", response_model=list[DockerImageOut])
async def enumerate_images(
    environment_id: int,
    _: AuthContext = Depends(_operator),
    db: Session = Depends(get_db),
) -> list[DockerImageOut]:
    """Enumerate tagged images visible to a Docker environment's proxy.

    Requires the environment to be enabled and risk-acknowledged. Returns image
    references the caller can then scan as normal image targets.
    """
    environment = _get_or_404(db, environment_id)
    if not environment.enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="This environment is disabled.")
    if not environment.risk_acknowledged:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="Acknowledge the Docker-access residual risk before enumerating images.",
        )
    try:
        images = await list_images(environment.proxy_url)
    except DockerProxyError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    return [DockerImageOut(id=i.id, tags=i.tags, size_bytes=i.size_bytes) for i in images]
