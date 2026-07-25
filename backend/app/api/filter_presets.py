"""Saved scan-history filter presets (docs/ARCHIVE.md §4.4).

Presets are **owner-scoped**: every endpoint operates only on the presets owned
by the authenticated user, so any viewer can save, list, update, and delete
their own filter sets. Writes are CSRF-guarded. The stored ``filters`` payload
is non-sensitive filter metadata (scanner, status, severity, tags, ...).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.history_schemas import FilterPresetIn, FilterPresetOut
from app.api.pagination import Page, full_page
from app.auth.deps import AuthContext, require_auth, require_csrf
from app.db.models import FilterPreset
from app.db.session import get_db

router = APIRouter(prefix="/filter-presets", tags=["filter-presets"])


def _get_owned_or_404(db: Session, preset_id: int, owner_id: int) -> FilterPreset:
    """Fetch a preset owned by ``owner_id`` or raise 404 (never leak others')."""
    preset = db.get(FilterPreset, preset_id)
    if preset is None or preset.owner_id != owner_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Filter preset not found.")
    return preset


@router.get("", response_model=Page[FilterPresetOut])
def list_presets(
    auth: AuthContext = Depends(require_auth),
    db: Session = Depends(get_db),
) -> Page[FilterPresetOut]:
    """List the authenticated user's saved filter presets."""
    rows = db.scalars(
        select(FilterPreset)
        .where(FilterPreset.owner_id == auth.user.id)
        .order_by(FilterPreset.name)
    ).all()
    return full_page([FilterPresetOut.model_validate(r) for r in rows])


@router.post("", response_model=FilterPresetOut, status_code=status.HTTP_201_CREATED)
def create_preset(
    payload: FilterPresetIn,
    auth: AuthContext = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> FilterPresetOut:
    """Create a new filter preset owned by the authenticated user."""
    exists = db.scalar(
        select(FilterPreset).where(
            FilterPreset.owner_id == auth.user.id, FilterPreset.name == payload.name
        )
    )
    if exists is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail="A preset with that name already exists."
        )
    preset = FilterPreset(owner_id=auth.user.id, name=payload.name, filters=payload.filters)
    db.add(preset)
    db.commit()
    db.refresh(preset)
    return FilterPresetOut.model_validate(preset)


@router.put("/{preset_id}", response_model=FilterPresetOut)
def update_preset(
    preset_id: int,
    payload: FilterPresetIn,
    auth: AuthContext = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> FilterPresetOut:
    """Rename a preset or replace its saved filters."""
    preset = _get_owned_or_404(db, preset_id, auth.user.id)
    if payload.name != preset.name:
        clash = db.scalar(
            select(FilterPreset).where(
                FilterPreset.owner_id == auth.user.id,
                FilterPreset.name == payload.name,
                FilterPreset.id != preset.id,
            )
        )
        if clash is not None:
            raise HTTPException(
                status.HTTP_409_CONFLICT, detail="A preset with that name already exists."
            )
    preset.name = payload.name
    preset.filters = payload.filters
    db.commit()
    db.refresh(preset)
    return FilterPresetOut.model_validate(preset)


@router.delete("/{preset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_preset(
    preset_id: int,
    auth: AuthContext = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> Response:
    """Delete one of the authenticated user's presets."""
    preset = _get_owned_or_404(db, preset_id, auth.user.id)
    db.delete(preset)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
