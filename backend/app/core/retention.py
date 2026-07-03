"""Result-retention pruning of old raw scan artifacts (docs/PLAN.md §12, Phase 6).

Raw scanner output and SBOMs are the source of truth (§4.3) but the bulk of the
on-disk footprint. When retention is enabled, artifacts belonging to scans older
than the configured age are removed — files and metadata rows — while the scan
row and its normalized findings are kept, so history, trends, and severity
counts remain intact but disk usage stays bounded.

These helpers are pure and synchronous so the maintenance scheduler can call them
on a timer and tests can exercise them directly against a session.
"""

from __future__ import annotations

import contextlib
import logging
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.app_settings import SettingsService
from app.core.artifacts import artifact_path
from app.core.timeutil import utcnow
from app.db.models import Artifact, Scan

logger = logging.getLogger(__name__)


def prune_expired_artifacts(db: Session, *, max_age_days: int, now: datetime | None = None) -> int:
    """Delete raw artifacts of scans older than ``max_age_days`` (returns count).

    The scan rows and normalized findings are preserved; only the raw artifact
    files and their metadata rows are removed. A missing file on disk is ignored
    (the row is still removed) so a partially-cleaned state converges.
    """
    cutoff = (now or utcnow()) - timedelta(days=max_age_days)
    old_scan_ids = select(Scan.id).where(Scan.created_at < cutoff)
    artifacts = db.scalars(select(Artifact).where(Artifact.scan_id.in_(old_scan_ids))).all()

    pruned = 0
    for artifact in artifacts:
        with contextlib.suppress(OSError, ValueError):
            artifact_path(artifact.relative_path).unlink(missing_ok=True)
        db.delete(artifact)
        pruned += 1
    if pruned:
        db.commit()
        logger.info(
            "Retention pruned %d raw artifact(s) older than %d day(s).", pruned, max_age_days
        )
    return pruned


def run_retention(db: Session, *, now: datetime | None = None) -> int:
    """Run retention if enabled in settings; return the number of artifacts pruned."""
    settings = SettingsService(db).retention()
    if not settings.enabled:
        return 0
    return prune_expired_artifacts(db, max_age_days=settings.max_age_days, now=now)
