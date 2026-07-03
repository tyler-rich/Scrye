"""Trivy VEX documents and ignore rules (docs/PLAN.md §4.1/§4.5, Phase 6).

Two admin-managed policy inputs that shape Trivy's results:

- :class:`VexDocument` — a Vulnerability Exploitability eXchange document
  (OpenVEX / CycloneDX VEX / CSAF) whose statements let Trivy suppress
  vulnerabilities that are documented as not-affected. The document body is
  non-secret policy data stored verbatim and materialized into a tmpfs file that
  Trivy reads via ``--vex`` at scan time.
- :class:`TrivyIgnoreRule` — one structured ``.trivyignore`` entry (a
  vulnerability/check id, an optional human reason, and an optional expiry).
  Active rules are rendered into a transient ``.trivyignore`` passed to Trivy.

Neither table stores secret material.
"""

from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.db.base import Base


class VexFormat(enum.StrEnum):
    """Supported VEX document formats Trivy can consume."""

    OPENVEX = "openvex"
    CYCLONEDX = "cyclonedx"
    CSAF = "csaf"


#: File extension used when materializing each VEX format for Trivy's ``--vex``.
VEX_FILE_SUFFIX: dict[VexFormat, str] = {
    VexFormat.OPENVEX: ".openvex.json",
    VexFormat.CYCLONEDX: ".cdx.json",
    VexFormat.CSAF: ".csaf.json",
}


class VexDocument(Base):
    """A stored VEX document applied to Trivy scans when enabled."""

    __tablename__ = "vex_documents"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    format: Mapped[VexFormat] = mapped_column(
        Enum(
            VexFormat,
            native_enum=False,
            length=16,
            values_callable=lambda e: [m.value for m in e],
        )
    )
    #: The raw VEX document body (JSON text); non-secret policy data.
    content: Mapped[str] = mapped_column(Text)

    created_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_by_username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class TrivyIgnoreRule(Base):
    """One structured ``.trivyignore`` entry applied to Trivy scans."""

    __tablename__ = "trivy_ignore_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    #: The id to ignore (CVE, GHSA, or a Trivy misconfig/secret check id).
    vuln_id: Mapped[str] = mapped_column(String(128), index=True)
    #: Optional human-readable justification (rendered as a comment).
    reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    #: Optional expiry; an expired rule is no longer applied.
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    created_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_by_username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
