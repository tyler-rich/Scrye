"""Docker-environment model for "scan running images" (docs/PLAN.md §3, §4.1).

A :class:`DockerEnvironment` records a read-only ``docker-socket-proxy`` URL that
Scrye can query to *enumerate* images — never to control Docker. The app must
never mount ``/var/run/docker.sock`` (locked decision §0.3, CIS 5.21/5.22); it
talks to the proxy over HTTP and can only list. Because reaching a Docker daemon
(even read-only) is a meaningful exposure, an environment is only usable once an
admin has explicitly acknowledged the residual risk.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.db.base import Base


class DockerEnvironment(Base):
    """A read-only Docker socket-proxy endpoint for image enumeration."""

    __tablename__ = "docker_environments"

    id: Mapped[int] = mapped_column(primary_key=True)
    #: Human-readable label, unique for selection in the UI.
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    #: Base URL of the read-only docker-socket-proxy (e.g. http://proxy:2375).
    proxy_url: Mapped[str] = mapped_column(String(512))
    #: Admin must acknowledge the residual risk before the environment is usable.
    risk_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    #: Whether the environment is offered for enumeration in the UI.
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    created_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_by_username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    def is_usable(self) -> bool:
        """Return True when the environment is enabled and risk-acknowledged."""
        return self.enabled and self.risk_acknowledged
