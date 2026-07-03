"""Materialize Trivy VEX documents and ignore rules for a scan (Phase 6).

Trivy honors two policy inputs Scrye manages in the database:

- a ``.trivyignore`` file (the global blob from scanner settings plus the active
  structured ignore rules), passed via the ``TRIVY_IGNOREFILE`` env var, and
- one or more VEX documents, written to files and passed via ``TRIVY_VEX``.

Using Trivy's environment-variable equivalents of ``--ignorefile`` / ``--vex``
keeps the transient file paths off the process argv and means the scanner
argv-builders don't need to change. The files live in a per-scan temp directory
(the container's tmpfs ``/tmp``) and are removed when the context exits, on
success or failure. None of this data is secret, but cleaning up keeps tmpfs
tidy across many scans.
"""

from __future__ import annotations

import contextlib
import shutil
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.app_settings import SettingsService
from app.core.timeutil import utcnow
from app.db.models import VEX_FILE_SUFFIX, TrivyIgnoreRule, VexDocument, VexFormat

#: Name of the rendered ignore file within the per-scan temp directory.
_IGNOREFILE_NAME = ".trivyignore"


@dataclass(frozen=True)
class _VexDoc:
    """A VEX document to materialize (name, format, body)."""

    name: str
    format: VexFormat
    content: str


@dataclass
class TrivyPolicy:
    """The resolved Trivy policy inputs for a scan."""

    ignorefile_text: str = ""
    vex_documents: list[_VexDoc] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        """Return True when there is nothing to materialize."""
        return not self.ignorefile_text.strip() and not self.vex_documents


def _render_ignorefile(global_blob: str, rules: list[TrivyIgnoreRule]) -> str:
    """Render the combined ``.trivyignore`` from the global blob + active rules."""
    lines: list[str] = []
    blob = (global_blob or "").strip()
    if blob:
        lines.append("# --- Global ignore rules (scanner settings) ---")
        lines.append(blob)
    if rules:
        lines.append("# --- Managed ignore rules ---")
        for rule in rules:
            reason = rule.reason.strip() if rule.reason else ""
            if reason:
                lines.append(f"# {reason}")
            lines.append(rule.vuln_id)
    return "\n".join(lines).strip() + ("\n" if lines else "")


def load_trivy_policy(db: Session) -> TrivyPolicy:
    """Load the active ignore rules, global ignore blob, and VEX documents."""
    now = utcnow()
    scanner_settings = SettingsService(db).scanners()
    rules = list(
        db.scalars(
            select(TrivyIgnoreRule)
            .where(TrivyIgnoreRule.enabled.is_(True))
            .order_by(TrivyIgnoreRule.vuln_id)
        ).all()
    )
    active_rules = [r for r in rules if r.expires_at is None or r.expires_at > now]

    ignorefile_text = _render_ignorefile(scanner_settings.trivyignore, active_rules)

    vex_rows = db.scalars(
        select(VexDocument).where(VexDocument.enabled.is_(True)).order_by(VexDocument.id)
    ).all()
    vex_docs = [_VexDoc(name=v.name, format=v.format, content=v.content) for v in vex_rows]

    return TrivyPolicy(ignorefile_text=ignorefile_text, vex_documents=vex_docs)


@contextlib.contextmanager
def materialize_trivy_policy(policy: TrivyPolicy) -> Iterator[dict[str, str]]:
    """Write the policy files to a temp dir; yield the Trivy env overlay.

    The overlay sets ``TRIVY_IGNOREFILE`` and/or ``TRIVY_VEX`` (Trivy's
    equivalents of ``--ignorefile`` / ``--vex``). An empty policy yields an empty
    overlay and creates no files. The temp directory is always removed on exit.
    """
    if policy.is_empty:
        yield {}
        return

    tmpdir = Path(tempfile.mkdtemp(prefix="scrye-trivy-policy-"))
    try:
        overlay: dict[str, str] = {}
        if policy.ignorefile_text.strip():
            ignore_path = tmpdir / _IGNOREFILE_NAME
            ignore_path.write_text(policy.ignorefile_text, encoding="utf-8")
            overlay["TRIVY_IGNOREFILE"] = str(ignore_path)

        vex_paths: list[str] = []
        for index, doc in enumerate(policy.vex_documents):
            suffix = VEX_FILE_SUFFIX.get(doc.format, ".json")
            vex_path = tmpdir / f"vex-{index}{suffix}"
            vex_path.write_text(doc.content, encoding="utf-8")
            vex_paths.append(str(vex_path))
        if vex_paths:
            overlay["TRIVY_VEX"] = ",".join(vex_paths)

        yield overlay
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
