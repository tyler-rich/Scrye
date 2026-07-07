"""Materialize the global Grype ignore config for a scan (FEAT-6).

The Scanners settings group carries a free-form **Grype config YAML** blob
(``ScannerSettings.grype_ignore``) — typically an ``ignore:`` rule list. Grype
applies it via a config file (``grype -c <path>``), so at scan time the blob is
written to a temp file on the container tmpfs and its path handed to the Grype
runner. Nothing here is secret; the temp dir is removed when the context exits,
on success or failure.
"""

from __future__ import annotations

import contextlib
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.app_settings import SettingsService

#: Private env-overlay key the worker uses to hand the Grype runner a config
#: path. It is popped before the child environment is built (and ``SCRYE_*`` is
#: stripped from inherited env anyway), so it never reaches Grype as an env var.
GRYPE_CONFIG_OVERLAY_KEY = "SCRYE_GRYPE_CONFIG"

#: Name of the rendered config file within the per-scan temp directory.
_CONFIG_NAME = ".grype.yaml"


def load_grype_ignore(db: Session) -> str:
    """Return the configured global Grype ignore/config YAML (may be empty)."""
    return SettingsService(db).scanners().grype_ignore or ""


@contextlib.contextmanager
def materialize_grype_config(config_yaml: str) -> Iterator[dict[str, str]]:
    """Write the Grype config to a temp file; yield the runner env overlay.

    An empty/blank config yields an empty overlay and creates no file. The
    returned overlay carries the config path under
    :data:`GRYPE_CONFIG_OVERLAY_KEY`, which the Grype runner converts into a
    ``-c <path>`` argv flag.
    """
    if not config_yaml.strip():
        yield {}
        return

    tmpdir = Path(tempfile.mkdtemp(prefix="scrye-grype-config-"))
    try:
        config_path = tmpdir / _CONFIG_NAME
        config_path.write_text(config_yaml, encoding="utf-8")
        yield {GRYPE_CONFIG_OVERLAY_KEY: str(config_path)}
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
