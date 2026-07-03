"""Generate the repository ``.env.example`` from the :class:`Settings` model.

The config loader is the single source of truth for configuration (see
``CLAUDE.md`` § Required deliverables). Run this whenever ``Settings`` changes::

    python -m scripts.gen_env_example          # write ../.env.example
    python -m scripts.gen_env_example --check   # fail if out of date

Only **non-sensitive** variables are emitted. The application master key is
never included — it is read at runtime from the Docker secret file referenced by
``SCRYE_APP_SECRET_KEY_FILE``. When future phases add stored-secret settings
(e.g. an OIDC client secret), they must be emitted as a named placeholder with a
comment, never a real value.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from app.core.config import Settings

HEADER = """\
# ─────────────────────────────────────────────────────────────
# Scrye — example environment configuration
# ─────────────────────────────────────────────────────────────
# Generated from the Pydantic `Settings` model
# (backend/app/core/config.py) via `python -m scripts.gen_env_example`.
# Do NOT edit by hand — update the Settings model and regenerate.
#
# These are NON-SENSITIVE configuration variables only. The application
# master key is never set here; it is read from the Docker secret file
# referenced by SCRYE_APP_SECRET_KEY_FILE. Copy this file to `.env` for
# local development and adjust values as needed.
# ─────────────────────────────────────────────────────────────
"""


def _format_default(value: Any) -> str:
    """Render a field default as an env-file value string."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list | tuple):
        return ",".join(str(item) for item in value)
    return str(value)


def render_env_example() -> str:
    """Render the full ``.env.example`` contents from the Settings model."""
    prefix = Settings.model_config.get("env_prefix", "")
    lines: list[str] = [HEADER]

    for name, field in Settings.model_fields.items():
        env_var = f"{prefix}{name}".upper()
        description = (field.description or "").strip()
        if description:
            lines.append(f"# {description}")
        default = field.get_default(call_default_factory=True)
        lines.append(f"{env_var}={_format_default(default)}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _target_path() -> Path:
    """Return the repository-root path of ``.env.example``."""
    # backend/scripts/gen_env_example.py -> repo root is two parents up.
    return Path(__file__).resolve().parents[2] / ".env.example"


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint: write or check the generated ``.env.example``."""
    parser = argparse.ArgumentParser(description="Generate .env.example from Settings.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if .env.example is out of date instead of writing it.",
    )
    args = parser.parse_args(argv)

    rendered = render_env_example()
    target = _target_path()

    if args.check:
        current = target.read_text(encoding="utf-8") if target.exists() else ""
        if current != rendered:
            print(f"{target} is out of date; run `python -m scripts.gen_env_example`.")
            return 1
        print(f"{target} is up to date.")
        return 0

    target.write_text(rendered, encoding="utf-8")
    print(f"Wrote {target}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
