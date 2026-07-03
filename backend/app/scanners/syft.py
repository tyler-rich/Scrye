"""Syft SBOM generation: orchestrate ``syft <source> -o <format>``.

Syft is bundled (docs/PLAN.md §4.2): one cataloging pass produces an SBOM that is
stored as a downloadable artifact and can be fed to Grype (``grype sbom:...``).
Only the raw SBOM bytes and its format are returned; parsing into findings is
Grype's job, not Syft's.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.config import get_settings
from app.scanners.base import (
    ScannerError,
    build_env,
    resolve_binary,
    run_command,
)

#: SBOM output formats Scrye offers, in canonical order (default first).
SYFT_FORMATS: tuple[str, ...] = ("cyclonedx-json", "spdx-json", "syft-json")

#: Default SBOM format (CycloneDX JSON — widely consumable and Grype-friendly).
DEFAULT_SYFT_FORMAT = SYFT_FORMATS[0]

#: Suggested artifact filename per format.
SBOM_FILENAMES: dict[str, str] = {
    "cyclonedx-json": "sbom.cyclonedx.json",
    "spdx-json": "sbom.spdx.json",
    "syft-json": "sbom.syft.json",
}


@dataclass
class SbomResult:
    """The output of one Syft cataloging run."""

    raw_output: bytes
    sbom_format: str
    filename: str


def resolve_format(fmt: str | None) -> str:
    """Return a valid Syft format, defaulting when ``fmt`` is unset/unknown."""
    if fmt in SYFT_FORMATS:
        return fmt  # type: ignore[return-value]
    return DEFAULT_SYFT_FORMAT


def build_command(binary: str, source: str, sbom_format: str) -> list[str]:
    """Build the ``syft`` argument vector.

    Args:
        binary: Resolved Syft executable path.
        source: A Syft source string — an image ref or ``dir:<path>``.
        sbom_format: A format token from :data:`SYFT_FORMATS`.

    Returns:
        The full argv list.
    """
    return [binary, "--quiet", "-o", sbom_format, source]


async def generate_sbom(
    source: str, fmt: str | None = None, *, env: dict[str, str] | None = None
) -> SbomResult:
    """Run Syft against ``source`` and return the SBOM bytes.

    Args:
        source: A Syft source string (image ref or ``dir:<path>``).
        fmt: Desired SBOM format; defaults to :data:`DEFAULT_SYFT_FORMAT`.
        env: Optional environment overlay (e.g. transient ``DOCKER_CONFIG``).

    Returns:
        The raw SBOM bytes, its format, and a suggested filename.

    Raises:
        ScannerError: If the binary is missing, times out, or exits non-zero.
    """
    sbom_format = resolve_format(fmt)
    binary = resolve_binary(get_settings().syft_binary)
    argv = build_command(binary, source, sbom_format)
    result = await run_command(
        argv, timeout=get_settings().scan_timeout_seconds, env=build_env(env)
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip() or "no error output"
        raise ScannerError(f"Syft exited with code {result.returncode}: {detail}")
    return SbomResult(
        raw_output=result.stdout,
        sbom_format=sbom_format,
        filename=SBOM_FILENAMES[sbom_format],
    )
