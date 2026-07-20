"""Scan-time target and credential resolution (docs/ARCHIVE.md §4.1, §4.2, §6).

Bridges the database (stored registry/git credentials, uploaded SBOM artifacts)
and the credential materialization layer. Secrets are decrypted **here, at scan
time** and handed to the scanner as short-lived in-memory values; the resolved
:class:`~app.scanners.credentials.RegistryAuth` / ``GitAuth`` never persist.

Filesystem targets are constrained to admin-configured roots so a scan can never
be pointed at arbitrary host paths (e.g. the database or the master-key file).
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.artifacts import artifact_path
from app.core.config import get_settings
from app.core.crypto import SecretDecryptError
from app.core.secret_store import (
    AAD_GIT_TOKEN,
    AAD_REGISTRY_SECRET,
    decrypt_secret,
)
from app.db.models import (
    SECRET_BEARING_AUTH_TYPES,
    Artifact,
    ArtifactKind,
    GitCredential,
    Registry,
    Scan,
)
from app.scanners.base import ScannerError
from app.scanners.credentials import GitAuth, RegistryAuth


class TargetError(ScannerError):
    """A scan target or its credential could not be resolved.

    Subclasses :class:`ScannerError` so the worker treats it like any other
    scan-time failure. The message is operator-safe and never contains secrets.
    """


def resolve_registry_auth(session: Session, options: dict) -> RegistryAuth | None:
    """Resolve the registry credential referenced by a scan's options.

    Args:
        session: Active database session.
        options: The scan's stored options (may carry ``registry_id``).

    Returns:
        A resolved :class:`RegistryAuth`, or ``None`` when no registry is used.

    Raises:
        TargetError: If the registry is missing, disabled, lacks a stored
            secret, or its secret cannot be decrypted.
    """
    registry_id = options.get("registry_id")
    if not registry_id:
        return None
    registry = session.get(Registry, registry_id)
    if registry is None:
        raise TargetError("The selected registry no longer exists.")
    if not registry.enabled:
        raise TargetError(f"Registry {registry.name!r} is disabled.")

    secret: str | None = None
    if registry.auth_type in SECRET_BEARING_AUTH_TYPES:
        if not registry.secret_ciphertext:
            raise TargetError(f"Registry {registry.name!r} has no stored credential.")
        try:
            secret = decrypt_secret(
                registry.secret_ciphertext, aad=AAD_REGISTRY_SECRET, row_id=registry.id
            )
        except SecretDecryptError as exc:
            raise TargetError(
                f"Registry {registry.name!r} credential could not be decrypted."
            ) from exc
    return RegistryAuth(
        registry_host=registry.registry_host,
        auth_type=registry.auth_type,
        username=registry.username,
        secret=secret,
    )


def resolve_git_auth(session: Session, options: dict) -> GitAuth | None:
    """Resolve the git credential referenced by a scan's options.

    Args:
        session: Active database session.
        options: The scan's stored options (may carry ``git_credential_id``).

    Returns:
        A resolved :class:`GitAuth`, or ``None`` for a public repository.

    Raises:
        TargetError: If the credential is missing, has no token, or its token
            cannot be decrypted.
    """
    credential_id = options.get("git_credential_id")
    if not credential_id:
        return None
    credential = session.get(GitCredential, credential_id)
    if credential is None:
        raise TargetError("The selected git credential no longer exists.")
    if not credential.token_ciphertext:
        raise TargetError(f"Git credential {credential.name!r} has no stored token.")
    try:
        token = decrypt_secret(credential.token_ciphertext, aad=AAD_GIT_TOKEN, row_id=credential.id)
    except SecretDecryptError as exc:
        raise TargetError(f"Git credential {credential.name!r} could not be decrypted.") from exc
    return GitAuth(provider=credential.provider, token=token, username=credential.username)


def resolve_filesystem_path(target: str) -> str:
    """Validate a filesystem scan target against the configured allowed roots.

    Args:
        target: The requested absolute directory path.

    Returns:
        The resolved absolute path, guaranteed to exist and sit under a root.

    Raises:
        TargetError: If filesystem scanning is disabled, the path escapes every
            allowed root, or it is not an existing directory.
    """
    roots = get_settings().filesystem_scan_roots
    if not roots:
        raise TargetError(
            "Filesystem scanning is disabled. Set SCRYE_FILESYSTEM_SCAN_ROOTS to the "
            "absolute path(s) that may be scanned."
        )
    resolved = Path(target).resolve()
    within_root = any(
        resolved == (root := Path(raw).resolve()) or root in resolved.parents for raw in roots
    )
    if not within_root:
        raise TargetError("The target path is not under an allowed filesystem scan root.")
    if not resolved.is_dir():
        raise TargetError("The target path does not exist or is not a directory.")
    return str(resolved)


def resolve_sbom_path(session: Session, scan: Scan) -> str:
    """Resolve the on-disk path of the SBOM file attached to an SBOM scan.

    Args:
        session: Active database session.
        scan: The SBOM-target scan whose uploaded SBOM artifact to locate.

    Returns:
        The absolute path of the stored SBOM file.

    Raises:
        TargetError: If no SBOM artifact is attached or its file is missing.
    """
    artifact = session.scalars(
        select(Artifact)
        .where(Artifact.scan_id == scan.id, Artifact.kind == ArtifactKind.SBOM)
        .order_by(Artifact.id)
    ).first()
    if artifact is None:
        raise TargetError("No SBOM file was attached to this scan.")
    try:
        path = artifact_path(artifact.relative_path)
    except ValueError as exc:
        raise TargetError("The attached SBOM path is invalid.") from exc
    if not path.is_file():
        raise TargetError("The attached SBOM file is missing on disk.")
    return str(path)
