"""Application-layer envelope encryption for stored secrets.

Implements the locked secrets-at-rest design (``docs/ARCHIVE.md`` §6):

- The **master key** is read from a *file* — never an environment variable or
  image layer. The Docker secret file referenced by
  ``SCRYE_APP_SECRET_KEY_FILE`` takes precedence; when no secret is supplied the
  key is **generated once on first launch** and persisted at
  ``SCRYE_APP_SECRET_KEY_AUTOGEN_FILE`` (see :func:`resolve_master_keys` for the
  full precedence order and the invariants that keep a second key from ever
  orphaning stored ciphertext).
- Each secret is encrypted with **AES-256-GCM** using a random per-secret
  96-bit nonce and a 256-bit encryption key derived from the master key via
  **HKDF-SHA256**.
- Stored tokens carry ``key-version || nonce || ciphertext+tag`` so every blob
  is self-describing and **key rotation** is supported: the key file may hold
  multiple versions, new writes use the highest version, and old blobs can be
  re-encrypted with :meth:`SecretCipher.rotate`.

SQLCipher full-DB encryption is deferred; this module is the seam where that
would slot in later (per the locked decision it is *not* built in v1).

Plaintext handling rules: callers must decrypt only when the secret is about to
be used (at scan time, per the plan), never log the result, and never return it
from the API.
"""

from __future__ import annotations

import base64
import binascii
import errno
import logging
import os
import re
import stat
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import Settings, get_settings

logger = logging.getLogger(__name__)

#: Opt-out that lets a deployment whose master key is a raw passphrase boot long
#: enough to rotate to a high-entropy key. Off by default; a temporary
#: boot-and-rotate escape hatch, not a permanent setting (every load under it
#: warns). Read directly from the environment (not the ``Settings`` surface) so
#: it stays out of ``.env.example`` and isn't advertised as normal configuration.
_ALLOW_WEAK_KEY_ENV = "SCRYE_ALLOW_WEAK_MASTER_KEY"
_TRUTHY = frozenset({"1", "true", "yes", "on"})

#: Serialized-token prefix; tokens look like ``scrye$v1$<b64 nonce>$<b64 ct+tag>``.
_TOKEN_PREFIX = "scrye"
_TOKEN_RE = re.compile(r"^scrye\$v(\d+)\$([A-Za-z0-9_-]+)\$([A-Za-z0-9_-]+)$")
#: A key-file line in multi-version form: ``v<version>:<base64 key material>``.
_KEYLINE_RE = re.compile(r"^v(\d+)\s*:\s*(\S+)$")

_NONCE_BYTES = 12  # 96-bit GCM nonce, per NIST SP 800-38D.
_MIN_KEY_BYTES = 32  # Require >= 256 bits of master key material.
_HKDF_INFO = b"scrye/field-encryption"

#: Random bytes in an auto-generated master key. Base64-encoded, 48 bytes is
#: byte-for-byte the documented ``openssl rand -base64 48`` form, so a generated
#: key clears the :data:`_MIN_KEY_BYTES` entropy floor with margin and never needs
#: the :data:`_ALLOW_WEAK_KEY_ENV` opt-out.
_GENERATED_KEY_BYTES = 48
#: Required permissions for a key file this process creates: owner read/write only.
_KEY_FILE_MODE = 0o600
#: Bounded wait for the winner of a generation race to finish writing its file.
#: The winner writes and fsyncs immediately after ``O_CREAT|O_EXCL``, so the window
#: between "the file exists" and "the file has content" is sub-millisecond; this
#: only has to outlast a descheduled writer, never a crashed one.
_RACE_READ_ATTEMPTS = 25
_RACE_READ_DELAY_SECONDS = 0.1


class MasterKeyError(RuntimeError):
    """Raised when the master key file is missing, unreadable, or invalid."""


class MasterKeyFileEmptyError(MasterKeyError):
    """Raised when the key file exists but has no content.

    Distinguished from every other :class:`MasterKeyError` because it is the one
    failure that can be transient: ``O_CREAT|O_EXCL`` publishes the file before
    its content, so a process starting alongside a generator can catch it empty
    (see :func:`_load_key_file`). Every other failure is terminal.
    """


class SecretDecryptError(RuntimeError):
    """Raised when a stored secret token cannot be decrypted."""


def _weak_master_key_allowed() -> bool:
    """Return True if the operator opted in to booting with a low-entropy key.

    Controlled by :data:`_ALLOW_WEAK_KEY_ENV`; a deliberate, temporary escape
    hatch for rotating a legacy passphrase key, off unless explicitly enabled.
    """
    return os.environ.get(_ALLOW_WEAK_KEY_ENV, "").strip().lower() in _TRUTHY


def _decode_key_material(raw: str, *, source: str) -> bytes:
    """Decode and entropy-gate one piece of key material from the key file.

    Requires **valid base64** decoding to at least 256 bits — the documented
    ``openssl rand -base64 48`` form. Non-base64 content is treated as a raw
    passphrase and **rejected**: passphrase-shaped material carries far less
    entropy per byte, so a stolen database could be brute-forced offline at
    HKDF speed (SEC-3). The rejection can be temporarily lifted with
    :data:`_ALLOW_WEAK_KEY_ENV` so an existing passphrase-keyed deployment can
    boot long enough to rotate.

    This is input validation only: for a valid base64 key the returned bytes are
    exactly what they always were, so key derivation and every existing
    encrypted value are unchanged.

    Args:
        raw: The textual key material.
        source: Human-readable origin used in error messages.

    Returns:
        The decoded key bytes.

    Raises:
        MasterKeyError: If the material is not valid base64 (and the weak-key
            opt-out is off) or decodes to fewer than 32 bytes.
    """
    try:
        decoded = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        if not _weak_master_key_allowed():
            raise MasterKeyError(
                f"Master key material from {source} is not valid base64 and is "
                "rejected as a low-entropy passphrase. Generate a high-entropy "
                "key with `openssl rand -base64 48`. To boot an existing "
                "deployment with a legacy passphrase key just long enough to "
                f"rotate it, set {_ALLOW_WEAK_KEY_ENV}=1 (temporary — not for "
                "permanent use)."
            ) from None
        decoded = raw.encode("utf-8")
        logger.warning(
            "%s is set: accepting a non-base64 (low-entropy) master key from %s. "
            "This is a temporary boot-and-rotate escape hatch — rotate to a key "
            "generated with `openssl rand -base64 48` and unset %s.",
            _ALLOW_WEAK_KEY_ENV,
            source,
            _ALLOW_WEAK_KEY_ENV,
        )
    if len(decoded) < _MIN_KEY_BYTES:
        raise MasterKeyError(
            f"Master key material from {source} is too short: "
            f"{len(decoded)} bytes decoded, need at least {_MIN_KEY_BYTES}. "
            "Generate one with `openssl rand -base64 48`."
        )
    return decoded


def load_master_keys(path: Path) -> dict[int, bytes]:
    """Load all master key versions from the secret file.

    Two formats are accepted:

    - **Single key** (the common case): the whole file is one base64 string,
      treated as version 1.
    - **Multi-version** (for rotation): one ``v<N>:<base64>`` entry per line;
      the highest version is used for new encryptions and older versions remain
      available for decryption/rotation.

    This is the loader only; :func:`resolve_master_keys` decides *which* file to
    load and is the only thing that may create one.

    Args:
        path: Filesystem path of the key file (Docker secret or auto-generated).

    Returns:
        Mapping of key version to raw master key bytes.

    Raises:
        MasterKeyError: If the file is missing, empty, or malformed.
    """
    try:
        content = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError as exc:
        raise MasterKeyError(
            f"Master key file not found at {path}. Provide it as a Docker secret "
            "(SCRYE_APP_SECRET_KEY_FILE); generate with `openssl rand -base64 48`."
        ) from exc
    except OSError as exc:
        raise MasterKeyError(f"Master key file at {path} could not be read: {exc}") from exc

    if not content:
        raise MasterKeyFileEmptyError(
            f"Master key file at {path} is empty. An empty key file is never "
            "silently replaced: if it is a zero-byte file left behind by a first "
            "start that was interrupted mid-generation (no secrets stored yet), "
            "delete it and restart to generate a fresh key. Otherwise restore the "
            "original key content — deleting a real key makes every stored secret "
            "unrecoverable."
        )

    lines = [line.strip() for line in content.splitlines() if line.strip()]
    versioned = [_KEYLINE_RE.match(line) for line in lines]

    if all(versioned):
        keys: dict[int, bytes] = {}
        for match in versioned:
            assert match is not None  # narrowed by all() above
            version = int(match.group(1))
            if version < 1:
                raise MasterKeyError(f"Master key versions start at 1; got v{version}.")
            if version in keys:
                raise MasterKeyError(f"Duplicate master key version v{version} in {path}.")
            keys[version] = _decode_key_material(match.group(2), source=f"{path} (v{version})")
        return keys

    if len(lines) == 1:
        return {1: _decode_key_material(lines[0], source=str(path))}

    raise MasterKeyError(
        f"Master key file at {path} is malformed: use a single base64 key, or one "
        "`v<version>:<base64>` entry per line."
    )


@dataclass(frozen=True)
class MasterKeyResolution:
    """The master key actually in force, and where it came from."""

    #: File the key material was read from.
    path: Path
    #: Loaded ``version -> key material`` mapping.
    keys: dict[int, bytes]
    #: True only when *this* call generated the file at :attr:`path`.
    generated: bool
    #: True when the key came from the configured (Docker secret) path rather
    #: than the auto-generated fallback.
    from_configured_path: bool


def _key_file_exists(path: Path) -> bool:
    """Return True if a key file exists at ``path``.

    Absence has to be **proven**, not assumed: a key file that exists but cannot
    be stat-ed (an unreadable parent directory, an I/O error) must never look
    like "no key here", because the caller's next move would be to generate a
    second key and silently orphan every secret already encrypted under the
    first. Only ``ENOENT``/``ENOTDIR`` — the filesystem positively saying the
    path is not there — count as absence.

    Raises:
        MasterKeyError: If presence could not be determined.
    """
    try:
        os.stat(path)
    except OSError as exc:
        if exc.errno in (errno.ENOENT, errno.ENOTDIR):
            return False
        raise MasterKeyError(
            f"Cannot determine whether a master key file exists at {path}: {exc}. "
            "Refusing to start: generating a key here could orphan secrets already "
            "encrypted under an existing one. Fix the path/permissions and restart."
        ) from exc
    return True


def _verify_key_file_permissions(path: Path) -> None:
    """Verify a just-created key file is 0600 and owned by this process.

    A filesystem that ignores POSIX modes (some SMB/vfat mounts, a squashing NFS
    export) would leave the master key group- or world-readable, so the write is
    only trusted after re-reading the metadata back off disk.

    Raises:
        MasterKeyError: If the mode or owner is not what was asked for.
    """
    try:
        info = os.stat(path)
    except OSError as exc:
        raise MasterKeyError(
            f"Generated master key at {path} could not be stat-ed back: {exc}"
        ) from exc

    mode = stat.S_IMODE(info.st_mode)
    if mode != _KEY_FILE_MODE:
        raise MasterKeyError(
            f"Generated master key at {path} has mode {mode:04o}, not "
            f"{_KEY_FILE_MODE:04o}. The filesystem holding it does not honor the "
            "requested permissions, so the key would be readable by other users. "
            "Store the key on a filesystem that preserves POSIX modes, or supply it "
            "yourself as a Docker secret (SCRYE_APP_SECRET_KEY_FILE)."
        )
    if info.st_uid != os.geteuid():
        raise MasterKeyError(
            f"Generated master key at {path} is owned by uid {info.st_uid}, not the "
            f"container uid {os.geteuid()}. The filesystem is remapping ownership; "
            "store the key elsewhere or supply it as a Docker secret "
            "(SCRYE_APP_SECRET_KEY_FILE)."
        )


def _load_key_file(path: Path) -> dict[int, bytes]:
    """Load a key file, tolerating one another process is mid-write.

    ``O_CREAT|O_EXCL`` publishes the *file* before its *content*, so a process
    starting at the same instant as the generator — whether it lost the O_EXCL
    race or simply saw the path exist — can catch the key file empty. Only
    :class:`MasterKeyFileEmptyError` is retried; every other failure (content
    present but malformed, a key below the entropy floor) propagates immediately,
    because waiting cannot change it. Retrying the *load* rather than re-checking
    the file's size is deliberate: the size could change between a failed read and
    the check, which would re-raise a failure the retry had already resolved.

    Waiting out a *crashed* generator is not the goal either — after the bounded
    wait the empty-file error surfaces, and it says how to recover.

    A caller must never treat a failure here as "no key present": generating a
    second key is what orphans stored secrets.

    Raises:
        MasterKeyError: If the file does not load (immediately, or after the wait).
    """
    last_error: MasterKeyFileEmptyError | None = None
    for _ in range(_RACE_READ_ATTEMPTS):
        try:
            return load_master_keys(path)
        except MasterKeyFileEmptyError as exc:
            last_error = exc
            time.sleep(_RACE_READ_DELAY_SECONDS)
    raise MasterKeyError(
        f"Master key file at {path} stayed empty while waiting for a concurrent "
        f"start to write it: {last_error}"
    )


def _generate_master_key_file(path: Path) -> MasterKeyResolution:
    """Generate a master key, persist it at ``path``, and load it back.

    The key is ``os.urandom(48)`` base64-encoded — the documented
    ``openssl rand -base64 48`` form — written with ``O_CREAT|O_EXCL`` so two
    processes starting at once cannot both generate: the loser reads the winner's
    file (:func:`_load_key_file`) instead of minting a second key.

    Raises:
        MasterKeyError: If the directory or file cannot be created, the
            permissions do not come back as 0600/this-uid, or the written key
            does not load.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise MasterKeyError(
            f"Cannot create the directory for the master key file {path}: {exc}. "
            "It must be on a writable, persistent volume."
        ) from exc

    material = base64.b64encode(os.urandom(_GENERATED_KEY_BYTES)).decode("ascii")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _KEY_FILE_MODE)
    except FileExistsError:
        # Lost the race. Someone else's key is now the deployment's key.
        logger.info("Master key file at %s was created concurrently; using that key.", path)
        return MasterKeyResolution(
            path=path,
            keys=_load_key_file(path),
            generated=False,
            from_configured_path=False,
        )
    except OSError as exc:
        raise MasterKeyError(
            f"Cannot create the master key file {path}: {exc}. It must be on a "
            "writable, persistent volume, or supply the key yourself as a Docker "
            "secret (SCRYE_APP_SECRET_KEY_FILE)."
        ) from exc

    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            handle.write(f"{material}\n")
            handle.flush()
            os.fsync(handle.fileno())
        # chmod explicitly: the O_CREAT mode above is masked by the process umask,
        # so it is a ceiling, not a guarantee.
        os.chmod(path, _KEY_FILE_MODE)
        _verify_key_file_permissions(path)
        keys = load_master_keys(path)
    except (OSError, MasterKeyError) as exc:
        # Remove only the file this call created moments ago: nothing has read it,
        # so no ciphertext exists under it, and leaving a half-written or
        # wrongly-permissioned key behind would have the next start silently adopt
        # it. This is the one place deleting a key file is safe.
        try:
            path.unlink(missing_ok=True)
        except OSError:  # pragma: no cover - best-effort cleanup
            logger.warning("Could not remove the failed master key file at %s.", path)
        if isinstance(exc, MasterKeyError):
            raise
        raise MasterKeyError(f"Failed to write the master key file {path}: {exc}") from exc

    logger.info(
        "Generated a new application master key at %s (mode 0600, uid %d). "
        "BACK THIS FILE UP NOW and store the copy somewhere other than the data "
        "volume: every stored secret — registry credentials, git tokens, the OIDC "
        "client secret, MFA seeds, scheduled-backup passphrases — is encrypted with "
        "a key derived from it, and if this file is lost they are UNRECOVERABLE. "
        "There is no recovery path and no backdoor.",
        path,
        os.geteuid(),
    )
    return MasterKeyResolution(path=path, keys=keys, generated=True, from_configured_path=False)


def _assert_generated_key_is_not_orphaned(
    in_use_path: Path,
    in_use_keys: dict[int, bytes],
    generated_path: Path,
) -> None:
    """Refuse to start if an auto-generated key file is being bypassed.

    When a deployment that auto-generated a key later gains a Docker secret, the
    configured secret wins by precedence — and every secret written under the
    generated key would then fail to decrypt. Because stored tokens name their
    key *version*, safety requires each ``version -> material`` pair from the
    generated file to be present **under the same version** in the file actually
    in use; a matching key under a different version number would not be found at
    decrypt time.

    Raises:
        MasterKeyError: If the generated key file exists and is not covered.
    """
    if generated_path == in_use_path or not _key_file_exists(generated_path):
        return

    try:
        generated_keys = load_master_keys(generated_path)
    except MasterKeyError as exc:
        raise MasterKeyError(
            f"A master key file also exists at {generated_path} but could not be "
            f"read: {exc} Refusing to start: it may hold the key that secrets in "
            "this database were encrypted under. Repair or remove it deliberately."
        ) from exc

    uncovered = sorted(
        version
        for version, material in generated_keys.items()
        if in_use_keys.get(version) != material
    )
    if uncovered:
        versions = ", ".join(f"v{version}" for version in uncovered)
        raise MasterKeyError(
            f"Two different master keys are present: {in_use_path} (configured, takes "
            f"precedence) and {generated_path} (previously auto-generated), whose "
            f"{versions} key material is not in the configured file. Any secret "
            "written under the auto-generated key would fail to decrypt, so Scrye "
            "refuses to start. Either copy the auto-generated key line into the "
            "configured file as its own version (keeping the version number it was "
            f"written under) so both decrypt, or delete {generated_path} if nothing "
            "was ever stored under it."
        )


def resolve_master_keys(settings: Settings | None = None) -> MasterKeyResolution:
    """Resolve the master key in force, generating one on first launch if needed.

    Precedence, highest first:

    1. **The configured key file** ``SCRYE_APP_SECRET_KEY_FILE`` (default
       ``/run/secrets/app_secret_key``) — the Docker secret. If a file exists
       there it is used, full stop.
    2. **The auto-generated key file** ``SCRYE_APP_SECRET_KEY_AUTOGEN_FILE``
       (default ``/data/app_secret_key``), if it exists.
    3. **A freshly generated key** written to (2) — only when neither file exists
       and ``SCRYE_APP_SECRET_KEY_AUTOGENERATE`` is on.

    No key is ever taken from an environment variable or an image layer.

    The invariants this enforces, in order of importance:

    - **A key file that exists is used, never replaced.** If it cannot be read,
      is empty, is malformed, or fails the entropy floor, startup **fails** — a
      second key would silently orphan every field-encrypted secret in the
      database. Generation follows only from a *proven absent* file, never from a
      *failed load*.
    - **An explicitly configured path is an assertion.** If an operator set
      ``SCRYE_APP_SECRET_KEY_FILE`` and the file is missing, that is a
      deployment fault (an unmounted secret), so startup fails rather than
      substituting a generated key. Auto-generation applies when the setting is
      left at its default.
    - **The two files may not disagree** — see
      :func:`_assert_generated_key_is_not_orphaned`.

    Raises:
        MasterKeyError: On any of the refusals above, or when no key is found and
            auto-generation is disabled.
    """
    settings = settings or get_settings()
    configured = settings.app_secret_key_file
    generated = settings.app_secret_key_autogen_file

    if _key_file_exists(configured):
        keys = load_master_keys(configured)
        _assert_generated_key_is_not_orphaned(configured, keys, generated)
        return MasterKeyResolution(
            path=configured,
            keys=keys,
            generated=False,
            from_configured_path=True,
        )

    if settings.app_secret_key_file_is_explicit and configured != generated:
        raise MasterKeyError(
            f"SCRYE_APP_SECRET_KEY_FILE is set to {configured}, but no file exists "
            "there. Refusing to start: a configured key path is an assertion that "
            "the key lives there, and generating a different key instead would "
            "orphan every secret already stored under the real one. Mount the "
            "secret (a Compose `secrets:` entry, or a bind mount), or unset "
            "SCRYE_APP_SECRET_KEY_FILE to let Scrye manage a key at "
            f"{generated} itself."
        )

    if _key_file_exists(generated):
        return MasterKeyResolution(
            path=generated,
            keys=_load_key_file(generated),
            generated=False,
            from_configured_path=False,
        )

    if not settings.app_secret_key_autogenerate:
        raise MasterKeyError(
            f"No master key file at {configured} or {generated}, and "
            "SCRYE_APP_SECRET_KEY_AUTOGENERATE is off. Provide the key as a Docker "
            "secret (generate it with `openssl rand -base64 48`) or re-enable "
            "auto-generation."
        )

    return _generate_master_key_file(generated)


class SecretCipher:
    """AES-256-GCM field encryption with HKDF-derived, versioned keys."""

    def __init__(self, master_keys: dict[int, bytes]) -> None:
        """Derive one AES key per master-key version.

        Args:
            master_keys: Mapping of version to raw master key bytes.

        Raises:
            MasterKeyError: If no keys are provided.
        """
        if not master_keys:
            raise MasterKeyError("No master keys available to build the secret cipher.")
        self._aes: dict[int, AESGCM] = {
            version: AESGCM(self._derive_key(material)) for version, material in master_keys.items()
        }
        self.current_version: int = max(self._aes)

    @staticmethod
    def _derive_key(master_key: bytes) -> bytes:
        """Derive the 256-bit field-encryption key from master key material."""
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_HKDF_INFO)
        return hkdf.derive(master_key)

    def encrypt(self, plaintext: str, *, aad: str | None = None) -> str:
        """Encrypt a secret value under the current key version.

        Args:
            plaintext: The secret value to protect.
            aad: Optional associated data binding the blob to its context
                (e.g. ``"registries.password"``); must match on decrypt.

        Returns:
            A self-describing token: ``scrye$v<ver>$<b64 nonce>$<b64 ct+tag>``.
        """
        nonce = os.urandom(_NONCE_BYTES)
        ciphertext = self._aes[self.current_version].encrypt(
            nonce, plaintext.encode("utf-8"), aad.encode("utf-8") if aad else None
        )
        return (
            f"{_TOKEN_PREFIX}$v{self.current_version}"
            f"${base64.urlsafe_b64encode(nonce).decode('ascii').rstrip('=')}"
            f"${base64.urlsafe_b64encode(ciphertext).decode('ascii').rstrip('=')}"
        )

    @staticmethod
    def _parse(token: str) -> tuple[int, bytes, bytes]:
        """Split a token into (version, nonce, ciphertext).

        Raises:
            SecretDecryptError: If the token does not match the expected format.
        """
        match = _TOKEN_RE.match(token)
        if not match:
            raise SecretDecryptError("Stored secret token has an unrecognized format.")

        def _unb64(part: str) -> bytes:
            return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))

        try:
            return int(match.group(1)), _unb64(match.group(2)), _unb64(match.group(3))
        except (binascii.Error, ValueError) as exc:
            # A token that matches the shape but carries malformed base64 (e.g. a
            # corrupted/truncated blob) must surface as SecretDecryptError, the
            # error every caller already handles — not a raw binascii.Error that
            # would 500 a registry test or crash backup creation.
            raise SecretDecryptError("Stored secret token is malformed.") from exc

    def key_version(self, token: str) -> int:
        """Return the key version a stored token was encrypted under."""
        version, _, _ = self._parse(token)
        return version

    def decrypt(self, token: str, *, aad: str | None = None) -> str:
        """Decrypt a stored secret token.

        Args:
            token: A token produced by :meth:`encrypt`.
            aad: The associated data supplied at encryption time, if any.

        Returns:
            The plaintext secret. Handle per the plaintext rules in the module
            docstring — use immediately, never log, never return via the API.

        Raises:
            SecretDecryptError: On unknown key version, tampering, or AAD
                mismatch. The error never contains secret material.
        """
        version, nonce, ciphertext = self._parse(token)
        aes = self._aes.get(version)
        if aes is None:
            raise SecretDecryptError(
                f"Secret was encrypted under key version v{version}, which is not "
                "present in the master key file."
            )
        try:
            plaintext = aes.decrypt(nonce, ciphertext, aad.encode("utf-8") if aad else None)
        except InvalidTag as exc:
            raise SecretDecryptError(
                "Secret failed authentication (wrong key, tampered data, or AAD mismatch)."
            ) from exc
        return plaintext.decode("utf-8")

    def needs_rotation(self, token: str) -> bool:
        """Return True if a token was encrypted under an outdated key version."""
        return self.key_version(token) != self.current_version

    def rotate(self, token: str, *, aad: str | None = None) -> str:
        """Re-encrypt a token under the current key version."""
        return self.encrypt(self.decrypt(token, aad=aad), aad=aad)


@lru_cache
def get_master_key_resolution() -> MasterKeyResolution:
    """Return the process-wide master key, resolving (and generating) it once.

    Cached so first-launch generation and its one-time backup warning happen
    exactly once per process, whichever call site touches a secret first.
    """
    return resolve_master_keys()


@lru_cache
def get_secret_cipher() -> SecretCipher:
    """Return the process-wide cipher built from the resolved master key."""
    return SecretCipher(get_master_key_resolution().keys)


def reset_secret_cipher() -> None:
    """Clear the cached cipher and key resolution (tests and key-rotation flows)."""
    get_secret_cipher.cache_clear()
    get_master_key_resolution.cache_clear()
