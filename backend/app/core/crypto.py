"""Application-layer envelope encryption for stored secrets.

Implements the locked secrets-at-rest design (``docs/PLAN.md`` §6):

- The **master key** is read from the Docker secret file referenced by
  ``SCRYE_APP_SECRET_KEY_FILE`` — never an environment variable or image layer.
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
import os
import re
from functools import lru_cache
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import get_settings

#: Serialized-token prefix; tokens look like ``scrye$v1$<b64 nonce>$<b64 ct+tag>``.
_TOKEN_PREFIX = "scrye"
_TOKEN_RE = re.compile(r"^scrye\$v(\d+)\$([A-Za-z0-9_-]+)\$([A-Za-z0-9_-]+)$")
#: A key-file line in multi-version form: ``v<version>:<base64 key material>``.
_KEYLINE_RE = re.compile(r"^v(\d+)\s*:\s*(\S+)$")

_NONCE_BYTES = 12  # 96-bit GCM nonce, per NIST SP 800-38D.
_MIN_KEY_BYTES = 32  # Require >= 256 bits of master key material.
_HKDF_INFO = b"scrye/field-encryption"


class MasterKeyError(RuntimeError):
    """Raised when the master key file is missing, unreadable, or invalid."""


class SecretDecryptError(RuntimeError):
    """Raised when a stored secret token cannot be decrypted."""


def _decode_key_material(raw: str, *, source: str) -> bytes:
    """Decode one piece of key material from the key file.

    Accepts standard base64 (the documented ``openssl rand -base64 48`` form);
    falls back to the raw UTF-8 bytes for non-base64 content. Either way the
    material must provide at least 256 bits.

    Args:
        raw: The textual key material.
        source: Human-readable origin used in error messages.

    Returns:
        The decoded key bytes.

    Raises:
        MasterKeyError: If the material is shorter than 32 bytes.
    """
    try:
        decoded = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        decoded = raw.encode("utf-8")
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

    Args:
        path: Filesystem path of the Docker secret file.

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
        raise MasterKeyError(f"Master key file at {path} is empty.")

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
def get_secret_cipher() -> SecretCipher:
    """Return the process-wide cipher built from the configured key file."""
    return SecretCipher(load_master_keys(get_settings().app_secret_key_file))


def reset_secret_cipher() -> None:
    """Clear the cached cipher (used by tests and key-rotation flows)."""
    get_secret_cipher.cache_clear()
