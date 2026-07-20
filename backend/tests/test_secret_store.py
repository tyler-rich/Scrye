"""Tests for the field-secret store helpers (AAD binding)."""

from __future__ import annotations

import pytest

from app.core.crypto import SecretDecryptError
from app.core.secret_store import (
    AAD_GIT_TOKEN,
    AAD_REGISTRY_SECRET,
    decrypt_secret,
    encrypt_secret,
)


def test_encrypt_decrypt_round_trip() -> None:
    token = encrypt_secret("hunter2", aad=AAD_REGISTRY_SECRET)
    assert token != "hunter2"  # never plaintext
    assert "hunter2" not in token
    assert decrypt_secret(token, aad=AAD_REGISTRY_SECRET) == "hunter2"


def test_decrypt_with_wrong_aad_fails() -> None:
    token = encrypt_secret("ghp_token", aad=AAD_GIT_TOKEN)
    # A blob bound to the git-token field must not decrypt under the registry tag.
    with pytest.raises(SecretDecryptError):
        decrypt_secret(token, aad=AAD_REGISTRY_SECRET)


class TestRowBinding:
    def test_row_bound_round_trip(self) -> None:
        token = encrypt_secret("hunter2", aad=AAD_REGISTRY_SECRET, row_id=42)
        assert decrypt_secret(token, aad=AAD_REGISTRY_SECRET, row_id=42) == "hunter2"

    def test_row_bound_blob_does_not_decrypt_for_another_row(self) -> None:
        # SEC-7: a ciphertext bound to row 42 must not authenticate as row 43 —
        # neither under the row-43 tag nor via the legacy column-only fallback.
        token = encrypt_secret("hunter2", aad=AAD_REGISTRY_SECRET, row_id=42)
        with pytest.raises(SecretDecryptError):
            decrypt_secret(token, aad=AAD_REGISTRY_SECRET, row_id=43)

    def test_legacy_column_only_blob_still_decrypts_with_row_id(self) -> None:
        # INVARIANT: a value written before row binding (row_id omitted) must still
        # decrypt when the reader now passes a row_id — the fallback covers it, so
        # no migration is needed.
        legacy = encrypt_secret("hunter2", aad=AAD_REGISTRY_SECRET)  # column-only
        assert decrypt_secret(legacy, aad=AAD_REGISTRY_SECRET, row_id=42) == "hunter2"

    def test_row_bound_blob_requires_the_row_id_to_decrypt(self) -> None:
        # A row-bound blob does not decrypt under the bare column tag alone.
        token = encrypt_secret("hunter2", aad=AAD_REGISTRY_SECRET, row_id=42)
        with pytest.raises(SecretDecryptError):
            decrypt_secret(token, aad=AAD_REGISTRY_SECRET)
