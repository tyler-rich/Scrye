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
