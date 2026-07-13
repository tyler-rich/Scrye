"""Unit tests for the envelope-encryption module (docs/PLAN.md §6)."""

from __future__ import annotations

import base64
import os
from pathlib import Path

import pytest

from app.core.crypto import (
    MasterKeyError,
    SecretCipher,
    SecretDecryptError,
    load_master_keys,
)


def _write_key_file(tmp_path: Path, content: str) -> Path:
    key_file = tmp_path / "app_secret_key"
    key_file.write_text(content, encoding="utf-8")
    return key_file


def _random_b64_key() -> str:
    return base64.b64encode(os.urandom(48)).decode("ascii")


@pytest.fixture
def cipher(tmp_path: Path) -> SecretCipher:
    key_file = _write_key_file(tmp_path, _random_b64_key())
    return SecretCipher(load_master_keys(key_file))


class TestKeyLoading:
    def test_single_base64_key_is_version_1(self, tmp_path: Path) -> None:
        keys = load_master_keys(_write_key_file(tmp_path, _random_b64_key() + "\n"))
        assert set(keys) == {1}
        assert len(keys[1]) == 48

    def test_multi_version_file(self, tmp_path: Path) -> None:
        content = f"v1:{_random_b64_key()}\nv2:{_random_b64_key()}\n"
        keys = load_master_keys(_write_key_file(tmp_path, content))
        assert set(keys) == {1, 2}
        assert keys[1] != keys[2]

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(MasterKeyError, match="not found"):
            load_master_keys(tmp_path / "nope")

    def test_empty_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(MasterKeyError, match="empty"):
            load_master_keys(_write_key_file(tmp_path, "  \n"))

    def test_short_key_raises(self, tmp_path: Path) -> None:
        short = base64.b64encode(os.urandom(16)).decode("ascii")
        with pytest.raises(MasterKeyError, match="too short"):
            load_master_keys(_write_key_file(tmp_path, short))

    def test_duplicate_version_raises(self, tmp_path: Path) -> None:
        key = _random_b64_key()
        with pytest.raises(MasterKeyError, match="Duplicate"):
            load_master_keys(_write_key_file(tmp_path, f"v1:{key}\nv1:{key}\n"))

    def test_malformed_multiline_raises(self, tmp_path: Path) -> None:
        with pytest.raises(MasterKeyError, match="malformed"):
            load_master_keys(_write_key_file(tmp_path, f"{_random_b64_key()}\nnot-a-key-line\n"))

    def test_raw_non_base64_key_rejected_by_entropy_floor(self, tmp_path: Path) -> None:
        # A raw passphrase (not valid base64) is now refused as low-entropy
        # even when it is >= 32 bytes long (SEC-3), with an actionable error.
        with pytest.raises(MasterKeyError, match="not valid base64"):
            load_master_keys(_write_key_file(tmp_path, "correct horse battery staple pw!"))

    def test_weak_key_accepted_under_optout_with_warning(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        # The temporary boot-and-rotate escape hatch lets a legacy passphrase key
        # load (>= 32 bytes), but every load under it logs a warning so it can't
        # quietly become permanent.
        monkeypatch.setenv("SCRYE_ALLOW_WEAK_MASTER_KEY", "1")
        with caplog.at_level("WARNING", logger="app.core.crypto"):
            keys = load_master_keys(_write_key_file(tmp_path, "!" * 40))
        assert len(keys[1]) == 40
        assert any("SCRYE_ALLOW_WEAK_MASTER_KEY" in rec.message for rec in caplog.records)

    def test_weak_key_optout_still_enforces_length_floor(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Even with the opt-out, the >= 32-byte floor still applies.
        monkeypatch.setenv("SCRYE_ALLOW_WEAK_MASTER_KEY", "1")
        with pytest.raises(MasterKeyError, match="too short"):
            load_master_keys(_write_key_file(tmp_path, "!" * 10))

    def test_valid_base64_key_still_decrypts_existing_data(self, tmp_path: Path) -> None:
        # INVARIANT (SEC-3 fix must not change at-rest crypto): a fixed, valid
        # base64 key is accepted unchanged and a value encrypted under it still
        # round-trips — the entropy floor is input validation only, not a KDF or
        # format change, so existing ciphertext keeps decrypting.
        fixed_key = base64.b64encode(b"\x11" * 48).decode("ascii")
        cipher_before = SecretCipher(load_master_keys(_write_key_file(tmp_path, fixed_key)))
        token = cipher_before.encrypt("stored-registry-secret", aad="registries.secret")
        # A fresh cipher built from the same key file (as a restart would) decrypts it.
        cipher_after = SecretCipher(load_master_keys(_write_key_file(tmp_path, fixed_key)))
        assert cipher_after.decrypt(token, aad="registries.secret") == "stored-registry-secret"


class TestEncryptDecrypt:
    def test_round_trip(self, cipher: SecretCipher) -> None:
        token = cipher.encrypt("hunter2-registry-password")
        assert cipher.decrypt(token) == "hunter2-registry-password"

    def test_plaintext_not_in_token(self, cipher: SecretCipher) -> None:
        secret = "very-recognizable-plaintext"
        token = cipher.encrypt(secret)
        assert secret not in token
        assert token.startswith("scrye$v1$")

    def test_same_plaintext_yields_unique_tokens(self, cipher: SecretCipher) -> None:
        tokens = {cipher.encrypt("same-value") for _ in range(20)}
        assert len(tokens) == 20  # random per-secret nonce

    def test_tampered_ciphertext_rejected(self, cipher: SecretCipher) -> None:
        token = cipher.encrypt("secret")
        head, _, ct = token.rpartition("$")
        flipped = ("A" if ct[0] != "A" else "B") + ct[1:]
        with pytest.raises(SecretDecryptError, match="authentication"):
            cipher.decrypt(f"{head}${flipped}")

    def test_garbage_token_rejected(self, cipher: SecretCipher) -> None:
        with pytest.raises(SecretDecryptError, match="format"):
            cipher.decrypt("not-a-token")

    def test_aad_binds_context(self, cipher: SecretCipher) -> None:
        token = cipher.encrypt("secret", aad="registries.password")
        assert cipher.decrypt(token, aad="registries.password") == "secret"
        with pytest.raises(SecretDecryptError):
            cipher.decrypt(token, aad="git_credentials.token")
        with pytest.raises(SecretDecryptError):
            cipher.decrypt(token)

    def test_wrong_key_rejected(self, tmp_path: Path, cipher: SecretCipher) -> None:
        other = SecretCipher(load_master_keys(_write_key_file(tmp_path, _random_b64_key())))
        token = cipher.encrypt("secret")
        with pytest.raises(SecretDecryptError):
            other.decrypt(token)

    def test_derivation_is_deterministic(self, tmp_path: Path) -> None:
        key_file = _write_key_file(tmp_path, _random_b64_key())
        cipher_a = SecretCipher(load_master_keys(key_file))
        cipher_b = SecretCipher(load_master_keys(key_file))
        assert cipher_b.decrypt(cipher_a.encrypt("x")) == "x"

    def test_unicode_round_trip(self, cipher: SecretCipher) -> None:
        assert cipher.decrypt(cipher.encrypt("pässwörd-🔑")) == "pässwörd-🔑"


class TestRotation:
    def test_rotate_to_new_version(self, tmp_path: Path) -> None:
        v1 = _random_b64_key()
        old = SecretCipher(load_master_keys(_write_key_file(tmp_path, v1)))
        token_v1 = old.encrypt("rotate-me", aad="ctx")

        new = SecretCipher(
            load_master_keys(_write_key_file(tmp_path, f"v1:{v1}\nv2:{_random_b64_key()}\n"))
        )
        assert new.current_version == 2
        assert new.key_version(token_v1) == 1
        assert new.needs_rotation(token_v1)

        token_v2 = new.rotate(token_v1, aad="ctx")
        assert new.key_version(token_v2) == 2
        assert not new.needs_rotation(token_v2)
        assert new.decrypt(token_v2, aad="ctx") == "rotate-me"

    def test_unknown_version_rejected(self, cipher: SecretCipher) -> None:
        token = cipher.encrypt("x").replace("$v1$", "$v9$", 1)
        with pytest.raises(SecretDecryptError, match="v9"):
            cipher.decrypt(token)
