"""Tests for the backup passphrase KDF (docs/PLAN.md §8).

These lock in the scrypt work factor and confirm the derived key drives a
working AES-256-GCM round-trip, so a regression that weakens the parameters (or
breaks derivation) fails loudly.
"""

from __future__ import annotations

import pytest

from app.core import passphrase
from app.core.passphrase import (
    SCRYPT_N,
    SCRYPT_P,
    SCRYPT_R,
    PassphraseKdfError,
    derive_key,
    new_salt,
    passphrase_cipher,
)

PASSPHRASE = "correct-horse-battery-staple"


class TestScryptParameters:
    def test_work_factor_meets_owasp_floor(self) -> None:
        # N=2**17, r=8, p=1 is the current OWASP scrypt recommendation.
        assert SCRYPT_N == 2**17
        assert SCRYPT_R == 8
        assert SCRYPT_P == 1

    def test_memory_cost_is_about_128_mib(self) -> None:
        # scrypt memory use is 128 * N * r bytes; with N=2**17, r=8 that is 128 MiB.
        memory_bytes = 128 * SCRYPT_N * SCRYPT_R
        assert memory_bytes == 128 * 1024 * 1024

    def test_maxmem_headroom_permits_derivation(self) -> None:
        # A regression that lowered maxmem below 128*N*r would make derive_key
        # raise; a successful derivation proves the configured maxmem is enough.
        assert len(derive_key(PASSPHRASE, new_salt())) == 32


class TestDerivation:
    def test_key_is_32_bytes(self) -> None:
        assert len(derive_key(PASSPHRASE, new_salt())) == 32

    def test_same_inputs_are_deterministic(self) -> None:
        salt = new_salt()
        assert derive_key(PASSPHRASE, salt) == derive_key(PASSPHRASE, salt)

    def test_salt_diversifies_the_key(self) -> None:
        assert derive_key(PASSPHRASE, new_salt()) != derive_key(PASSPHRASE, new_salt())

    def test_empty_passphrase_is_rejected(self) -> None:
        with pytest.raises(PassphraseKdfError):
            derive_key("", new_salt())

    def test_cipher_round_trips_under_the_derived_key(self) -> None:
        salt = new_salt()
        cipher = passphrase_cipher(PASSPHRASE, salt)
        token = cipher.encrypt("s3cr3t", aad=passphrase.AAD_BUNDLE)
        assert cipher.decrypt(token, aad=passphrase.AAD_BUNDLE) == "s3cr3t"


class TestParameterizedDerivation:
    """Item (g): derivation must honor explicit scrypt params so a restore can
    reproduce a key made under a different (e.g. older) work factor."""

    def test_explicit_low_params_reproduce_and_differ_from_default(self) -> None:
        salt = new_salt()
        low = derive_key(PASSPHRASE, salt, n=2**14, r=8, p=1)
        # Same low params reproduce the key (the restore path)...
        assert derive_key(PASSPHRASE, salt, n=2**14, r=8, p=1) == low
        # ...while the current default work factor yields a different key.
        assert derive_key(PASSPHRASE, salt) != low

    def test_invalid_params_rejected(self) -> None:
        salt = new_salt()
        for bad in ({"n": 3}, {"n": 0}, {"r": 0}, {"p": 0}):
            with pytest.raises(PassphraseKdfError):
                derive_key(PASSPHRASE, salt, **bad)

    def test_parameter_bombs_rejected_before_derivation(self) -> None:
        """SEC-2: restore-supplied params are untrusted; absurd cost factors must
        be rejected up front rather than handed to scrypt with a matching
        ``maxmem`` (which is what used to make the guard self-defeating)."""
        salt = new_salt()
        for bomb in (
            {"n": 2**30},  # ~128 GiB
            {"n": 2**21},  # just past the ceiling
            {"r": 17},
            {"p": 5},
            {"n": 2**20, "r": 16},  # within per-parameter caps, over the memory budget
        ):
            with pytest.raises(PassphraseKdfError):
                derive_key(PASSPHRASE, salt, **bomb)

    def test_default_parameters_stay_within_the_clamps(self) -> None:
        # Guards the guard: if the module defaults are ever raised past the
        # ceilings, every legitimate backup would stop restoring.
        assert len(derive_key(PASSPHRASE, new_salt(), n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)) == 32

    def test_cipher_round_trip_under_low_params(self) -> None:
        salt = new_salt()
        cipher = passphrase_cipher(PASSPHRASE, salt, n=2**14, r=8, p=1)
        token = cipher.encrypt("secret", aad="x")
        # Re-deriving under the same recorded params decrypts it.
        assert (
            passphrase_cipher(PASSPHRASE, salt, n=2**14, r=8, p=1).decrypt(token, aad="x")
            == "secret"
        )
