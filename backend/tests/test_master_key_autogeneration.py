"""Tests for first-launch master-key generation and its safety invariants.

The feature exists so a fresh deployment starts without the operator having to
run ``openssl rand -base64 48`` first. The invariants around it matter far more
than the convenience, because a *second* master key silently orphans every
field-encrypted secret in the database (registry credentials, git tokens, the
OIDC client secret, TOTP seeds, scheduled-backup passphrases):

- a key file that exists is used, never overwritten;
- a key file that exists but cannot be loaded **fails startup** rather than being
  regenerated — generation follows only from a *proven absent* file;
- the configured (Docker secret) path keeps its precedence;
- concurrent starts produce exactly one key.
"""

from __future__ import annotations

import base64
import logging
import os
import stat
import threading
from pathlib import Path

import pytest

from app.core import crypto
from app.core.config import Settings
from app.core.crypto import (
    MasterKeyError,
    SecretCipher,
    resolve_master_keys,
)

_GENERATED_LOG_MARKER = "Generated a new application master key"


def _settings(
    *,
    configured: Path,
    autogen: Path,
    explicit: bool = False,
    autogenerate: bool = True,
) -> Settings:
    """Build a Settings instance with both master-key paths under a tmp dir.

    ``explicit`` models whether an operator named ``SCRYE_APP_SECRET_KEY_FILE``:
    constructor kwargs land in ``model_fields_set`` exactly like an env var would,
    so an implicit (left-at-default) path is modeled by dropping the field from
    that set — the tests cannot use the real default, which is unwritable.
    """
    settings = Settings(
        app_secret_key_file=configured,
        app_secret_key_autogen_file=autogen,
        app_secret_key_autogenerate=autogenerate,
    )
    if not explicit:
        settings.model_fields_set.discard("app_secret_key_file")
    return settings


def _random_b64_key() -> str:
    return base64.b64encode(os.urandom(48)).decode("ascii")


@pytest.fixture(autouse=True)
def _no_weak_key_optout(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prove generated keys clear the entropy floor on their own merits (SEC-3).

    Nothing here may lean on the ``SCRYE_ALLOW_WEAK_MASTER_KEY`` escape hatch.
    """
    monkeypatch.delenv("SCRYE_ALLOW_WEAK_MASTER_KEY", raising=False)


@pytest.fixture
def paths(tmp_path: Path) -> tuple[Path, Path]:
    """Return a (configured, auto-generated) key-path pair, neither existing."""
    return tmp_path / "secret" / "app_secret_key", tmp_path / "data" / "app_secret_key"


class TestFirstLaunchGeneration:
    def test_generates_a_key_on_a_clean_volume(self, paths: tuple[Path, Path]) -> None:
        configured, autogen = paths
        resolution = resolve_master_keys(_settings(configured=configured, autogen=autogen))

        assert resolution.generated is True
        assert resolution.from_configured_path is False
        assert resolution.path == autogen
        assert autogen.is_file()
        assert not configured.exists()  # the Docker-secret path is never written to

    def test_generated_key_clears_the_entropy_floor_without_the_optout(
        self, paths: tuple[Path, Path]
    ) -> None:
        # The documented `openssl rand -base64 48` equivalent: valid base64
        # decoding to 48 bytes, well past the >= 32-byte floor, so the weak-key
        # opt-out (deleted by the autouse fixture) is never needed.
        configured, autogen = paths
        resolution = resolve_master_keys(_settings(configured=configured, autogen=autogen))

        assert set(resolution.keys) == {1}
        assert len(resolution.keys[1]) == 48
        content = autogen.read_text(encoding="utf-8").strip()
        assert base64.b64decode(content, validate=True) == resolution.keys[1]
        # Reloading through the entropy-gated loader must accept it as-is.
        assert crypto.load_master_keys(autogen) == resolution.keys

    def test_generated_keys_are_unique_per_deployment(self, tmp_path: Path) -> None:
        first = resolve_master_keys(
            _settings(configured=tmp_path / "s1", autogen=tmp_path / "d1" / "key")
        )
        second = resolve_master_keys(
            _settings(configured=tmp_path / "s2", autogen=tmp_path / "d2" / "key")
        )
        assert first.keys[1] != second.keys[1]

    def test_generated_file_mode_is_0600(self, paths: tuple[Path, Path]) -> None:
        configured, autogen = paths
        resolve_master_keys(_settings(configured=configured, autogen=autogen))

        mode = stat.S_IMODE(autogen.stat().st_mode)
        assert mode == 0o600, f"master key file is {mode:04o}, not 0600"
        assert not mode & (stat.S_IRGRP | stat.S_IROTH), "key is group/world readable"

    def test_generated_file_is_owned_by_this_process(self, paths: tuple[Path, Path]) -> None:
        configured, autogen = paths
        resolve_master_keys(_settings(configured=configured, autogen=autogen))
        assert autogen.stat().st_uid == os.geteuid()

    def test_generation_logs_the_backup_warning_once_at_info(
        self, paths: tuple[Path, Path], caplog: pytest.LogCaptureFixture
    ) -> None:
        # Losing this file is the single most important operational fact about it,
        # so the notice has to be in the startup log — once, at INFO.
        configured, autogen = paths
        with caplog.at_level(logging.INFO, logger="app.core.crypto"):
            resolve_master_keys(_settings(configured=configured, autogen=autogen))

        generated = [rec for rec in caplog.records if _GENERATED_LOG_MARKER in rec.getMessage()]
        assert len(generated) == 1
        message = generated[0].getMessage()
        assert generated[0].levelno == logging.INFO
        assert str(autogen) in message
        assert "BACK THIS FILE UP" in message
        assert "UNRECOVERABLE" in message

    def test_parent_directory_is_created(self, tmp_path: Path) -> None:
        autogen = tmp_path / "data" / "nested" / "app_secret_key"
        resolve_master_keys(_settings(configured=tmp_path / "secret", autogen=autogen))
        assert autogen.is_file()

    def test_generation_is_refused_when_disabled(self, paths: tuple[Path, Path]) -> None:
        configured, autogen = paths
        with pytest.raises(MasterKeyError, match="AUTOGENERATE is off"):
            resolve_master_keys(
                _settings(configured=configured, autogen=autogen, autogenerate=False)
            )
        assert not autogen.exists()

    def test_unwritable_target_fails_loudly(self, tmp_path: Path, monkeypatch) -> None:
        # A read-only volume must surface as a startup error, not a silent
        # in-memory key that would encrypt secrets nothing can ever decrypt.
        def _refuse(*args: object, **kwargs: object) -> None:
            raise PermissionError("read-only file system")

        monkeypatch.setattr(crypto.os, "open", _refuse)
        with pytest.raises(MasterKeyError, match="Cannot create the master key file"):
            resolve_master_keys(
                _settings(configured=tmp_path / "secret", autogen=tmp_path / "data" / "key")
            )


class TestExistingKeyIsNeverReplaced:
    def test_existing_generated_key_is_reused_verbatim(self, paths: tuple[Path, Path]) -> None:
        configured, autogen = paths
        autogen.parent.mkdir(parents=True)
        existing = _random_b64_key()
        autogen.write_text(f"{existing}\n", encoding="utf-8")

        resolution = resolve_master_keys(_settings(configured=configured, autogen=autogen))

        assert resolution.generated is False
        assert resolution.path == autogen
        assert resolution.keys[1] == base64.b64decode(existing, validate=True)
        assert autogen.read_text(encoding="utf-8") == f"{existing}\n"

    def test_repeated_resolution_never_regenerates(self, paths: tuple[Path, Path]) -> None:
        configured, autogen = paths
        settings = _settings(configured=configured, autogen=autogen)
        first = resolve_master_keys(settings)
        content = autogen.read_bytes()

        second = resolve_master_keys(settings)

        assert second.generated is False
        assert second.keys == first.keys
        assert autogen.read_bytes() == content

    def test_configured_secret_file_still_takes_precedence(self, paths: tuple[Path, Path]) -> None:
        configured, autogen = paths
        configured.parent.mkdir(parents=True)
        configured.write_text(_random_b64_key(), encoding="utf-8")

        resolution = resolve_master_keys(
            _settings(configured=configured, autogen=autogen, explicit=True)
        )

        assert resolution.from_configured_path is True
        assert resolution.path == configured
        assert resolution.generated is False
        assert not autogen.exists(), "no key may be generated while a secret is provided"

    @pytest.mark.parametrize(
        ("content", "match"),
        [
            ("", "empty"),
            ("   \n", "empty"),
            ("correct horse battery staple pw!", "not valid base64"),
            (base64.b64encode(b"\x01" * 16).decode("ascii"), "too short"),
            (base64.b64encode(b"\x02" * 48).decode("ascii") + "\nnot-a-key-line\n", "malformed"),
        ],
        ids=["empty", "whitespace", "passphrase", "too-short", "malformed"],
    )
    def test_malformed_existing_key_fails_startup_instead_of_regenerating(
        self, paths: tuple[Path, Path], content: str, match: str
    ) -> None:
        # THE cardinal invariant: a key file that exists but does not load is a
        # hard stop. Regenerating here would orphan every stored secret.
        configured, autogen = paths
        autogen.parent.mkdir(parents=True)
        autogen.write_text(content, encoding="utf-8")

        with pytest.raises(MasterKeyError, match=match):
            resolve_master_keys(_settings(configured=configured, autogen=autogen))

        assert autogen.read_text(encoding="utf-8") == content, "existing key file was modified"

    def test_unreadable_existing_key_fails_startup(self, paths: tuple[Path, Path]) -> None:
        # A directory where the key file belongs stands in for any read failure
        # (and, unlike chmod 000, behaves the same when tests run as root).
        configured, autogen = paths
        autogen.mkdir(parents=True)

        with pytest.raises(MasterKeyError, match="could not be read"):
            resolve_master_keys(_settings(configured=configured, autogen=autogen))

        assert autogen.is_dir()

    def test_undeterminable_presence_fails_startup(
        self, paths: tuple[Path, Path], monkeypatch
    ) -> None:
        # Absence must be *proven*. If stat fails for any reason other than "not
        # there", treating it as absence would generate a second key.
        configured, autogen = paths
        real_stat = crypto.os.stat

        def _stat(path: object, *args: object, **kwargs: object) -> os.stat_result:
            if str(path) == str(autogen):
                raise PermissionError(13, "Permission denied")
            return real_stat(path, *args, **kwargs)

        monkeypatch.setattr(crypto.os, "stat", _stat)
        with pytest.raises(MasterKeyError, match="Cannot determine whether"):
            resolve_master_keys(_settings(configured=configured, autogen=autogen))
        assert not autogen.exists()

    def test_explicitly_configured_but_missing_key_refuses_to_start(
        self, paths: tuple[Path, Path]
    ) -> None:
        # An operator-set path asserts the key lives there. A missing file means an
        # unmounted secret, not a fresh install — generating one would orphan the
        # secrets encrypted under the real key.
        configured, autogen = paths
        with pytest.raises(MasterKeyError, match="SCRYE_APP_SECRET_KEY_FILE is set to"):
            resolve_master_keys(_settings(configured=configured, autogen=autogen, explicit=True))
        assert not autogen.exists()

    def test_implicit_configured_path_falls_through_to_generation(
        self, paths: tuple[Path, Path]
    ) -> None:
        configured, autogen = paths
        resolution = resolve_master_keys(
            _settings(configured=configured, autogen=autogen, explicit=False)
        )
        assert resolution.generated is True
        assert resolution.path == autogen


class TestBothKeyFilesPresent:
    """The two-key interlock: precedence must not silently orphan ciphertext."""

    def test_unrelated_generated_key_alongside_a_secret_refuses_to_start(
        self, paths: tuple[Path, Path]
    ) -> None:
        configured, autogen = paths
        configured.parent.mkdir(parents=True)
        configured.write_text(_random_b64_key(), encoding="utf-8")
        autogen.parent.mkdir(parents=True)
        autogen.write_text(_random_b64_key(), encoding="utf-8")

        with pytest.raises(MasterKeyError, match="Two different master keys are present"):
            resolve_master_keys(_settings(configured=configured, autogen=autogen, explicit=True))

    def test_same_material_under_a_different_version_still_refuses(
        self, paths: tuple[Path, Path]
    ) -> None:
        # Tokens name their key *version*, so the generated key being present under
        # some other version number would not be found at decrypt time.
        configured, autogen = paths
        generated_key = _random_b64_key()
        autogen.parent.mkdir(parents=True)
        autogen.write_text(generated_key, encoding="utf-8")  # version 1
        configured.parent.mkdir(parents=True)
        configured.write_text(f"v2:{generated_key}\n", encoding="utf-8")

        with pytest.raises(MasterKeyError, match="v1 key material is not in"):
            resolve_master_keys(_settings(configured=configured, autogen=autogen, explicit=True))

    def test_generated_key_carried_forward_as_a_version_is_accepted(
        self, paths: tuple[Path, Path]
    ) -> None:
        # The documented migration: keep the auto-generated key as the version it
        # was written under and add the new one, so old blobs still decrypt.
        configured, autogen = paths
        generated_key = _random_b64_key()
        autogen.parent.mkdir(parents=True)
        autogen.write_text(generated_key, encoding="utf-8")
        old_cipher = SecretCipher(crypto.load_master_keys(autogen))
        token = old_cipher.encrypt("registry-password", aad="registries.secret")

        configured.parent.mkdir(parents=True)
        configured.write_text(f"v1:{generated_key}\nv2:{_random_b64_key()}\n", encoding="utf-8")
        resolution = resolve_master_keys(
            _settings(configured=configured, autogen=autogen, explicit=True)
        )

        assert resolution.path == configured
        cipher = SecretCipher(resolution.keys)
        assert cipher.current_version == 2
        assert cipher.decrypt(token, aad="registries.secret") == "registry-password"

    def test_unloadable_generated_key_alongside_a_secret_refuses_to_start(
        self, paths: tuple[Path, Path]
    ) -> None:
        # It may hold the key this database's secrets were written under; it is not
        # ours to ignore.
        configured, autogen = paths
        configured.parent.mkdir(parents=True)
        configured.write_text(_random_b64_key(), encoding="utf-8")
        autogen.parent.mkdir(parents=True)
        autogen.write_text("corrupted-not-base64!!", encoding="utf-8")

        with pytest.raises(MasterKeyError, match="could not be read"):
            resolve_master_keys(_settings(configured=configured, autogen=autogen, explicit=True))

    def test_identical_paths_do_not_trip_the_interlock(self, tmp_path: Path) -> None:
        shared = tmp_path / "app_secret_key"
        shared.write_text(_random_b64_key(), encoding="utf-8")
        resolution = resolve_master_keys(
            _settings(configured=shared, autogen=shared, explicit=True)
        )
        assert resolution.path == shared


class TestConcurrentStartup:
    def test_simultaneous_starts_produce_exactly_one_key(
        self, paths: tuple[Path, Path], caplog: pytest.LogCaptureFixture
    ) -> None:
        configured, autogen = paths
        settings = _settings(configured=configured, autogen=autogen)
        workers = 8
        barrier = threading.Barrier(workers)
        results: list[crypto.MasterKeyResolution] = []
        failures: list[BaseException] = []
        lock = threading.Lock()

        def _start() -> None:
            barrier.wait()
            try:
                resolution = resolve_master_keys(settings)
            except BaseException as exc:  # noqa: BLE001 - recorded and asserted below
                with lock:
                    failures.append(exc)
                return
            with lock:
                results.append(resolution)

        with caplog.at_level(logging.INFO, logger="app.core.crypto"):
            threads = [threading.Thread(target=_start) for _ in range(workers)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

        assert not failures, f"concurrent startup failed: {failures!r}"
        assert len(results) == workers
        # Exactly one generator, and every other worker adopted its key.
        assert sum(1 for res in results if res.generated) == 1
        assert {res.keys[1] for res in results} == {results[0].keys[1]}
        notices = [rec for rec in caplog.records if _GENERATED_LOG_MARKER in rec.getMessage()]
        assert len(notices) == 1
        assert crypto.load_master_keys(autogen)[1] == results[0].keys[1]

    def test_race_loser_waits_for_the_winners_content(self, tmp_path: Path) -> None:
        # The winner can hold an empty file for an instant between O_CREAT and its
        # write; the loser must wait it out rather than fail (or generate).
        key_file = tmp_path / "app_secret_key"
        key_file.touch()
        material = _random_b64_key()

        def _finish_writing() -> None:
            key_file.write_text(f"{material}\n", encoding="utf-8")

        timer = threading.Timer(0.25, _finish_writing)
        timer.start()
        try:
            keys = crypto._load_key_file(key_file)
        finally:
            timer.cancel()
        assert keys[1] == base64.b64decode(material, validate=True)

    def test_race_loser_gives_up_loudly_rather_than_generating(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.setattr(crypto, "_RACE_READ_ATTEMPTS", 2)
        monkeypatch.setattr(crypto, "_RACE_READ_DELAY_SECONDS", 0.01)
        key_file = tmp_path / "app_secret_key"
        key_file.touch()

        with pytest.raises(MasterKeyError, match="stayed empty"):
            crypto._load_key_file(key_file)

    def test_a_malformed_key_is_not_waited_on(self, tmp_path: Path, monkeypatch) -> None:
        # Content is present and does not load: that is a real fault, so it must
        # surface at once rather than after the concurrent-write grace period.
        monkeypatch.setattr(crypto, "_RACE_READ_DELAY_SECONDS", 30.0)
        key_file = tmp_path / "app_secret_key"
        key_file.write_text("not-base64-at-all!!", encoding="utf-8")

        with pytest.raises(MasterKeyError, match="not valid base64"):
            crypto._load_key_file(key_file)


class TestPermissionVerification:
    def test_wrong_mode_is_rejected(self, tmp_path: Path) -> None:
        key_file = tmp_path / "app_secret_key"
        key_file.write_text(_random_b64_key(), encoding="utf-8")
        key_file.chmod(0o644)

        with pytest.raises(MasterKeyError, match="has mode 0644"):
            crypto._verify_key_file_permissions(key_file)

    def test_correct_mode_passes(self, tmp_path: Path) -> None:
        key_file = tmp_path / "app_secret_key"
        key_file.write_text(_random_b64_key(), encoding="utf-8")
        key_file.chmod(0o600)
        crypto._verify_key_file_permissions(key_file)  # must not raise

    def test_synthesized_ownership_is_rejected_with_an_actionable_message(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        # A filesystem that reports a foreign owner for a file this process just
        # created (CIFS/SMB `uid=`, NFS squashing) is faking POSIX ownership, so the
        # key's 0600 does not actually protect it. On a normal filesystem this can't
        # happen — a new file always belongs to the creating euid — so the reported
        # owner is stubbed here.
        key_file = tmp_path / "app_secret_key"
        key_file.write_text(_random_b64_key(), encoding="utf-8")
        key_file.chmod(0o600)
        real_stat = crypto.os.stat
        foreign_uid = os.geteuid() + 26

        def _stat(path: object, *args: object, **kwargs: object) -> os.stat_result:
            info = real_stat(path, *args, **kwargs)
            if str(path) == str(key_file):
                fields = list(info)
                fields[4] = foreign_uid  # st_uid
                return os.stat_result(fields)
            return info

        monkeypatch.setattr(crypto.os, "stat", _stat)
        with pytest.raises(MasterKeyError) as excinfo:
            crypto._verify_key_file_permissions(key_file)

        message = str(excinfo.value)
        assert f"owned by uid {foreign_uid}" in message
        assert f"container uid {os.geteuid()}" in message
        # The fix differs from the unwritable-directory case, and saying so matters:
        # chown cannot help when the filesystem synthesizes the owner.
        assert "chown` on the host will not help" in message
        assert f"run the container as uid {foreign_uid}" in message

    def test_unwritable_data_directory_names_the_uid_and_the_fix(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        # The common NAS misconfiguration (a bind mount whose ownership doesn't match
        # the container uid). The message is all the operator gets, so it must carry
        # the directory, the uid:gid, and a literal chown.
        autogen = tmp_path / "data" / "app_secret_key"

        def _refuse(*args: object, **kwargs: object) -> None:
            raise PermissionError(13, "Permission denied")

        monkeypatch.setattr(crypto.os, "open", _refuse)
        with pytest.raises(MasterKeyError) as excinfo:
            resolve_master_keys(_settings(configured=tmp_path / "secret", autogen=autogen))

        message = str(excinfo.value)
        assert str(autogen.parent) in message
        assert f"({os.geteuid()}:{os.getegid()})" in message
        assert f"chown -R {os.geteuid()}:{os.getegid()} <host path>" in message
        assert "user:" in message
        assert "SCRYE_APP_SECRET_KEY_FILE" in message

    def test_a_key_that_fails_verification_is_not_left_behind(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        # Otherwise the next start would silently adopt the very file this start
        # refused. Only the creating call may delete it, before anything uses it.
        autogen = tmp_path / "data" / "app_secret_key"

        def _reject(path: Path) -> None:
            raise MasterKeyError(f"simulated permission mismatch on {path}")

        monkeypatch.setattr(crypto, "_verify_key_file_permissions", _reject)
        with pytest.raises(MasterKeyError, match="simulated permission mismatch"):
            resolve_master_keys(_settings(configured=tmp_path / "secret", autogen=autogen))
        assert not autogen.exists()


class TestGeneratedKeySurvivesRestart:
    def test_secrets_still_decrypt_after_a_restart(self, paths: tuple[Path, Path]) -> None:
        # A restart re-resolves from disk. The key must be the same one, so data
        # encrypted before the restart still decrypts after it.
        configured, autogen = paths
        settings = _settings(configured=configured, autogen=autogen)

        first_boot = resolve_master_keys(settings)
        token = SecretCipher(first_boot.keys).encrypt("git-token", aad="git_credentials.token")

        second_boot = resolve_master_keys(settings)

        assert second_boot.generated is False
        assert second_boot.keys == first_boot.keys
        assert (
            SecretCipher(second_boot.keys).decrypt(token, aad="git_credentials.token")
            == "git-token"
        )

    def test_process_cache_reset_re_reads_the_same_key(
        self, paths: tuple[Path, Path], monkeypatch
    ) -> None:
        # get_secret_cipher()/get_master_key_resolution() are process-cached; the
        # reset used by tests and rotation flows must land on the same key file.
        configured, autogen = paths
        monkeypatch.setattr(
            crypto,
            "get_settings",
            lambda: _settings(configured=configured, autogen=autogen),
        )
        crypto.reset_secret_cipher()
        try:
            token = crypto.get_secret_cipher().encrypt("oidc-client-secret")
            assert crypto.get_master_key_resolution().path == autogen
            crypto.reset_secret_cipher()
            assert crypto.get_master_key_resolution().generated is False
            assert crypto.get_secret_cipher().decrypt(token) == "oidc-client-secret"
        finally:
            crypto.reset_secret_cipher()
