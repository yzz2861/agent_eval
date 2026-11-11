import subprocess
import sys
import threading
import time

import pytest

from pwdlib import (
    CorruptedHashHandling,
    MigrationFailureReason,
    MigrationResult,
    MigrationStatus,
    PasswordHash,
    PasswordMigrationPolicy,
    exceptions,
)
from pwdlib.hashers.argon2 import Argon2Hasher
from pwdlib.hashers.bcrypt import BcryptHasher

_PASSWORD = "herminetincture"

_ARGON2_HASHER = Argon2Hasher()
_ARGON2_HASH_STR = _ARGON2_HASHER.hash(_PASSWORD)

_BCRYPT_HASHER = BcryptHasher()
_BCRYPT_HASH_STR = _BCRYPT_HASHER.hash(_PASSWORD)

# Recognized algorithm prefix, corrupted content (truncated or bad params).
_TRUNCATED_ARGON2_HASH = "$argon2id$v=19$m=65536,t=3,p=4"
_MALFORMED_ARGON2_HASH = (
    "$argon2id$v=A&$m==,p=$c29tZXNhbHQ$arQWpIVsXmUQDj660XNQBCR3AeZaVN7ChRcM97sGDK4"
)
_TRUNCATED_BCRYPT_HASH = "$2b$12$" + "C" * 20
_UNKNOWN_HASH = "INVALID_HASH"


@pytest.fixture
def password_hash() -> PasswordHash:
    return PasswordHash((Argon2Hasher(), BcryptHasher()))


def test_recommended() -> None:
    password_hash = PasswordHash.recommended()
    assert len(password_hash.hashers) == 1
    assert isinstance(password_hash.current_hasher, Argon2Hasher)


def test_hash(password_hash: PasswordHash) -> None:
    hash = password_hash.hash("herminetincture")
    assert isinstance(hash, str)
    assert password_hash.current_hasher.identify(hash)


@pytest.mark.parametrize(
    "hash,password,result",
    [
        (_ARGON2_HASH_STR, _PASSWORD, True),
        (_ARGON2_HASH_STR, "INVALID_PASSWORD", False),
        (_BCRYPT_HASH_STR, _PASSWORD, True),
        (_BCRYPT_HASH_STR, "INVALID_PASSWORD", False),
    ],
)
def test_verify(
    hash: str | bytes,
    password: str,
    result: bool,
    password_hash: PasswordHash,
) -> None:
    assert password_hash.verify(password, hash) == result


def test_verify_unknown_hash(password_hash: PasswordHash) -> None:
    with pytest.raises(exceptions.UnknownHashError):
        password_hash.verify("INVALID_HASH", _PASSWORD)


@pytest.mark.parametrize(
    "hash,password,result,has_updated_hash",
    [
        (_ARGON2_HASH_STR, _PASSWORD, True, False),
        (_ARGON2_HASH_STR, "INVALID_PASSWORD", False, False),
        (_BCRYPT_HASH_STR, _PASSWORD, True, True),
        (_BCRYPT_HASH_STR, "INVALID_PASSWORD", False, False),
    ],
)
def test_verify_and_update(
    hash: str | bytes,
    password: str,
    result: bool,
    has_updated_hash: bool,
    password_hash: PasswordHash,
) -> None:
    valid, updated_hash = password_hash.verify_and_update(password, hash)
    assert valid == result
    assert updated_hash is not None if has_updated_hash else updated_hash is None
    if updated_hash is not None:
        assert password_hash.current_hasher.identify(updated_hash)


def test_verify_and_update_unknown_hash(password_hash: PasswordHash) -> None:
    with pytest.raises(exceptions.UnknownHashError):
        password_hash.verify_and_update(_PASSWORD, "INVALID_HASH")


@pytest.mark.parametrize(
    "invalid_value",
    [
        pytest.param(123, id="int"),
        pytest.param(None, id="None"),
        pytest.param([], id="list"),
        pytest.param({}, id="dict"),
    ],
)
def test_invalid_type(invalid_value: object, password_hash: PasswordHash) -> None:
    with pytest.raises(TypeError, match="password must be str or bytes"):
        password_hash.hash(invalid_value)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="password must be str or bytes"):
        password_hash.verify(invalid_value, _ARGON2_HASH_STR)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="hash must be str or bytes"):
        password_hash.verify(_PASSWORD, invalid_value)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="password must be str or bytes"):
        password_hash.verify_and_update(invalid_value, _ARGON2_HASH_STR)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="hash must be str or bytes"):
        password_hash.verify_and_update(_PASSWORD, invalid_value)  # type: ignore[arg-type]


class InMemoryHashStore:
    """Test double for the PasswordHashStore storage boundary."""

    def __init__(self, hash: str) -> None:
        self._hash = hash
        self.update_calls = 0

    def load_hash(self, old_hash: str) -> str | None:
        return self._hash

    def update_hash(self, old_hash: str, new_hash: str) -> None:
        self.update_calls += 1
        self._hash = new_hash


class BlockingHashStore(InMemoryHashStore):
    """Store whose first update blocks until the test releases it."""

    def __init__(self, hash: str) -> None:
        super().__init__(hash)
        self.barrier = threading.Barrier(2)
        self.update_started = threading.Event()
        self.release_update = threading.Event()

    def update_hash(self, old_hash: str, new_hash: str) -> None:
        self.update_started.set()
        if self.update_calls == 0:
            self.release_update.wait(5)
        super().update_hash(old_hash, new_hash)


class FailingHashStore(InMemoryHashStore):
    def update_hash(self, old_hash: str, new_hash: str) -> None:
        raise RuntimeError


@pytest.fixture
def migration_policy(password_hash: PasswordHash) -> PasswordMigrationPolicy:
    return PasswordMigrationPolicy(password_hash)


def test_migration_bcrypt_success_upgrade(
    migration_policy: PasswordMigrationPolicy,
) -> None:
    store = InMemoryHashStore(_BCRYPT_HASH_STR)

    result = migration_policy.verify_and_migrate(_PASSWORD, _BCRYPT_HASH_STR, store)

    assert result.authenticated is True
    assert result.upgraded is True
    assert result.status is MigrationStatus.UPGRADED
    assert result.failure_reason is MigrationFailureReason.NONE
    assert result.algorithm == Argon2Hasher.algorithm
    assert result.final_hash is not None
    assert Argon2Hasher().identify(result.final_hash)
    assert store.update_calls == 1
    assert store.load_hash(_BCRYPT_HASH_STR) == result.final_hash


def test_migration_argon2_passes_without_upgrade(
    migration_policy: PasswordMigrationPolicy,
) -> None:
    store = InMemoryHashStore(_ARGON2_HASH_STR)

    result = migration_policy.verify_and_migrate(_PASSWORD, _ARGON2_HASH_STR, store)

    assert result.authenticated is True
    assert result.upgraded is False
    assert result.status is MigrationStatus.SUCCESS
    assert result.failure_reason is MigrationFailureReason.NONE
    assert result.algorithm == Argon2Hasher.algorithm
    assert result.final_hash == _ARGON2_HASH_STR
    assert store.update_calls == 0


@pytest.mark.parametrize(
    "corrupted_hash,algorithm",
    [
        (_TRUNCATED_ARGON2_HASH, Argon2Hasher.algorithm),
        (_MALFORMED_ARGON2_HASH, Argon2Hasher.algorithm),
        (_TRUNCATED_BCRYPT_HASH, BcryptHasher.algorithm),
    ],
)
def test_migration_corrupted_hash_is_distinct_from_bad_password(
    migration_policy: PasswordMigrationPolicy,
    corrupted_hash: str,
    algorithm: str,
) -> None:
    store = InMemoryHashStore(corrupted_hash)

    result = migration_policy.verify_and_migrate(_PASSWORD, corrupted_hash, store)

    assert result.authenticated is False
    assert result.upgraded is False
    assert result.status is MigrationStatus.CORRUPTED_HASH
    assert result.failure_reason is MigrationFailureReason.CORRUPTED_HASH
    assert result.algorithm == algorithm
    assert store.update_calls == 0


def test_migration_corrupted_hash_can_raise(
    password_hash: PasswordHash,
) -> None:
    policy = PasswordMigrationPolicy(
        password_hash,
        corrupted_hash_handling=CorruptedHashHandling.RAISE,
    )

    with pytest.raises(exceptions.CorruptedHashError) as exc_info:
        policy.verify_and_migrate(
            _PASSWORD, _TRUNCATED_ARGON2_HASH, InMemoryHashStore("")
        )

    assert exc_info.value.algorithm == Argon2Hasher.algorithm


def test_migration_unknown_prefix_still_raises(
    migration_policy: PasswordMigrationPolicy,
) -> None:
    with pytest.raises(exceptions.UnknownHashError):
        migration_policy.verify_and_migrate(
            _PASSWORD, _UNKNOWN_HASH, InMemoryHashStore("")
        )


def test_migration_wrong_password(
    migration_policy: PasswordMigrationPolicy,
) -> None:
    store = InMemoryHashStore(_BCRYPT_HASH_STR)

    result = migration_policy.verify_and_migrate(
        "INVALID_PASSWORD", _BCRYPT_HASH_STR, store
    )

    assert result.authenticated is False
    assert result.upgraded is False
    assert result.status is MigrationStatus.INVALID_PASSWORD
    assert result.failure_reason is MigrationFailureReason.INVALID_PASSWORD
    assert result.algorithm == BcryptHasher.algorithm
    assert result.final_hash == _BCRYPT_HASH_STR
    assert store.update_calls == 0


def test_migration_concurrent_requests_commit_once(
    migration_policy: PasswordMigrationPolicy,
) -> None:
    store = BlockingHashStore(_BCRYPT_HASH_STR)
    results: list[MigrationResult] = []

    def worker() -> None:
        store.barrier.wait()
        results.append(
            migration_policy.verify_and_migrate(_PASSWORD, _BCRYPT_HASH_STR, store)
        )

    thread_1 = threading.Thread(target=worker)
    thread_2 = threading.Thread(target=worker)
    thread_1.start()
    thread_2.start()

    assert store.update_started.wait(5)
    store.release_update.set()
    thread_1.join(5)
    thread_2.join(5)

    assert store.update_calls == 1
    statuses = {result.status for result in results}
    assert statuses == {
        MigrationStatus.UPGRADED,
        MigrationStatus.ALREADY_MIGRATED,
    }
    assert all(result.authenticated for result in results)
    final_hashes = {result.final_hash for result in results}
    assert final_hashes == {store.load_hash(_BCRYPT_HASH_STR)}


def test_migration_storage_error_keeps_authentication(
    migration_policy: PasswordMigrationPolicy,
) -> None:
    result = migration_policy.verify_and_migrate(
        _PASSWORD, _BCRYPT_HASH_STR, FailingHashStore(_BCRYPT_HASH_STR)
    )

    assert result.authenticated is True
    assert result.upgraded is False
    assert result.status is MigrationStatus.STORAGE_ERROR
    assert result.failure_reason is MigrationFailureReason.STORAGE_ERROR
    assert isinstance(result.error, RuntimeError)
    assert Argon2Hasher().identify(result.final_hash)


def test_migration_repeated_call_does_not_upgrade_twice(
    migration_policy: PasswordMigrationPolicy,
) -> None:
    store = InMemoryHashStore(_BCRYPT_HASH_STR)

    first = migration_policy.verify_and_migrate(_PASSWORD, _BCRYPT_HASH_STR, store)
    assert first.status is MigrationStatus.UPGRADED

    upgraded_hash = store.load_hash(_BCRYPT_HASH_STR)
    assert upgraded_hash is not None
    second = migration_policy.verify_and_migrate(_PASSWORD, upgraded_hash, store)

    assert second.authenticated is True
    assert second.upgraded is False
    assert second.status is MigrationStatus.SUCCESS
    assert second.final_hash == upgraded_hash
    assert store.update_calls == 1


def test_migration_min_verification_time(password_hash: PasswordHash) -> None:
    policy = PasswordMigrationPolicy(password_hash, min_verification_time=0.2)
    started_at = time.perf_counter()

    policy.verify_and_migrate(
        "INVALID_PASSWORD", _BCRYPT_HASH_STR, InMemoryHashStore(_BCRYPT_HASH_STR)
    )

    assert time.perf_counter() - started_at >= 0.19


def test_migration_upgrade_can_be_disabled(password_hash: PasswordHash) -> None:
    policy = PasswordMigrationPolicy(password_hash, upgrade_on_success=False)
    store = InMemoryHashStore(_BCRYPT_HASH_STR)

    result = policy.verify_and_migrate(_PASSWORD, _BCRYPT_HASH_STR, store)

    assert result.authenticated is True
    assert result.upgraded is False
    assert result.status is MigrationStatus.SUCCESS
    assert result.final_hash == _BCRYPT_HASH_STR
    assert store.update_calls == 0


@pytest.mark.parametrize("hasher_name", ["argon2", "bcrypt"])
def test_missing_optional_dependency_raises_hasher_not_available(
    hasher_name: str,
) -> None:
    code = (
        f"import sys\n"
        f"sys.modules['{hasher_name}'] = None\n"
        f"import importlib\n"
        f"try:\n"
        f"    importlib.import_module('pwdlib.hashers.{hasher_name}')\n"
        f"except Exception as exc:\n"
        f"    print(type(exc).__name__)\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code],
        check=True,
        capture_output=True,
        text=True,
    )
    assert completed.stdout.strip() == "HasherNotAvailable"


def test_migration_accepts_plain_callables(password_hash: PasswordHash) -> None:
    policy = PasswordMigrationPolicy(password_hash)
    stored = {"hash": _BCRYPT_HASH_STR}
    updates: list[tuple[str, str]] = []

    def update_hash(old_hash: str, new_hash: str) -> None:
        updates.append((old_hash, new_hash))
        stored["hash"] = new_hash

    def load_hash(old_hash: str) -> str | None:
        return stored["hash"]

    result = policy.verify_and_migrate(
        _PASSWORD,
        _BCRYPT_HASH_STR,
        update_hash,
        load=load_hash,
    )

    assert result.status is MigrationStatus.UPGRADED
    assert updates == [(_BCRYPT_HASH_STR, result.final_hash)]
    assert stored["hash"] == result.final_hash


def test_migration_invalid_options(password_hash: PasswordHash) -> None:
    with pytest.raises(ValueError, match="min_verification_time"):
        PasswordMigrationPolicy(password_hash, min_verification_time=-1)

    with pytest.raises(TypeError, match="corrupted_hash_handling"):
        PasswordMigrationPolicy(
            password_hash,
            corrupted_hash_handling="raise",  # type: ignore[arg-type]
        )

    with pytest.raises(ValueError, match="legacy_hashers"):
        PasswordMigrationPolicy(
            password_hash,
            legacy_hashers=(object(),),  # type: ignore[arg-type]
        )


def test_migration_explicit_legacy_allowlist(password_hash: PasswordHash) -> None:
    policy = PasswordMigrationPolicy(password_hash, legacy_hashers=(BcryptHasher(),))
    assert [hasher.algorithm for hasher in policy.legacy_hashers] == ["bcrypt"]


def test_migration_failing_eq_falls_back_to_identity(
    password_hash: PasswordHash,
) -> None:
    class BrokenHasher:
        algorithm = "broken"

        def __eq__(self, other: object) -> bool:
            raise RuntimeError("boom")

    policy = PasswordMigrationPolicy(password_hash)
    assert policy._is_target_hasher(password_hash.current_hasher) is True
    assert policy._is_target_hasher(BrokenHasher()) is False  # type: ignore[arg-type]


def test_migration_backend_error_is_reported_as_corrupted(
    password_hash: PasswordHash,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def exploding_verify(password: str | bytes, hash: str | bytes) -> bool:
        raise ValueError

    monkeypatch.setattr(password_hash.hashers[1], "verify", exploding_verify)
    policy = PasswordMigrationPolicy(password_hash)

    result = policy.verify_and_migrate(
        _PASSWORD, _BCRYPT_HASH_STR, InMemoryHashStore(_BCRYPT_HASH_STR)
    )

    assert result.status is MigrationStatus.CORRUPTED_HASH
    assert result.failure_reason is MigrationFailureReason.CORRUPTED_HASH
    assert isinstance(result.error, ValueError)


def test_migration_ignores_broken_load_callback(
    password_hash: PasswordHash,
) -> None:
    policy = PasswordMigrationPolicy(password_hash)
    stored = {"hash": _BCRYPT_HASH_STR}

    def failing_load(old_hash: str) -> str | None:
        raise RuntimeError

    def update_hash(old_hash: str, new_hash: str) -> None:
        stored["hash"] = new_hash

    result = policy.verify_and_migrate(
        _PASSWORD, _BCRYPT_HASH_STR, update_hash, load=failing_load
    )

    assert result.status is MigrationStatus.UPGRADED
    assert stored["hash"] == result.final_hash


def test_migration_garbage_load_value_does_not_fake_migration(
    password_hash: PasswordHash,
) -> None:
    policy = PasswordMigrationPolicy(password_hash)

    result = policy.verify_and_migrate(
        _PASSWORD,
        _BCRYPT_HASH_STR,
        lambda old, new: None,
        load=lambda old: "",
    )

    assert result.status is MigrationStatus.UPGRADED


def test_migration_unrecognized_load_value_is_ignored(
    password_hash: PasswordHash,
) -> None:
    policy = PasswordMigrationPolicy(password_hash)

    result = policy.verify_and_migrate(
        _PASSWORD,
        _BCRYPT_HASH_STR,
        lambda old, new: None,
        load=lambda old: "neither-bcrypt-nor-argon2",
    )

    assert result.status is MigrationStatus.UPGRADED


def test_migration_without_load_detects_no_committed_hash(
    password_hash: PasswordHash,
) -> None:
    policy = PasswordMigrationPolicy(password_hash)

    result = policy.verify_and_migrate(
        _PASSWORD, _BCRYPT_HASH_STR, lambda old, new: None
    )

    assert result.status is MigrationStatus.UPGRADED
    assert policy._load_committed_hash(_BCRYPT_HASH_STR, None) is None


def test_migration_result_equality(password_hash: PasswordHash) -> None:
    policy = PasswordMigrationPolicy(password_hash)
    first = policy.verify_and_migrate(
        _PASSWORD, _ARGON2_HASH_STR, InMemoryHashStore(_ARGON2_HASH_STR)
    )
    second = policy.verify_and_migrate(
        _PASSWORD, _ARGON2_HASH_STR, InMemoryHashStore(_ARGON2_HASH_STR)
    )

    assert first == second
    assert first != object()


@pytest.mark.parametrize(
    "hash,expected",
    [
        (_ARGON2_HASH_STR, True),
        (_TRUNCATED_ARGON2_HASH, False),
        (_MALFORMED_ARGON2_HASH, False),
        (_BCRYPT_HASH_STR, False),
    ],
)
def test_argon2_is_valid(hash: str, expected: bool) -> None:
    assert Argon2Hasher.is_valid(hash) is expected


@pytest.mark.parametrize(
    "hash,expected",
    [
        (_ARGON2_HASH_STR, True),
        (_TRUNCATED_ARGON2_HASH, True),
        (_MALFORMED_ARGON2_HASH, True),
        (_BCRYPT_HASH_STR, False),
        ("INVALID_HASH", False),
    ],
)
def test_argon2_identify_prefix(hash: str, expected: bool) -> None:
    assert Argon2Hasher.identify_prefix(hash) is expected


@pytest.mark.parametrize(
    "hash,expected",
    [
        (_BCRYPT_HASH_STR, True),
        (_TRUNCATED_BCRYPT_HASH, False),
    ],
)
def test_bcrypt_is_valid(hash: str, expected: bool) -> None:
    assert BcryptHasher.is_valid(hash) is expected


@pytest.mark.parametrize(
    "hash,expected",
    [
        (_BCRYPT_HASH_STR, True),
        (_TRUNCATED_BCRYPT_HASH, True),
        (_ARGON2_HASH_STR, False),
    ],
)
def test_bcrypt_identify_prefix(hash: str, expected: bool) -> None:
    assert BcryptHasher.identify_prefix(hash) is expected


def test_hasher_prefix_and_validity_handle_invalid_utf8() -> None:
    invalid_utf8 = b"\xc3\x28"
    assert Argon2Hasher.identify_prefix(invalid_utf8) is False
    assert Argon2Hasher.is_valid(invalid_utf8) is False
    assert BcryptHasher.identify_prefix(invalid_utf8) is False
    assert BcryptHasher.is_valid(invalid_utf8) is False


def test_migration_bytes_hash_round_trip(password_hash: PasswordHash) -> None:
    policy = PasswordMigrationPolicy(password_hash)
    result = policy.verify_and_migrate(
        _PASSWORD,
        _BCRYPT_HASH_STR.encode("ascii"),
        InMemoryHashStore(_BCRYPT_HASH_STR),
    )
    assert result.status is MigrationStatus.UPGRADED
    assert isinstance(result.final_hash, str)


def test_hasher_equality() -> None:
    assert Argon2Hasher() == Argon2Hasher()
    assert BcryptHasher() == BcryptHasher()
    assert Argon2Hasher() != BcryptHasher()
    assert BcryptHasher(rounds=10) != BcryptHasher(rounds=12)
    assert hash(Argon2Hasher()) == hash(Argon2Hasher())
