from __future__ import annotations

import tracemalloc

import pytest

from pwdlib import PasswordHash, exceptions
from pwdlib.hashers.argon2 import Argon2Hasher
from pwdlib.hashers.bcrypt import BcryptHasher

_PASSWORD = "herminetincture"


@pytest.fixture(scope="module")
def argon2_hasher() -> Argon2Hasher:
    return Argon2Hasher(time_cost=1, memory_cost=1024, parallelism=1)


@pytest.fixture(scope="module")
def bcrypt_hasher() -> BcryptHasher:
    return BcryptHasher(rounds=4)


@pytest.fixture(scope="module")
def password_hash(
    argon2_hasher: Argon2Hasher, bcrypt_hasher: BcryptHasher
) -> PasswordHash:
    return PasswordHash((argon2_hasher, bcrypt_hasher))


@pytest.mark.parametrize("password", [b"a" * 71, b"a" * 72, "é" * 36])
def test_bcrypt_accepts_up_to_72_utf8_bytes(
    password: str | bytes, bcrypt_hasher: BcryptHasher
) -> None:
    password_hash = bcrypt_hasher.hash(password)
    assert bcrypt_hasher.verify(password, password_hash)


@pytest.mark.parametrize("password", [b"a" * 73, "é" * 37])
def test_bcrypt_rejects_more_than_72_utf8_bytes(
    password: str | bytes, bcrypt_hasher: BcryptHasher
) -> None:
    with pytest.raises(exceptions.PasswordTooLongError):
        bcrypt_hasher.hash(password)


@pytest.mark.parametrize(
    "password,result",
    [
        pytest.param(b"a" * 1024, True, id="1024-bytes"),
        pytest.param("é" * 512, True, id="1024-utf8-bytes"),
        pytest.param(b"a" * 1025, False, id="1025-bytes"),
        pytest.param("é" * 513, False, id="1026-utf8-bytes"),
    ],
)
def test_argon2_password_byte_boundary(
    password: str | bytes, result: bool, argon2_hasher: Argon2Hasher
) -> None:
    if result:
        password_hash = argon2_hasher.hash(password)
        assert argon2_hasher.verify(password, password_hash)
    else:
        with pytest.raises(exceptions.PasswordTooLongError):
            argon2_hasher.hash(password)


@pytest.mark.parametrize(
    "password,exception",
    [
        pytest.param("a\x00b", exceptions.PasswordNULByteError, id="str-nul"),
        pytest.param(b"a\x00b", exceptions.PasswordNULByteError, id="bytes-nul"),
        pytest.param(b"\xff", exceptions.PasswordEncodingError, id="invalid-utf8"),
        pytest.param("\ud800", exceptions.PasswordEncodingError, id="surrogate"),
    ],
)
def test_invalid_password_values_are_rejected_before_backend(
    password: str | bytes,
    exception: type[exceptions.PasswordLimitError],
    password_hash: PasswordHash,
    bcrypt_hasher: BcryptHasher,
) -> None:
    with pytest.raises(exception):
        password_hash.hash(password)
    with pytest.raises(exception):
        bcrypt_hasher.hash(password)
    with pytest.raises(exception):
        password_hash.verify(password, password_hash.current_hasher.hash(_PASSWORD))


def test_empty_and_tiny_passwords_remain_supported(
    password_hash: PasswordHash, argon2_hasher: Argon2Hasher
) -> None:
    for password in ("", b"", "x", b"x"):
        password_hash_str = password_hash.hash(password)
        assert password_hash.verify(password, password_hash_str)

    bounded = Argon2Hasher(
        time_cost=1, memory_cost=1024, parallelism=1, min_password_bytes=1
    )
    with pytest.raises(exceptions.PasswordTooShortError):
        bounded.hash("")


@pytest.mark.parametrize(
    "hash,exception",
    [
        pytest.param("$2b$", exceptions.HashTooShortError, id="bcrypt-short"),
        pytest.param("$2b$" + "A" * 57, exceptions.HashTooLongError, id="bcrypt-long"),
        pytest.param("$argon2id$", exceptions.HashTooShortError, id="argon2-short"),
        pytest.param(
            "$argon2id$" + "A" * 2000, exceptions.HashTooLongError, id="argon2-long"
        ),
        pytest.param(
            "$2c$" + "A" * 56,
            exceptions.UnsupportedHashError,
            id="unsupported-bcrypt-prefix",
        ),
        pytest.param(
            "$argon2x$" + "A" * 55,
            exceptions.UnsupportedHashError,
            id="unsupported-argon2-prefix",
        ),
        pytest.param(
            "$argon2id$" + "$".join(["x"] * 6),
            exceptions.HashFieldCountError,
            id="too-many-fields",
        ),
        pytest.param(
            "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$!!!!",
            exceptions.UnsupportedHashError,
            id="invalid-digest-charset",
        ),
        pytest.param(
            b"$2b$12$" + b"\xff" + b"A" * 50,
            exceptions.InvalidHashEncodingError,
            id="invalid-ascii",
        ),
    ],
)
def test_malformed_hashes_have_stable_errors(
    hash: str | bytes,
    exception: type[exceptions.HashFormatError],
    password_hash: PasswordHash,
) -> None:
    with pytest.raises(exception):
        password_hash.verify(_PASSWORD, hash)
    with pytest.raises(exception):
        password_hash.verify_and_update(_PASSWORD, hash)


def test_same_policy_for_all_entry_points(
    password_hash: PasswordHash, argon2_hasher: Argon2Hasher
) -> None:
    hash = argon2_hasher.hash(_PASSWORD)
    with pytest.raises(exceptions.PasswordTooLongError):
        password_hash.verify(b"a" * 1025, hash)
    with pytest.raises(exceptions.PasswordTooLongError):
        password_hash.verify_and_update(b"a" * 1025, hash)
    with pytest.raises(exceptions.HashTooLongError):
        password_hash.verify(_PASSWORD, "$argon2id$" + "A" * 2000)
    with pytest.raises(exceptions.HashTooLongError):
        password_hash.verify_and_update(_PASSWORD, "$argon2id$" + "A" * 2000)


def test_limits_are_configurable(argon2_hasher: Argon2Hasher) -> None:
    argon2_hash = argon2_hasher.hash(_PASSWORD)

    password_hash = PasswordHash((argon2_hasher,), max_password_bytes=8)
    with pytest.raises(exceptions.PasswordTooLongError):
        password_hash.hash("a" * 9)

    password_hash = PasswordHash((argon2_hasher,), max_hash_bytes=64)
    with pytest.raises(exceptions.HashTooLongError):
        password_hash.verify(_PASSWORD, argon2_hash)

    assert PasswordHash((argon2_hasher,), max_hash_bytes=128).verify(
        _PASSWORD, argon2_hash
    )

    password_hash = PasswordHash((argon2_hasher,), max_hash_fields=4)
    with pytest.raises(exceptions.HashFieldCountError):
        password_hash.verify(_PASSWORD, argon2_hash)

    relaxed_bcrypt = BcryptHasher(rounds=4, max_password_bytes=73)
    assert relaxed_bcrypt.verify(b"a" * 73, relaxed_bcrypt.hash(b"a" * 73))


def test_limit_errors_do_not_echo_passwords(bcrypt_hasher: BcryptHasher) -> None:
    password = "do-not-echo-" + "x" * 1000
    with pytest.raises(exceptions.PasswordTooLongError) as exc_info:
        bcrypt_hasher.hash(password)
    assert password not in str(exc_info.value)
    assert password not in repr(exc_info.value)


def test_oversized_inputs_do_not_reach_backends(
    monkeypatch: pytest.MonkeyPatch,
    bcrypt_hasher: BcryptHasher,
    argon2_hasher: Argon2Hasher,
) -> None:
    password_hash = PasswordHash((argon2_hasher, bcrypt_hasher))
    bcrypt_hash = bcrypt_hasher.hash(_PASSWORD)
    argon2_hash = argon2_hasher.hash(_PASSWORD)
    calls: list[str] = []

    def fail(*args: object, **kwargs: object) -> None:
        calls.append("backend")
        raise AssertionError("backend was called")  # noqa: TRY003

    class BackendSpy:
        def verify(self, *args: object, **kwargs: object) -> None:
            fail(*args, **kwargs)

        def hash(self, *args: object, **kwargs: object) -> None:
            fail(*args, **kwargs)

        def check_needs_rehash(self, *args: object, **kwargs: object) -> bool:
            return False

    monkeypatch.setattr("pwdlib.hashers.bcrypt.bcrypt.checkpw", fail)
    monkeypatch.setattr("pwdlib.hashers.bcrypt.bcrypt.hashpw", fail)
    monkeypatch.setattr(argon2_hasher, "_hasher", BackendSpy())

    with pytest.raises(exceptions.PasswordTooLongError):
        password_hash.hash(b"a" * (8 * 1024 * 1024))
    with pytest.raises(exceptions.PasswordTooLongError):
        password_hash.verify(b"a" * (8 * 1024 * 1024), argon2_hash)
    with pytest.raises(exceptions.HashTooLongError):
        password_hash.verify(_PASSWORD, b"$argon2id$" + b"A" * (8 * 1024 * 1024))
    with pytest.raises(exceptions.HashTooLongError):
        password_hash.verify_and_update(
            _PASSWORD, b"$argon2id$" + b"A" * (8 * 1024 * 1024)
        )
    with pytest.raises(exceptions.PasswordTooLongError):
        bcrypt_hasher.verify(b"a" * 73, bcrypt_hash)

    assert calls == []


def test_wrapper_honors_hasher_specific_password_limit(
    monkeypatch: pytest.MonkeyPatch, bcrypt_hasher: BcryptHasher
) -> None:
    password_hash = PasswordHash((bcrypt_hasher,))
    bcrypt_hash = bcrypt_hasher.hash(_PASSWORD)
    calls: list[str] = []

    def fail(*args: object, **kwargs: object) -> None:
        calls.append("hasher")
        raise AssertionError("hasher was called")  # noqa: TRY003

    monkeypatch.setattr(bcrypt_hasher, "hash", fail)
    monkeypatch.setattr(bcrypt_hasher, "verify", fail)

    with pytest.raises(exceptions.PasswordTooLongError):
        password_hash.hash(b"a" * 73)
    with pytest.raises(exceptions.PasswordTooLongError):
        password_hash.verify(b"a" * 73, bcrypt_hash)
    with pytest.raises(exceptions.PasswordTooLongError):
        password_hash.verify_and_update(b"a" * 73, bcrypt_hash)

    assert calls == []


def test_oversized_input_does_not_create_a_full_copy(
    password_hash: PasswordHash, bcrypt_hasher: BcryptHasher
) -> None:
    large_password = b"a" * (8 * 1024 * 1024)
    large_hash = b"$argon2id$" + b"A" * (8 * 1024 * 1024)
    argon2_hash = password_hash.current_hasher.hash(_PASSWORD)
    bcrypt_hash = bcrypt_hasher.hash(_PASSWORD)

    tracemalloc.start()
    baseline = tracemalloc.get_traced_memory()[0]
    with pytest.raises(exceptions.PasswordTooLongError):
        password_hash.verify(large_password, argon2_hash)
    with pytest.raises(exceptions.HashTooLongError):
        password_hash.verify(_PASSWORD, large_hash)
    with pytest.raises(exceptions.PasswordTooLongError):
        bcrypt_hasher.verify(large_password, bcrypt_hash)
    peak_extra = tracemalloc.get_traced_memory()[1] - baseline
    tracemalloc.stop()

    assert peak_extra < 256 * 1024
