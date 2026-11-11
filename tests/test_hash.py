import pytest

from pwdlib import PasswordHash, exceptions
from pwdlib.hashers.argon2 import Argon2Hasher, Argon2VerificationPolicy
from pwdlib.hashers.bcrypt import BcryptHasher

_PASSWORD = "herminetincture"

_ARGON2_HASHER = Argon2Hasher()
_ARGON2_HASH_STR = _ARGON2_HASHER.hash(_PASSWORD)

_BCRYPT_HASHER = BcryptHasher()
_BCRYPT_HASH_STR = _BCRYPT_HASHER.hash(_PASSWORD)


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


def test_password_hash_without_policy_keeps_hashers() -> None:
    argon2_hasher = Argon2Hasher()
    password_hash = PasswordHash((argon2_hasher, BcryptHasher()))
    assert password_hash.current_hasher is argon2_hasher
    assert password_hash.current_hasher.verification_policy is None


def test_password_hash_with_policy_wraps_argon2_hashers() -> None:
    argon2_hasher = Argon2Hasher()
    policy = Argon2VerificationPolicy()
    password_hash = PasswordHash(
        (argon2_hasher, BcryptHasher()), verification_policy=policy
    )
    assert isinstance(password_hash.current_hasher, Argon2Hasher)
    assert password_hash.current_hasher.verification_policy is policy
    assert isinstance(password_hash.hashers[1], BcryptHasher)
    # The original hasher is not mutated.
    assert argon2_hasher.verification_policy is None


def test_recommended_with_verification_policy() -> None:
    policy = Argon2VerificationPolicy(max_memory_cost=32768)
    password_hash = PasswordHash.recommended_with_verification_policy(policy)
    assert isinstance(password_hash.current_hasher, Argon2Hasher)
    assert password_hash.current_hasher.verification_policy is policy


def test_verify_with_policy_blocks_tampered_hash() -> None:
    policy = Argon2VerificationPolicy()
    password_hash = PasswordHash((Argon2Hasher(),), verification_policy=policy)
    hash = password_hash.hash(_PASSWORD)
    tampered = hash.replace("m=65536", "m=4194304")
    with pytest.raises(exceptions.HashVerificationPolicyError) as exc_info:
        password_hash.verify(_PASSWORD, tampered)
    assert exc_info.value.reason == "memory_cost_exceeded"


def test_verify_with_policy_still_accepts_valid_hash() -> None:
    policy = Argon2VerificationPolicy()
    password_hash = PasswordHash((Argon2Hasher(),), verification_policy=policy)
    hash = password_hash.hash(_PASSWORD)
    assert password_hash.verify(_PASSWORD, hash) is True
    assert password_hash.verify("INVALID_PASSWORD", hash) is False


def test_verify_and_update_with_policy_unchanged_for_valid_hash() -> None:
    policy = Argon2VerificationPolicy()
    password_hash = PasswordHash(
        (Argon2Hasher(), BcryptHasher()), verification_policy=policy
    )
    valid, updated_hash = password_hash.verify_and_update(_PASSWORD, _ARGON2_HASH_STR)
    assert valid is True
    assert updated_hash is None


def test_verify_and_update_with_policy_blocks_tampered_hash() -> None:
    policy = Argon2VerificationPolicy()
    password_hash = PasswordHash((Argon2Hasher(),), verification_policy=policy)
    tampered = _ARGON2_HASH_STR.replace("m=65536", "m=4194304")
    with pytest.raises(exceptions.HashVerificationPolicyError):
        password_hash.verify_and_update(_PASSWORD, tampered)


def test_verify_with_policy_unknown_hash_still_raises_unknown_error() -> None:
    policy = Argon2VerificationPolicy()
    password_hash = PasswordHash((Argon2Hasher(),), verification_policy=policy)
    with pytest.raises(exceptions.UnknownHashError):
        password_hash.verify(_PASSWORD, "INVALID_HASH")


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
