import logging

import pytest

from pwdlib import PasswordHash, exceptions
from pwdlib.hashers.argon2 import Argon2Hasher
from pwdlib.hashers.base import PepperedHasher, PepperStrategy
from pwdlib.hashers.bcrypt import BcryptHasher

_PASSWORD = "herminetincture"
_UNICODE_PASSWORD = "herminé tinctüré 🔐"
_CURRENT_KEY = "current-pepper-secret"
_PREVIOUS_KEY = "previous-pepper-secret"


def _two_key_strategy() -> PepperStrategy:
    return PepperStrategy(
        current_key_id="key-2",
        keys={"key-1": _PREVIOUS_KEY, "key-2": _CURRENT_KEY},
    )


@pytest.fixture
def peppered_hash() -> PasswordHash:
    return PasswordHash((Argon2Hasher(), BcryptHasher()), pepper=_two_key_strategy())


def test_pepper_is_opt_in_and_explicit() -> None:
    plain = PasswordHash((Argon2Hasher(),))
    assert plain.pepper is None
    assert not isinstance(plain.current_hasher, PepperedHasher)

    peppered = PasswordHash((Argon2Hasher(),), pepper=_two_key_strategy())
    assert peppered.pepper is not None
    assert isinstance(peppered.current_hasher, PepperedHasher)


def test_hash_uses_current_key_and_hides_material(peppered_hash: PasswordHash) -> None:
    wrapped = peppered_hash.hash(_PASSWORD)
    assert isinstance(wrapped, str)
    assert wrapped.startswith("$pwdlib-pepper$v1$key-2$")
    assert _CURRENT_KEY not in wrapped
    assert _PREVIOUS_KEY not in wrapped
    assert peppered_hash.current_hasher.identify(wrapped)
    # The inner value is still a plain argon2 hash once unwrapped.
    _, inner_hash = peppered_hash.pepper.parse(wrapped)
    assert Argon2Hasher.identify(inner_hash)


def test_hash_and_verify_roundtrip_with_both_hashers() -> None:
    peppered = PasswordHash(
        (Argon2Hasher(), BcryptHasher()), pepper=_two_key_strategy()
    )
    argon2_wrapped = peppered.hash(_PASSWORD)
    assert peppered.verify(_PASSWORD, argon2_wrapped) is True
    assert peppered.verify("INVALID_PASSWORD", argon2_wrapped) is False

    bcrypt_wrapped = PasswordHash(
        (BcryptHasher(), Argon2Hasher()), pepper=_two_key_strategy()
    ).hash(_PASSWORD)
    assert peppered.verify(_PASSWORD, bcrypt_wrapped) is True
    assert peppered.verify("INVALID_PASSWORD", bcrypt_wrapped) is False


def test_dual_key_window_reads_old_key_and_rotates(
    peppered_hash: PasswordHash,
) -> None:
    old_strategy = PepperStrategy(
        current_key_id="key-1",
        keys={"key-1": _PREVIOUS_KEY, "key-2": _CURRENT_KEY},
    )
    old_password_hash = PasswordHash((Argon2Hasher(),), pepper=old_strategy)
    legacy_wrapped = old_password_hash.hash(_PASSWORD)
    assert legacy_wrapped.startswith("$pwdlib-pepper$v1$key-1$")

    # Verification during the rotation window uses the recorded key id.
    assert peppered_hash.verify(_PASSWORD, legacy_wrapped) is True
    assert peppered_hash.verify("INVALID_PASSWORD", legacy_wrapped) is False

    valid, updated = peppered_hash.verify_and_update(_PASSWORD, legacy_wrapped)
    assert valid is True
    assert updated is not None
    assert updated.startswith("$pwdlib-pepper$v1$key-2$")
    assert peppered_hash.verify(_PASSWORD, updated) is True

    # A current-key hash is not downgraded again by concurrent/repeated logins.
    valid, updated_again = peppered_hash.verify_and_update(_PASSWORD, updated)
    assert valid is True
    assert updated_again is None
    valid, no_update = peppered_hash.verify_and_update(_PASSWORD, updated)
    assert valid is True
    assert no_update is None


def test_rotation_after_old_key_retired_does_not_report_wrong_password(
    peppered_hash: PasswordHash,
) -> None:
    old_strategy = PepperStrategy(current_key_id="key-1", keys={"key-1": _PREVIOUS_KEY})
    legacy_wrapped = PasswordHash((Argon2Hasher(),), pepper=old_strategy).hash(
        _PASSWORD
    )

    retired = PasswordHash(
        (Argon2Hasher(),),
        pepper=PepperStrategy(
            current_key_id="key-2",
            # key-1 id is still known but its material was retired.
            keys={"key-1": None, "key-2": _CURRENT_KEY},
        ),
    )
    with pytest.raises(exceptions.MissingPepperKeyError) as exc_info:
        retired.verify(_PASSWORD, legacy_wrapped)
    assert exc_info.value.key_id == "key-1"
    with pytest.raises(exceptions.MissingPepperKeyError):
        retired.verify_and_update(_PASSWORD, legacy_wrapped)

    # The id itself disappearing is a distinct, unknown-key failure.
    removed = PasswordHash(
        (Argon2Hasher(),),
        pepper=PepperStrategy(current_key_id="key-2", keys={"key-2": _CURRENT_KEY}),
    )
    with pytest.raises(exceptions.UnknownPepperKeyError) as exc_info:
        removed.verify(_PASSWORD, legacy_wrapped)
    assert exc_info.value.key_id == "key-1"


def test_corrupt_wrapper_is_distinct_from_wrong_password(
    peppered_hash: PasswordHash,
) -> None:
    good = peppered_hash.hash(_PASSWORD)
    _, inner_hash = peppered_hash.pepper.parse(good)
    # Invalid character in the key id slot makes the wrapper undecodable.
    corrupt = f"$pwdlib-pepper$v1$bad/id${inner_hash}"

    with pytest.raises(exceptions.CorruptPepperHashError):
        peppered_hash.verify(_PASSWORD, corrupt)
    with pytest.raises(exceptions.CorruptPepperHashError):
        peppered_hash.verify_and_update(_PASSWORD, corrupt)

    # A structurally valid wrapper with a wrong password stays a plain False.
    assert peppered_hash.verify("INVALID_PASSWORD", good) is False
    valid, updated = peppered_hash.verify_and_update("INVALID_PASSWORD", good)
    assert valid is False
    assert updated is None


def test_unknown_key_error(peppered_hash: PasswordHash) -> None:
    good = peppered_hash.hash(_PASSWORD)
    _, inner_hash = peppered_hash.pepper.parse(good)
    unknown = f"$pwdlib-pepper$v1$key-99${inner_hash}"
    with pytest.raises(exceptions.UnknownPepperKeyError) as exc_info:
        peppered_hash.verify(_PASSWORD, unknown)
    assert exc_info.value.key_id == "key-99"


def test_corrupt_wrapper_fails_fast_through_verify_and_update(
    peppered_hash: PasswordHash,
) -> None:
    for corrupt in (
        "$pwdlib-pepper$v1$bad/id$abc",
        "$pwdlib-pepper$v1$key-2$",
        b"$pwdlib-pepper$v1$key-2",
    ):
        with pytest.raises(exceptions.CorruptPepperHashError):
            peppered_hash.verify(_PASSWORD, corrupt)
        with pytest.raises(exceptions.CorruptPepperHashError):
            peppered_hash.verify_and_update(_PASSWORD, corrupt)


def test_legacy_unpeppered_hash_still_verifies_and_upgrades(
    peppered_hash: PasswordHash,
) -> None:
    legacy_argon2 = Argon2Hasher().hash(_PASSWORD)
    legacy_bcrypt = BcryptHasher().hash(_PASSWORD)

    assert peppered_hash.verify(_PASSWORD, legacy_argon2) is True
    assert peppered_hash.verify(_PASSWORD, legacy_bcrypt) is True
    assert peppered_hash.verify("INVALID_PASSWORD", legacy_argon2) is False

    valid, updated = peppered_hash.verify_and_update(_PASSWORD, legacy_argon2)
    assert valid is True
    assert updated is not None
    assert updated.startswith("$pwdlib-pepper$v1$key-2$")
    assert peppered_hash.verify(_PASSWORD, updated) is True

    valid, updated = peppered_hash.verify_and_update(_PASSWORD, legacy_bcrypt)
    assert valid is True
    assert updated is not None
    assert updated.startswith("$pwdlib-pepper$v1$key-2$")


def test_bytes_and_unicode_passwords(peppered_hash: PasswordHash) -> None:
    unicode_wrapped = peppered_hash.hash(_UNICODE_PASSWORD)
    assert peppered_hash.verify(_UNICODE_PASSWORD, unicode_wrapped) is True
    assert (
        peppered_hash.verify(_UNICODE_PASSWORD.encode("utf-8"), unicode_wrapped) is True
    )
    assert peppered_hash.verify(b"wrong", unicode_wrapped) is False

    bytes_wrapped = peppered_hash.hash(b"raw-bytes-password")
    assert peppered_hash.verify(b"raw-bytes-password", bytes_wrapped) is True
    assert peppered_hash.verify(b"raw-bytes-passwor", bytes_wrapped) is False


def test_bcrypt_seventy_two_byte_semantics_preserved() -> None:
    peppered = PasswordHash((BcryptHasher(rounds=4),), pepper=_two_key_strategy())
    long_password = b"a" * 100
    wrapped = peppered.hash(long_password)
    assert peppered.verify(long_password, wrapped) is True
    # The pepper derivation feeds bcrypt a fixed 32-byte HMAC digest, so
    # passwords colliding only under bcrypt's raw 72-byte truncation remain
    # distinct once pepper is enabled.
    assert peppered.verify(b"a" * 72, wrapped) is False
    assert peppered.verify(b"a" * 72 + b"different", wrapped) is False
    assert peppered.verify(b"b" * 100, wrapped) is False

    # Without pepper, the underlying bcrypt truncation semantics are untouched.
    plain = PasswordHash((BcryptHasher(rounds=4),))
    plain_wrapped = plain.hash(long_password)
    assert plain.verify(b"a" * 72, plain_wrapped) is True
    assert plain.verify(b"a" * 72 + b"different", plain_wrapped) is True


def test_no_pepper_output_unchanged_shape() -> None:
    plain = PasswordHash((Argon2Hasher(),))
    digest = plain.hash(_PASSWORD)
    assert Argon2Hasher.identify(digest)
    assert plain.verify(_PASSWORD, digest) is True
    valid, updated = plain.verify_and_update(_PASSWORD, digest)
    assert valid is True
    assert updated is None


@pytest.mark.parametrize(
    "secret",
    [
        pytest.param(_CURRENT_KEY, id="str-material"),
        pytest.param(b"\x00\xff", id="bytes-material"),
    ],
)
def test_str_and_bytes_key_material(secret: str | bytes) -> None:
    strategy = PepperStrategy(current_key_id="k", keys={"k": secret})
    password_hash = PasswordHash((Argon2Hasher(),), pepper=strategy)
    wrapped = password_hash.hash(_PASSWORD)
    assert password_hash.verify(_PASSWORD, wrapped) is True


def test_invalid_strategy_construction() -> None:
    with pytest.raises(ValueError):
        PepperStrategy(current_key_id="bad id!", keys={"bad id!": _CURRENT_KEY})
    with pytest.raises(ValueError):
        PepperStrategy(current_key_id="k", keys={})
    with pytest.raises(ValueError):
        PepperStrategy(current_key_id="k", keys={"k": ""})
    with pytest.raises(ValueError):
        PepperStrategy(current_key_id="missing", keys={"k": _CURRENT_KEY})
    with pytest.raises(ValueError):
        PepperStrategy(current_key_id="k", keys={"k": None})
    with pytest.raises(TypeError):
        PasswordHash((Argon2Hasher(),), pepper="not-a-strategy")  # type: ignore[arg-type]


def test_exceptions_and_logs_never_leak_secrets_or_hash(
    peppered_hash: PasswordHash, caplog: pytest.LogCaptureFixture
) -> None:
    good = peppered_hash.hash(_PASSWORD)
    _, inner_hash = peppered_hash.pepper.parse(good)
    unknown = f"$pwdlib-pepper$v1$key-99${inner_hash}"
    retired = f"$pwdlib-pepper$v1$key-1${inner_hash}"
    corrupt = "$pwdlib-pepper$v1$bad/id$not-an-inner-hash"

    retired_strategy = PasswordHash(
        (Argon2Hasher(),),
        pepper=PepperStrategy(
            current_key_id="key-2",
            keys={"key-1": None, "key-2": _CURRENT_KEY},
        ),
    )

    caplog.set_level(logging.WARNING, logger="pwdlib.pepper")
    cases = [
        (peppered_hash, unknown, exceptions.UnknownPepperKeyError),
        (retired_strategy, retired, exceptions.MissingPepperKeyError),
        (peppered_hash, corrupt, exceptions.CorruptPepperHashError),
    ]
    for password_hash, hash_value, expected_error in cases:
        with pytest.raises(expected_error) as exc_info:
            password_hash.verify(_PASSWORD, hash_value)
        rendered = repr(exc_info.value) + str(exc_info.value)
        assert _CURRENT_KEY not in rendered
        assert _PREVIOUS_KEY not in rendered
        assert inner_hash not in rendered
        assert hash_value not in rendered

    for record in caplog.records:
        rendered = record.getMessage()
        assert _CURRENT_KEY not in rendered
        assert _PREVIOUS_KEY not in rendered
        assert inner_hash not in rendered
