import os

import pytest
import werkzeug.security as security
from werkzeug.security import check_password_hash
from werkzeug.security import diagnose_password_hash
from werkzeug.security import generate_password_hash
from werkzeug.security import MAX_HASH_LENGTH
from werkzeug.security import MAX_PASSWORD_HASH_LENGTH
from werkzeug.security import MAX_SALT_LENGTH
from werkzeug.security import PasswordHashStatus
from werkzeug.security import safe_join


def test_default_password_method():
    value = generate_password_hash("secret")
    assert value.startswith("scrypt:")


def test_scrypt():
    value = generate_password_hash("secret", method="scrypt")
    assert check_password_hash(value, "secret")
    assert value.startswith("scrypt:32768:8:1$")


def test_pbkdf2():
    value = generate_password_hash("secret", method="pbkdf2")
    assert check_password_hash(value, "secret")
    assert value.startswith("pbkdf2:sha256:1000000$")


def test_diagnose_current_hashes():
    for method in ("scrypt", "pbkdf2"):
        value = generate_password_hash("secret", method=method)
        result = diagnose_password_hash(value, "secret")
        assert result.status is PasswordHashStatus.OK
        assert result.valid
        assert result.password_matches
        assert not result.needs_upgrade
        assert result.reason == "password matches the stored hash"


def test_diagnose_password_mismatch_is_not_malformed():
    value = generate_password_hash("secret")
    result = diagnose_password_hash(value, "wrong")
    assert result.status is PasswordHashStatus.PASSWORD_MISMATCH
    assert not result.valid
    assert not result.password_matches
    assert result.format_valid
    assert result.algorithm_supported
    assert result.within_limits


def test_diagnose_unsupported_algorithms():
    result = diagnose_password_hash("sha256$salt$deadbeef", "secret")
    assert result.status is PasswordHashStatus.UNSUPPORTED_ALGORITHM
    assert not result.valid
    assert not result.algorithm_supported

    result = diagnose_password_hash(
        "pbkdf2:not-a-digest:1000000$salt$" + "0" * 64, "secret"
    )
    assert result.status is PasswordHashStatus.UNSUPPORTED_ALGORITHM
    assert not result.valid
    assert not result.algorithm_supported


@pytest.mark.parametrize(
    "value",
    [
        "scrypt:32768:8$salt$" + "0" * 128,
        "pbkdf2:sha256:1000000$salt",
        "scrypt:32768:8:1:1$salt$" + "0" * 128,
        "pbkdf2:sha256:1000000:1$salt$" + "0" * 64,
        "pbkdf2:sha256:not-a-number$salt$" + "0" * 64,
    ],
)
def test_diagnose_missing_or_extra_fields(value):
    result = diagnose_password_hash(value, "secret")
    assert result.status is PasswordHashStatus.MALFORMED
    assert not result.valid
    assert not result.format_valid


@pytest.mark.parametrize(
    "value",
    [
        "pbkdf2:sha256:-1$salt$" + "0" * 64,
        "pbkdf2:sha256:0$salt$" + "0" * 64,
        "scrypt:32768:-8:1$salt$" + "0" * 128,
        "scrypt:32768:8:-1$salt$" + "0" * 128,
        "scrypt:30000:8:1$salt$" + "0" * 128,
    ],
)
def test_diagnose_invalid_numeric_ranges(value):
    result = diagnose_password_hash(value, "secret")
    assert result.status is PasswordHashStatus.MALFORMED
    assert not result.valid
    assert not result.format_valid


@pytest.mark.parametrize(
    "value",
    [
        "pbkdf2:sha256:1000000000$salt$" + "0" * 64,
        "scrypt:1073741824:8:1$salt$" + "0" * 128,
        "scrypt:32768:128:1$salt$" + "0" * 128,
    ],
)
def test_diagnose_kdf_budget_is_checked_without_hashing(value, monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("KDF must not run for over-budget hashes")

    monkeypatch.setattr("werkzeug.security._hash_internal", fail_if_called)
    result = diagnose_password_hash(value, "secret")
    assert result.status is PasswordHashStatus.LIMIT_EXCEEDED
    assert not result.valid
    assert not result.within_limits


@pytest.mark.parametrize(
    "value",
    [
        "pbkdf2:sha256:1000000$salt$" + "a" * (MAX_PASSWORD_HASH_LENGTH + 1),
        "pbkdf2:sha256:1000000$" + "a" * (MAX_SALT_LENGTH + 1) + "$" + "0" * 64,
        "pbkdf2:sha256:1000000$salt$" + "0" * (MAX_HASH_LENGTH + 1),
    ],
)
def test_diagnose_length_limits_are_checked_without_hashing(value, monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("KDF must not run for overlong hashes")

    monkeypatch.setattr("werkzeug.security._hash_internal", fail_if_called)
    result = diagnose_password_hash(value, "secret")
    assert result.status is PasswordHashStatus.LIMIT_EXCEEDED
    assert not result.valid
    assert not result.within_limits


def test_diagnose_legacy_pbkdf2_and_upgrade():
    password = "pässwörd-密码"
    value = generate_password_hash(password, method="pbkdf2:sha1:260000")
    assert check_password_hash(value, password)

    result = diagnose_password_hash(value, password)
    assert result.status is PasswordHashStatus.OK
    assert result.valid
    assert result.needs_upgrade
    assert result.needs_rehash
    assert "legacy digest" in result.upgrade_reason
    assert "iteration count" in result.upgrade_reason
    assert result.suggested_method == "scrypt"
    assert result.suggested_parameters == "scrypt:32768:8:1"


def test_diagnose_legacy_scrypt_and_upgrade():
    password = "pässwörd-密码"
    value = generate_password_hash(password, method="scrypt:16384:8:1")
    assert check_password_hash(value, password)

    result = diagnose_password_hash(value, password)
    assert result.status is PasswordHashStatus.OK
    assert result.valid
    assert result.needs_upgrade
    assert "work factor" in result.upgrade_reason
    assert result.recommended_method == "scrypt"


def test_check_password_hash_always_returns_false_for_bad_records():
    values = [
        "sha256$salt$deadbeef",
        "pbkdf2:sha256:1000000000$salt$" + "0" * 64,
        "pgkdf2:sha256:1000000$salt$" + "0" * 64,
        "scrypt:32768:8$salt$" + "0" * 128,
        "pbkdf2:sha256:1000000$salt$not-hex",
        "pbkdf2:sha256:1000000$salt$" + "0" * 63,
        "",
        "not-a-hash",
    ]

    for value in values:
        assert check_password_hash(value, "secret") is False


def test_legacy_default_parameters_still_verify():
    password = "pässwörd-密码"

    for method in ("scrypt", "pbkdf2"):
        hashval, _ = security._hash_internal(method, "salt", password)
        value = f"{method}$salt${hashval}"
        assert check_password_hash(value, password)

        result = diagnose_password_hash(value, password)
        assert result.status is PasswordHashStatus.OK
        assert result.valid


def test_diagnostic_does_not_expose_sensitive_values():
    salt = "secret-salt-value"
    hashval = "deadbeef"
    result = diagnose_password_hash(
        f"pbkdf2:sha256:1000000000${salt}${hashval}", "plaintext-password"
    )
    rendered = repr(result)
    assert salt not in rendered
    assert hashval not in rendered
    assert "plaintext-password" not in rendered


def test_salted_hashes():
    hash1 = generate_password_hash("secret")
    hash2 = generate_password_hash("secret")
    assert hash1 != hash2
    assert check_password_hash(hash1, "secret")
    assert check_password_hash(hash2, "secret")


def test_require_salt():
    with pytest.raises(ValueError):
        generate_password_hash("secret", salt_length=0)


def test_invalid_method():
    with pytest.raises(ValueError, match="Invalid hash method"):
        generate_password_hash("secret", "sha256")


@pytest.mark.parametrize(
    ("path", "expect"),
    [
        ("b/c", "a/b/c"),
        ("../b/c", None),
        ("b\\c", None if os.name == "nt" else "a/b\\c"),
        ("//b/c", None),
    ],
)
def test_safe_join(path, expect):
    assert safe_join("a", path) == expect


def test_safe_join_os_sep():
    import werkzeug.security as sec

    prev_value = sec._os_alt_seps
    sec._os_alt_seps = "*"
    assert safe_join("foo", "bar/baz*") is None
    sec._os_alt_steps = prev_value


def test_safe_join_empty_trusted():
    assert safe_join("", "c:test.txt") == "./c:test.txt"


@pytest.mark.parametrize(
    "name", ["CON", "CON.txt", "CON.txt.html", "CON  ", "CON . txt", "b/CON"]
)
def test_safe_join_windows_special(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    """Windows special device name is not allowed on Windows."""
    monkeypatch.setattr("os.name", "nt")
    assert safe_join("a", name) is None


def test_safe_join_not_windows_special(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("os.name", "posix")
    assert safe_join("a", "CON") == "a/CON"
