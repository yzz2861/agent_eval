import json

import pytest

from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
from pwdlib.policy import (
    NORMALIZATION_FORM,
    RULE_BIDI_CONTROL,
    RULE_CONTROL_CHARACTER,
    RULE_EMPTY,
    RULE_INVALID_SURROGATE,
    RULE_INVALID_UTF8,
    RULE_TOO_LONG,
    RULE_TOO_SHORT,
    RULE_WEAK_CHECKER_ERROR,
    RULE_WEAK_PASSWORD,
    RULE_ZERO_WIDTH_CHARACTER,
    PasswordPolicy,
    PasswordPolicyError,
)

_VALID = "herminetincture"
_FULLWIDTH_VALID = "ｈｅｒｍｉｎｅｔｉｎｃｔｕｒｅ"


@pytest.fixture
def policy() -> PasswordPolicy:
    return PasswordPolicy()


def test_normalization_form_is_fixed() -> None:
    assert NORMALIZATION_FORM == "NFKC"
    assert PasswordPolicy.normalization_form == NORMALIZATION_FORM


def test_fullwidth_and_halfwidth_have_the_same_result(
    policy: PasswordPolicy,
) -> None:
    fullwidth = policy.evaluate(_FULLWIDTH_VALID)
    halfwidth = policy.evaluate(_VALID)

    assert fullwidth == halfwidth
    assert fullwidth.allowed
    assert fullwidth.normalized == _VALID
    assert fullwidth.utf8_length == len(_VALID.encode("utf-8"))
    assert fullwidth.visible_length == len(_VALID)


def test_bytes_and_str_have_the_same_result(policy: PasswordPolicy) -> None:
    raw = "密码安全测试口令"
    assert policy.evaluate(raw) == policy.evaluate(raw.encode("utf-8"))


def test_combining_sequences_are_composed(policy: PasswordPolicy) -> None:
    composed = "é" * 8
    decomposed = "e\u0301" * 8

    assert policy.normalize(decomposed) == composed
    result = policy.evaluate(decomposed)
    assert result.allowed
    assert result.normalized == composed
    assert result.utf8_length == len(composed.encode("utf-8"))
    assert result.visible_length == 8


def test_zero_width_padding_is_rejected(policy: PasswordPolicy) -> None:
    raw = "abcd" + "\u200b" * 100
    result = policy.evaluate(raw)

    assert not result.allowed
    assert result.rule_id == RULE_ZERO_WIDTH_CHARACTER
    assert result.visible_length == 4
    assert result.utf8_length == 304
    assert result.input_length_range == "64-127"


def test_bom_is_treated_as_zero_width(policy: PasswordPolicy) -> None:
    result = policy.evaluate("\ufeff" + "safe-password")
    assert result.rule_id == RULE_ZERO_WIDTH_CHARACTER


def test_control_and_bidi_characters_are_explicitly_rejected(
    policy: PasswordPolicy,
) -> None:
    control = policy.evaluate("safe-pass\nword")
    bidi = policy.evaluate("safe-pass\u202eword")

    assert control.rule_id == RULE_CONTROL_CHARACTER
    assert bidi.rule_id == RULE_BIDI_CONTROL
    assert not control.allowed
    assert not bidi.allowed


def test_invalid_surrogate_is_rejected_without_raising(
    policy: PasswordPolicy,
) -> None:
    result = policy.evaluate("abcdefgh\ud800")

    assert not result.allowed
    assert result.rule_id == RULE_INVALID_SURROGATE
    assert result.normalized is None
    assert result.utf8_length is None


def test_invalid_utf8_bytes_are_rejected(policy: PasswordPolicy) -> None:
    result = policy.evaluate(b"abcdefg\xff")

    assert not result.allowed
    assert result.rule_id == RULE_INVALID_UTF8
    assert result.normalized is None
    assert result.input_length_range == "8-15"


def test_overlong_multibyte_password_is_rejected(policy: PasswordPolicy) -> None:
    raw = "密" * 50
    result = policy.evaluate(raw)

    assert result.rule_id == RULE_TOO_LONG
    assert result.utf8_length == 150
    assert result.visible_length == 50
    assert result.utf8_byte_length == 150


@pytest.mark.parametrize("raw", ["", b"", "        "])
def test_empty_or_whitespace_only_is_rejected(
    raw: str | bytes,
    policy: PasswordPolicy,
) -> None:
    result = policy.evaluate(raw)
    assert not result.allowed
    if raw:
        assert result.rule_id == RULE_TOO_SHORT
        assert result.visible_length == 0
    else:
        assert result.rule_id == RULE_EMPTY
        assert result.utf8_length == 0


def test_invalid_input_type_is_rejected(policy: PasswordPolicy) -> None:
    result = policy.evaluate(None)
    assert result.rule_id == "policy.invalid_input_type"
    assert result.normalized is None


@pytest.mark.parametrize(
    "raw",
    ["password123", "ＰＡＳＳＷＯＲＤ１２３", "Passw0rd"],
)
def test_builtin_weak_passwords_are_rejected(
    raw: str,
    policy: PasswordPolicy,
) -> None:
    result = policy.evaluate(raw)
    assert result.rule_id == RULE_WEAK_PASSWORD


def test_injectable_weak_password_callback_sees_normalized_value() -> None:
    seen: list[str] = []

    def is_weak(value: str) -> bool:
        seen.append(value)
        return value.endswith("-weak")

    policy = PasswordPolicy(weak_password_checker=is_weak)
    result = policy.evaluate("ｈｅｒｍｉｎｅｔｉｎｃｔｕｒｅ－ｗｅａｋ")

    assert result.rule_id == RULE_WEAK_PASSWORD
    assert seen == ["herminetincture-weak"]


def test_custom_weak_password_list_is_normalized() -> None:
    policy = PasswordPolicy(
        weak_passwords=["ｃｕｓｔｏｍ－ｗｅａｋ"],
        include_default_weak_passwords=False,
    )
    result = policy.evaluate("ｃｕｓｔｏｍ－ｗｅａｋ")
    assert result.rule_id == RULE_WEAK_PASSWORD


def test_weak_password_callback_failure_fails_closed_without_plaintext() -> None:
    raw = "herminetincture"

    def broken(value: str) -> bool:
        raise RuntimeError(f"callback leaked {value}")  # noqa: TRY003 - test fixture

    policy = PasswordPolicy(weak_password_checker=broken)
    result = policy.evaluate(raw)

    assert result.rule_id == RULE_WEAK_CHECKER_ERROR
    assert raw not in result.reason
    assert raw not in str(result.audit_event("api"))


@pytest.mark.parametrize(
    "raw",
    [
        "密码安全测试口令",
        "كلمةالمرور",
        "парольбезопасность",
        "安全なパスワードです",
    ],
)
def test_valid_multilingual_passwords_are_accepted(
    raw: str,
    policy: PasswordPolicy,
) -> None:
    result = policy.evaluate(raw)
    assert result.allowed
    assert result.normalized == raw
    assert result.visible_length >= 8


def test_three_entrypoints_share_the_same_decision(policy: PasswordPolicy) -> None:
    raw = _FULLWIDTH_VALID
    results = [
        policy.evaluate(raw, entrypoint=entrypoint)
        for entrypoint in ("desktop", "mobile", "api")
    ]

    assert results[0] == results[1] == results[2]
    assert {result.normalized for result in results} == {_VALID}
    assert {result.allowed for result in results} == {True}

    events = [result.audit_event() for result in results]
    assert {event["entrypoint"] for event in events} == {
        "desktop",
        "mobile",
        "api",
    }
    assert {event["rule_id"] for event in events} == {"policy.accepted"}
    assert {event["input_length_range"] for event in events} == {"8-15"}


def test_rejected_password_never_reaches_hasher(policy: PasswordPolicy) -> None:
    raw = "abcd" + "\u200b" * 100
    result = policy.evaluate(raw)
    assert result.is_rejected

    class SpyHasher:
        def __init__(self) -> None:
            self.hash_calls: list[str | bytes] = []

        @classmethod
        def identify(cls, hash: str | bytes) -> bool:
            return str(hash).startswith("spy$")

        def hash(self, password: str | bytes, *, salt: bytes | None = None) -> str:
            self.hash_calls.append(password)
            return "spy$" + str(password)

        def verify(self, password: str | bytes, hash: str | bytes) -> bool:
            return False

        def check_needs_rehash(self, hash: str | bytes) -> bool:
            return False

    spy = SpyHasher()
    password_hash = PasswordHash((spy,))

    if result.allowed:
        password_hash.hash(result.normalized)  # type: ignore[arg-type]
    assert spy.hash_calls == []

    with pytest.raises(PasswordPolicyError):
        policy.enforce(raw, entrypoint="registration-api")
    assert spy.hash_calls == []


def test_error_and_audit_never_include_plaintext(policy: PasswordPolicy) -> None:
    raw = "abcd" + "\u200b" * 100
    result = policy.evaluate(raw, entrypoint="desktop-web")
    event = result.audit_event()
    serialized = json.dumps(event, ensure_ascii=False)

    assert event["rule_id"] == RULE_ZERO_WIDTH_CHARACTER
    assert event["entrypoint"] == "desktop-web"
    assert event["input_length_range"] == "64-127"
    assert raw not in serialized
    assert "abcd" not in serialized
    assert result.normalized not in repr(result)

    with pytest.raises(PasswordPolicyError) as exc_info:
        policy.enforce(raw, entrypoint="mobile-app")
    error = exc_info.value
    assert error.rule_id == RULE_ZERO_WIDTH_CHARACTER
    assert error.entrypoint == "mobile-app"
    assert error.input_length_range == "64-127"
    assert raw not in str(error)
    assert "abcd" not in str(error)


def test_legacy_password_hash_still_verifies_original_password() -> None:
    password_hash = PasswordHash((Argon2Hasher(),))
    stored_hash = password_hash.hash(_FULLWIDTH_VALID)

    assert password_hash.verify(_FULLWIDTH_VALID, stored_hash)
    assert not password_hash.verify(_VALID, stored_hash)


def test_policy_does_not_change_password_hash_defaults() -> None:
    password_hash = PasswordHash((Argon2Hasher(),))
    stored_hash = password_hash.hash(_VALID)
    assert password_hash.verify(_VALID, stored_hash)
    # The policy is not wired into PasswordHash: the full-width variant differs.
    assert not password_hash.verify(_FULLWIDTH_VALID, stored_hash)
