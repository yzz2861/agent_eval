import dataclasses

import pytest

from pwdlib import Argon2VerificationPolicy, PolicyViolationReason
from pwdlib.exceptions import HashVerificationPolicyError
from pwdlib.hashers.argon2 import Argon2Hasher

_PASSWORD = "herminetincture"

_HASHER = Argon2Hasher()
_HASH_STR = _HASHER.hash(_PASSWORD)

ARGON2ID_HASH_STR = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$Hnm7B2p4pnTo3mQ5qFmnHjR1OZBtVXd1B33joTc/XXg"
ARGON2D_HASH_STR = "$argon2d$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$P4FC8mhbA5awaolU7A6SOIr+vDJ+AvOcuryWUDzrdcI"
ARGON2I_HASH_STR = "$argon2i$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$WJ38Rw8Y82z6oLJyORBTspC2tAIryIkb1harNHedEPM"


def _replace_param(hash: str, name: str, value: int) -> str:
    parts = hash.split("$")
    params = parts[3].split(",")
    parts[3] = ",".join(
        f"{name}={value}" if item.startswith(f"{name}=") else item for item in params
    )
    return "$".join(parts)


@pytest.fixture
def policy_hasher() -> Argon2Hasher:
    return Argon2Hasher(verification_policy=Argon2VerificationPolicy())


@pytest.fixture
def backend_spy(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []
    from argon2 import PasswordHasher

    original_verify = PasswordHasher.verify

    def spy(self, hash, password):  # type: ignore[no-untyped-def]
        calls.append(hash)
        return original_verify(self, hash, password)

    monkeypatch.setattr(PasswordHasher, "verify", spy)
    return calls


def test_default_hasher_has_no_policy() -> None:
    assert Argon2Hasher().verification_policy is None


def test_policy_attached_to_hasher() -> None:
    policy = Argon2VerificationPolicy()
    hasher = Argon2Hasher(verification_policy=policy)
    assert hasher.verification_policy is policy


def test_with_verification_policy_preserves_parameters() -> None:
    hasher = Argon2Hasher(
        time_cost=5, memory_cost=131072, parallelism=2, hash_len=40, salt_len=24
    )
    policy = Argon2VerificationPolicy(max_memory_cost=131072, max_time_cost=5)
    guarded = hasher.with_verification_policy(policy)
    assert guarded.verification_policy is policy
    assert guarded._time_cost == 5
    assert guarded._memory_cost == 131072
    assert guarded._parallelism == 2
    assert guarded._hash_len == 40
    assert guarded._salt_len == 24


@pytest.mark.parametrize(
    "field", [f.name for f in dataclasses.fields(Argon2VerificationPolicy)]
)
def test_policy_rejects_non_positive_integers(field: str) -> None:
    with pytest.raises(ValueError):
        Argon2VerificationPolicy(**{field: 0})
    with pytest.raises(TypeError):
        Argon2VerificationPolicy(**{field: 1.5})  # type: ignore[arg-type]


def test_policy_accepts_valid_hash(
    policy_hasher: Argon2Hasher, backend_spy: list[str]
) -> None:
    assert policy_hasher.verify(_PASSWORD, _HASH_STR) is True
    assert len(backend_spy) == 1


def test_policy_wrong_password_returns_false(
    policy_hasher: Argon2Hasher, backend_spy: list[str]
) -> None:
    assert policy_hasher.verify("INVALID_PASSWORD", _HASH_STR) is False
    assert len(backend_spy) == 1


@pytest.mark.parametrize(
    "variant_hash",
    [ARGON2ID_HASH_STR, ARGON2I_HASH_STR, ARGON2D_HASH_STR],
)
def test_policy_all_argon2_variants_still_verify(
    variant_hash: str,
    policy_hasher: Argon2Hasher,
    backend_spy: list[str],
) -> None:
    assert policy_hasher.verify(_PASSWORD, variant_hash) is True
    assert len(backend_spy) == 1


def test_malicious_memory_cost_blocked_before_backend(
    policy_hasher: Argon2Hasher, backend_spy: list[str]
) -> None:
    evil = _replace_param(_HASH_STR, "m", 4194304)
    with pytest.raises(HashVerificationPolicyError) as exc_info:
        policy_hasher.verify(_PASSWORD, evil)
    assert exc_info.value.reason == PolicyViolationReason.MEMORY_COST
    assert "argon2" not in str(exc_info.value)
    assert evil not in str(exc_info.value)
    assert backend_spy == []


def test_malicious_time_cost_blocked_before_backend(
    policy_hasher: Argon2Hasher, backend_spy: list[str]
) -> None:
    evil = _replace_param(_HASH_STR, "t", 999)
    with pytest.raises(HashVerificationPolicyError) as exc_info:
        policy_hasher.verify(_PASSWORD, evil)
    assert exc_info.value.reason == PolicyViolationReason.TIME_COST
    assert evil not in str(exc_info.value)
    assert backend_spy == []


def test_malicious_parallelism_blocked_before_backend(
    policy_hasher: Argon2Hasher, backend_spy: list[str]
) -> None:
    evil = _replace_param(_HASH_STR, "p", 64)
    with pytest.raises(HashVerificationPolicyError) as exc_info:
        policy_hasher.verify(_PASSWORD, evil)
    assert exc_info.value.reason == PolicyViolationReason.PARALLELISM
    assert evil not in str(exc_info.value)
    assert backend_spy == []


def test_oversized_salt_blocked_before_backend(
    policy_hasher: Argon2Hasher, backend_spy: list[str]
) -> None:
    long_salt = "c29tZXNhbHQ" * 4  # 40 encoded chars -> 30 decoded bytes
    parts = _HASH_STR.split("$")
    parts[4] = long_salt
    evil = "$".join(parts)
    with pytest.raises(HashVerificationPolicyError) as exc_info:
        policy_hasher.verify(_PASSWORD, evil)
    assert exc_info.value.reason == PolicyViolationReason.SALT_LEN
    assert evil not in str(exc_info.value)
    assert backend_spy == []


def test_oversized_digest_blocked_before_backend(
    policy_hasher: Argon2Hasher, backend_spy: list[str]
) -> None:
    long_digest = "Hnm7B2p4pnTo3mQ5qFmnHjR1OZBtVXd1B33joTc" * 2
    parts = _HASH_STR.split("$")
    parts[5] = long_digest
    evil = "$".join(parts)
    with pytest.raises(HashVerificationPolicyError) as exc_info:
        policy_hasher.verify(_PASSWORD, evil)
    assert exc_info.value.reason == PolicyViolationReason.HASH_LEN
    assert evil not in str(exc_info.value)
    assert backend_spy == []


def test_oversized_encoded_hash_blocked_before_backend(
    backend_spy: list[str],
) -> None:
    with open("tests/data/argon2id_large_hash", "rb") as large_hash_file:
        large_hash = large_hash_file.read().decode("ascii")
    hasher = Argon2Hasher(
        verification_policy=Argon2VerificationPolicy(max_encoded_size=128)
    )
    with pytest.raises(HashVerificationPolicyError) as exc_info:
        hasher.verify(_PASSWORD, large_hash)
    assert exc_info.value.reason == PolicyViolationReason.ENCODED_SIZE
    assert large_hash not in str(exc_info.value)
    assert backend_spy == []


def test_multiple_violations_report_stable_first_reason(
    policy_hasher: Argon2Hasher, backend_spy: list[str]
) -> None:
    evil = _replace_param(_HASH_STR, "m", 4194304)
    evil = _replace_param(evil, "t", 999)
    evil = _replace_param(evil, "p", 64)
    with pytest.raises(HashVerificationPolicyError) as exc_info:
        policy_hasher.verify(_PASSWORD, evil)
    assert exc_info.value.reason == PolicyViolationReason.MEMORY_COST
    assert backend_spy == []


def test_legacy_high_cost_hash_verified_when_within_budget(
    backend_spy: list[str],
) -> None:
    legacy_hasher = Argon2Hasher(memory_cost=131072, time_cost=5)
    legacy_hash = legacy_hasher.hash(_PASSWORD)
    policy = Argon2VerificationPolicy(max_memory_cost=131072, max_time_cost=5)
    guarded = Argon2Hasher(verification_policy=policy)
    assert guarded.verify(_PASSWORD, legacy_hash) is True
    assert len(backend_spy) == 1


def test_legacy_high_cost_hash_returns_migration_result_above_budget(
    backend_spy: list[str],
) -> None:
    legacy_hasher = Argon2Hasher(memory_cost=131072, time_cost=5)
    legacy_hash = legacy_hasher.hash(_PASSWORD)
    guarded = Argon2Hasher(verification_policy=Argon2VerificationPolicy())
    with pytest.raises(HashVerificationPolicyError) as exc_info:
        guarded.verify(_PASSWORD, legacy_hash)
    assert exc_info.value.reason == PolicyViolationReason.MEMORY_COST
    assert backend_spy == []


def test_legacy_high_parallelism_accepted_with_relaxed_budget(
    backend_spy: list[str],
) -> None:
    legacy_hasher = Argon2Hasher(parallelism=8)
    legacy_hash = legacy_hasher.hash(_PASSWORD)
    relaxed = Argon2Hasher(
        verification_policy=Argon2VerificationPolicy(max_parallelism=8)
    )
    assert relaxed.verify(_PASSWORD, legacy_hash) is True
    assert len(backend_spy) == 1

    strict = Argon2Hasher(verification_policy=Argon2VerificationPolicy())
    with pytest.raises(HashVerificationPolicyError) as exc_info:
        strict.verify(_PASSWORD, legacy_hash)
    assert exc_info.value.reason == PolicyViolationReason.PARALLELISM
    assert len(backend_spy) == 1


def test_missing_params_hash_not_sent_to_backend(
    policy_hasher: Argon2Hasher, backend_spy: list[str]
) -> None:
    missing_param_hash = "$argon2id$v=19$m=65536,p=4$c29tZXNhbHQ$Hnm7B2p4"
    assert policy_hasher.verify(_PASSWORD, missing_param_hash) is False
    assert backend_spy == []


def test_hash_without_salt_or_digest_not_sent_to_backend(
    policy_hasher: Argon2Hasher, backend_spy: list[str]
) -> None:
    incomplete_hash = "$argon2id$v=19$m=65536,t=3,p=4"
    with pytest.raises(HashVerificationPolicyError) as exc_info:
        policy_hasher.verify(_PASSWORD, incomplete_hash)
    assert exc_info.value.reason == PolicyViolationReason.MISSING_COMPONENTS
    assert backend_spy == []


def test_default_mode_does_not_enforce_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hasher = Argon2Hasher()
    calls: list[str] = []
    from argon2 import PasswordHasher

    original_verify = PasswordHasher.verify

    def spy(self, hash, password):  # type: ignore[no-untyped-def]
        calls.append(hash)
        return original_verify(self, hash, password)

    monkeypatch.setattr(PasswordHasher, "verify", spy)
    evil = _replace_param(_HASH_STR, "m", 4194304)
    # No policy: the backend receives the hash and the mismatch (the tampered
    # parameters change the derived digest) yields False instead of a policy error.
    assert hasher.verify(_PASSWORD, evil) is False
    assert len(calls) == 1


def test_policy_error_never_contains_raw_hash(
    policy_hasher: Argon2Hasher,
) -> None:
    evil = _replace_param(_HASH_STR, "m", 4194304)
    with pytest.raises(HashVerificationPolicyError) as exc_info:
        policy_hasher.verify(_PASSWORD, evil)
    assert evil not in exc_info.value.message
    assert repr(evil) not in repr(exc_info.value)


def test_policy_check_unrecognized_hash() -> None:
    policy = Argon2VerificationPolicy()
    with pytest.raises(HashVerificationPolicyError) as exc_info:
        policy.check("not-an-argon2-hash")
    assert exc_info.value.reason == PolicyViolationReason.UNRECOGNIZED_HASH
    assert "argon2" not in str(exc_info.value)


def test_policy_verify_invalid_utf8_bytes_returns_false(
    policy_hasher: Argon2Hasher, backend_spy: list[str]
) -> None:
    assert policy_hasher.verify(_PASSWORD, b"\xc3\x28") is False
    assert backend_spy == []
