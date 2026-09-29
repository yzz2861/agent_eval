import threading
from dataclasses import FrozenInstanceError
from datetime import timedelta

import pytest

import jwt
from jwt import ProfileRegistry, ValidationProfile
from jwt.exceptions import (
    ExpiredSignatureError,
    InvalidAlgorithmError,
    InvalidAudienceError,
    InvalidSignatureError,
    InvalidTokenError,
    InvalidTypError,
    MissingRequiredClaimError,
    TokenTooOldError,
    TrustDomainError,
    UnknownIssuerError,
    UnknownKeyError,
)

from .utils import utc_timestamp

ISSUER_A = "https://issuer-a.example.com"
ISSUER_B = "https://issuer-b.example.com"
SECRET_A = "issuer-a-secret-that-is-long-enough"
SECRET_B = "issuer-b-secret-that-is-long-enough"


def make_profile(**overrides) -> ValidationProfile:
    kwargs = {
        "issuer": ISSUER_A,
        "algorithms": ["HS256"],
        "audience": "my-api",
        "key": SECRET_A,
    }
    kwargs.update(overrides)
    return ValidationProfile(**kwargs)


def make_token(secret=SECRET_A, headers=None, **claims) -> str:
    payload = {
        "iss": ISSUER_A,
        "aud": "my-api",
        "sub": "user-1",
        "iat": utc_timestamp(),
        "exp": utc_timestamp() + 300,
    }
    payload.update(claims)
    return jwt.encode(payload, secret, algorithm="HS256", headers=headers)


@pytest.fixture
def registry() -> ProfileRegistry:
    return ProfileRegistry([make_profile()])


class TestValidationProfile:
    def test_decode_happy_path(self):
        profile = make_profile()
        token = make_token()
        payload = profile.decode(token)
        assert payload["iss"] == ISSUER_A
        assert payload["sub"] == "user-1"

    def test_profile_is_immutable(self):
        profile = make_profile()
        with pytest.raises(FrozenInstanceError):
            profile.issuer = "other"
        with pytest.raises(TypeError):
            profile.keys["kid"] = "key"

    def test_mutable_constructor_args_are_copied(self):
        keys = {"k1": SECRET_A}
        algorithms = ["HS256"]
        profile = make_profile(keys=keys, algorithms=algorithms, key=None)
        keys["k2"] = "attacker-key"
        algorithms.append("none")
        assert "k2" not in profile.keys
        assert profile.algorithms == ("HS256",)

    def test_sequences_are_normalized(self):
        profile = make_profile(
            audience="my-api",
            required_claims=["exp"],
            leeway=timedelta(seconds=10),
            max_age=timedelta(minutes=5),
        )
        assert profile.audience == ("my-api",)
        assert profile.required_claims == ("exp",)
        assert profile.leeway == 10.0
        assert profile.max_age == 300.0

    def test_requires_key_material(self):
        with pytest.raises(ValueError, match="key"):
            make_profile(key=None)

    def test_requires_algorithms(self):
        with pytest.raises(ValueError, match="algorithms"):
            make_profile(algorithms=[])

    def test_requires_issuer(self):
        with pytest.raises(TypeError, match="issuer"):
            make_profile(issuer="")

    def test_wrong_signature_is_in_domain_failure(self):
        profile = make_profile()
        token = make_token(secret="attacker-secret-that-is-long-enough")
        with pytest.raises(InvalidSignatureError) as exc_info:
            profile.decode(token)
        assert not isinstance(exc_info.value, TrustDomainError)

    def test_algorithm_confusion_rejected(self):
        profile = make_profile()
        token = jwt.encode(
            {"iss": ISSUER_A, "aud": "my-api"}, SECRET_A, algorithm="HS512"
        )
        with pytest.raises(InvalidAlgorithmError):
            profile.decode(token)

    def test_audience_mismatch(self):
        profile = make_profile()
        token = make_token(aud="other-api")
        with pytest.raises(InvalidAudienceError):
            profile.decode(token)

    def test_issuer_mismatch(self):
        profile = make_profile()
        token = make_token(iss="https://evil.example.com")
        with pytest.raises(jwt.InvalidIssuerError):
            profile.decode(token)

    def test_required_claims(self):
        profile = make_profile(required_claims=["exp", "jti"])
        token = make_token()
        with pytest.raises(MissingRequiredClaimError) as exc_info:
            profile.decode(token)
        assert exc_info.value.claim == "jti"

    def test_typ_accepted(self):
        profile = make_profile(typ="JWT")
        assert profile.decode(make_token())["iss"] == ISSUER_A

    def test_typ_mismatch(self):
        profile = make_profile(typ="at+jwt")
        with pytest.raises(InvalidTypError):
            profile.decode(make_token())

    def test_max_age(self):
        profile = make_profile(max_age=60)
        old_token = make_token(iat=utc_timestamp() - 3600)
        with pytest.raises(TokenTooOldError):
            profile.decode(old_token)
        assert profile.decode(make_token())["iss"] == ISSUER_A

    def test_max_age_requires_iat(self):
        profile = make_profile(max_age=60)
        token = jwt.encode(
            {"iss": ISSUER_A, "aud": "my-api", "exp": utc_timestamp() + 300},
            SECRET_A,
            algorithm="HS256",
        )
        with pytest.raises(MissingRequiredClaimError) as exc_info:
            profile.decode(token)
        assert exc_info.value.claim == "iat"

    def test_leeway_applies_to_exp_and_max_age(self):
        profile = make_profile(leeway=30, max_age=60)
        token = make_token(
            iat=utc_timestamp() - 75,  # older than max_age, within leeway
            exp=utc_timestamp() - 15,  # expired, within leeway
        )
        assert profile.decode(token)["iss"] == ISSUER_A

        strict_profile = make_profile(max_age=60)
        fresh_token = make_token(iat=utc_timestamp() - 75)
        with pytest.raises(TokenTooOldError):
            strict_profile.decode(fresh_token)

    def test_expired_beyond_leeway(self):
        profile = make_profile(leeway=10)
        token = make_token(exp=utc_timestamp() - 60)
        with pytest.raises(ExpiredSignatureError):
            profile.decode(token)

    def test_kid_resolution(self):
        profile = make_profile(key=None, keys={"k1": SECRET_A})
        token = make_token(headers={"kid": "k1"})
        assert profile.decode(token)["iss"] == ISSUER_A

    def test_unknown_kid_rejected(self):
        profile = make_profile(key=None, keys={"k1": SECRET_A})
        token = make_token(headers={"kid": "k2"})
        with pytest.raises(UnknownKeyError):
            profile.decode(token)

    def test_missing_kid_with_key_map_only(self):
        profile = make_profile(key=None, keys={"k1": SECRET_A})
        token = make_token()
        with pytest.raises(UnknownKeyError):
            profile.decode(token)

    def test_default_key_used_without_kid(self):
        profile = make_profile(keys={"k1": "other-secret-that-is-long-enough"})
        token = make_token()
        assert profile.decode(token)["iss"] == ISSUER_A


class TestProfileRegistry:
    def test_decode_selects_profile_by_issuer(self, registry):
        payload = registry.decode(make_token())
        assert payload["iss"] == ISSUER_A

    def test_unknown_issuer_rejected(self, registry):
        token = make_token(iss="https://unknown.example.com")
        with pytest.raises(UnknownIssuerError):
            registry.decode(token)

    def test_missing_issuer_rejected(self, registry):
        token = jwt.encode({"aud": "my-api"}, SECRET_A, algorithm="HS256")
        with pytest.raises(UnknownIssuerError):
            registry.decode(token)

    def test_unknown_issuer_is_trust_domain_error(self, registry):
        token = make_token(iss="https://unknown.example.com")
        with pytest.raises(TrustDomainError):
            registry.decode(token)
        # Trust-domain mismatch is distinguishable from in-domain failures
        assert issubclass(UnknownIssuerError, TrustDomainError)
        assert issubclass(TrustDomainError, InvalidTokenError)
        assert not issubclass(InvalidSignatureError, TrustDomainError)

    def test_in_domain_failure_is_not_trust_domain_error(self, registry):
        token = make_token(secret="attacker-secret-that-is-long-enough")
        with pytest.raises(InvalidSignatureError) as exc_info:
            registry.decode(token)
        assert not isinstance(exc_info.value, TrustDomainError)

    def test_kid_isolation_between_issuers(self):
        # Same kid, different keys per issuer: fully isolated key spaces.
        registry = ProfileRegistry(
            [
                make_profile(key=None, keys={"shared-kid": SECRET_A}),
                make_profile(
                    issuer=ISSUER_B,
                    audience="my-api",
                    key=None,
                    keys={"shared-kid": SECRET_B},
                ),
            ]
        )
        token_a = make_token(headers={"kid": "shared-kid"})
        token_b = make_token(
            secret=SECRET_B, iss=ISSUER_B, headers={"kid": "shared-kid"}
        )
        assert registry.decode(token_a)["iss"] == ISSUER_A
        assert registry.decode(token_b)["iss"] == ISSUER_B
        # A token signed with B's key but claiming issuer A fails in A's domain
        forged = make_token(secret=SECRET_B, headers={"kid": "shared-kid"})
        with pytest.raises(InvalidSignatureError):
            registry.decode(forged)

    def test_unverified_iss_cannot_relax_algorithms(self, registry):
        # "none" alg tokens are rejected even though decode() is profile-driven
        token = jwt.encode({"iss": ISSUER_A, "aud": "my-api"}, "", algorithm="none")
        with pytest.raises(InvalidTokenError):
            registry.decode(token)

    def test_register_replaces_profile_atomically(self, registry):
        old_profile = registry.get(ISSUER_A)
        new_secret = "rotated-secret-that-is-long-enough"
        registry.register(make_profile(key=new_secret))

        # In-flight validation holding the old profile still sees the
        # complete old version.
        old_token = make_token()
        assert old_profile.decode(old_token)["iss"] == ISSUER_A

        # New decodes go through the new profile only.
        new_token = make_token(secret=new_secret)
        assert registry.decode(new_token)["iss"] == ISSUER_A
        with pytest.raises(InvalidSignatureError):
            registry.decode(old_token)

    def test_unregister(self, registry):
        registry.unregister(ISSUER_A)
        assert ISSUER_A not in registry
        with pytest.raises(UnknownIssuerError):
            registry.decode(make_token())

    def test_register_rejects_non_profile(self, registry):
        with pytest.raises(TypeError):
            registry.register("not-a-profile")

    def test_issuers_snapshot(self, registry):
        assert registry.issuers == (ISSUER_A,)
        registry.register(make_profile(issuer=ISSUER_B))
        assert set(registry.issuers) == {ISSUER_A, ISSUER_B}
        assert len(registry) == 2

    def test_concurrent_register_and_decode(self):
        # Decoders always see one complete profile version, never a
        # half-updated one, while another thread rotates profiles.
        registry = ProfileRegistry([make_profile()])
        secrets = [f"rotated-secret-{i}-long-enough" for i in range(10)]
        tokens = {secret: make_token(secret=secret) for secret in [SECRET_A, *secrets]}
        errors = []

        def rotate():
            for secret in secrets:
                registry.register(make_profile(key=secret))

        def validate():
            try:
                for _ in range(50):
                    snapshot = registry.get(ISSUER_A)
                    token = tokens[snapshot.key]
                    snapshot.decode(token)
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)

        rotator = threading.Thread(target=rotate)
        readers = [threading.Thread(target=validate) for _ in range(4)]
        rotator.start()
        for reader in readers:
            reader.start()
        rotator.join()
        for reader in readers:
            reader.join()
        assert not errors


class TestLegacyDecodeUnchanged:
    def test_plain_decode_still_works(self):
        token = jwt.encode({"some": "payload"}, "secret", algorithm="HS256")
        assert jwt.decode(token, "secret", algorithms=["HS256"]) == {"some": "payload"}

    def test_decode_without_profiles_is_unaffected(self):
        token = make_token()
        payload = jwt.decode(
            token,
            SECRET_A,
            algorithms=["HS256"],
            audience="my-api",
            issuer=ISSUER_A,
        )
        assert payload["sub"] == "user-1"
