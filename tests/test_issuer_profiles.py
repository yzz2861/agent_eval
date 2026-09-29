from __future__ import annotations

import dataclasses
import json
import threading
import time
from unittest.mock import patch
from datetime import timedelta

import pytest

import jwt
from jwt import (
    IssuerProfile,
    IssuerProfileDecoder,
    IssuerProfileRegistry,
)
from jwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    InvalidAlgorithmError,
    InvalidAudienceError,
    InvalidSignatureError,
    InvalidTokenError,
    InvalidTokenTypeError,
    MissingRequiredClaimError,
    TokenTooOldError,
    UnknownIssuerError,
)
from jwt.utils import base64url_encode


def raw_token(payload):
    header = base64url_encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
    ).decode()
    body = base64url_encode(json.dumps(payload).encode()).decode()
    return f"{header}.{body}.invalid-signature"


ISSUER_A = "https://idp-a.example.com"
ISSUER_B = "https://idp-b.example.com"
SECRET_A = "secret-a"
SECRET_B = "secret-b"
SECRET_A_K2 = "secret-a-k2"
SECRET_B_K2 = "secret-b-k2"


def make_token(payload, *, secret=SECRET_A, algorithm="HS256", headers=None):
    return jwt.encode(payload, secret, algorithm=algorithm, headers=headers)


def base_claims(issuer, *, iat=None, exp_delta=60, aud="api-a", sub="user-1"):
    now = int(time.time())
    iat = now if iat is None else iat
    return {"iss": issuer, "aud": aud, "sub": sub, "iat": iat, "exp": iat + exp_delta}


def make_registry() -> IssuerProfileRegistry:
    profile_a = IssuerProfile(
        issuer=ISSUER_A,
        algorithms=("HS256",),
        audience="api-a",
        keys={"k1": SECRET_A, "k2": SECRET_A_K2},
        required_claims=("exp", "iat", "sub"),
        typ=("JWT",),
        max_token_age=300,
        leeway=5,
    )
    profile_b = IssuerProfile(
        issuer=ISSUER_B,
        algorithms=("HS512",),
        audience="api-b",
        keys={"k1": SECRET_B},
        required_claims=("exp", "sub"),
    )
    return IssuerProfileRegistry([profile_a, profile_b])


def test_decode_success_with_per_issuer_settings():
    decoder = IssuerProfileDecoder(make_registry())

    token_a = make_token(base_claims(ISSUER_A), headers={"kid": "k1"})
    claims_a = decoder.decode(token_a)
    assert claims_a["iss"] == ISSUER_A

    token_b = make_token(
        base_claims(ISSUER_B, aud="api-b"),
        secret=SECRET_B,
        algorithm="HS512",
        headers={"kid": "k1"},
    )
    claims_b = decoder.decode(token_b)
    assert claims_b["iss"] == ISSUER_B


def test_decode_complete_returns_header_payload_signature():
    decoder = IssuerProfileDecoder(make_registry())
    token = make_token(base_claims(ISSUER_A), headers={"kid": "k1"})
    decoded = decoder.decode_complete(token)
    assert set(decoded) == {"header", "payload", "signature"}
    assert decoded["header"]["kid"] == "k1"
    assert decoded["payload"]["iss"] == ISSUER_A
    assert decoded["signature"]


def test_unknown_issuer_is_rejected():
    decoder = IssuerProfileDecoder(make_registry())
    token = make_token(base_claims("https://evil.example.com"))
    with pytest.raises(UnknownIssuerError) as exc_info:
        decoder.decode(token)
    assert "not registered" in str(exc_info.value)


def test_missing_or_invalid_iss_is_rejected():
    decoder = IssuerProfileDecoder(make_registry())

    claims = base_claims(ISSUER_A)
    del claims["iss"]
    with pytest.raises(UnknownIssuerError):
        decoder.decode(raw_token(claims))

    with pytest.raises(UnknownIssuerError):
        decoder.decode(raw_token({"iss": 123}))


def test_wrong_audience_is_in_domain_failure_not_unknown_issuer():
    decoder = IssuerProfileDecoder(make_registry())
    token = make_token(base_claims(ISSUER_A, aud="other-api"), headers={"kid": "k1"})
    with pytest.raises(InvalidAudienceError):
        decoder.decode(token)


def test_bad_signature_is_in_domain_failure():
    decoder = IssuerProfileDecoder(make_registry())
    token = make_token(base_claims(ISSUER_A), secret=SECRET_B, headers={"kid": "k1"})
    with pytest.raises(InvalidSignatureError):
        decoder.decode(token)


def test_algorithm_header_cannot_relax_allowed_algorithms():
    decoder = IssuerProfileDecoder(make_registry())
    token = make_token(
        base_claims(ISSUER_A),
        algorithm="HS512",
        headers={"kid": "k1"},
    )
    with pytest.raises(InvalidAlgorithmError):
        decoder.decode(token)


def test_same_kid_is_isolated_per_issuer():
    registry = IssuerProfileRegistry(
        [
            IssuerProfile(
                issuer=ISSUER_A,
                algorithms=("HS256",),
                audience="api-a",
                keys={"shared": SECRET_A_K2},
            ),
            IssuerProfile(
                issuer=ISSUER_B,
                algorithms=("HS256",),
                audience="api-b",
                keys={"shared": SECRET_B_K2},
            ),
        ]
    )
    decoder = IssuerProfileDecoder(registry)

    token_a = make_token(
        base_claims(ISSUER_A),
        secret=SECRET_A_K2,
        headers={"kid": "shared"},
    )
    token_b = make_token(
        base_claims(ISSUER_B, aud="api-b"),
        secret=SECRET_B_K2,
        headers={"kid": "shared"},
    )

    assert decoder.decode(token_a)["iss"] == ISSUER_A
    assert decoder.decode(token_b)["iss"] == ISSUER_B

    with pytest.raises(InvalidSignatureError):
        decoder.decode(
            make_token(
                base_claims(ISSUER_A),
                secret=SECRET_B_K2,
                headers={"kid": "shared"},
            )
        )


def test_unknown_kid_is_rejected():
    decoder = IssuerProfileDecoder(make_registry())
    token = make_token(base_claims(ISSUER_A), headers={"kid": "missing"})
    with pytest.raises(DecodeError, match="is not registered"):
        decoder.decode(token)


def test_default_key_is_used_without_kid():
    profile = IssuerProfile(
        issuer=ISSUER_A,
        algorithms=("HS256",),
        audience="api-a",
        default_key=SECRET_A,
    )
    decoder = IssuerProfileDecoder(IssuerProfileRegistry([profile]))
    token = make_token(base_claims(ISSUER_A))
    assert decoder.decode(token)["iss"] == ISSUER_A


def test_missing_kid_without_default_key_is_rejected():
    decoder = IssuerProfileDecoder(make_registry())
    token = make_token(base_claims(ISSUER_A))
    with pytest.raises(DecodeError, match="no 'kid'"):
        decoder.decode(token)


def test_typ_header_is_checked():
    decoder = IssuerProfileDecoder(make_registry())

    bad_typ = make_token(
        base_claims(ISSUER_A),
        headers={"kid": "k1", "typ": "at+jwt"},
    )
    with pytest.raises(InvalidTokenTypeError):
        decoder.decode(bad_typ)

    good_typ = make_token(
        base_claims(ISSUER_A),
        headers={"kid": "k1", "typ": "jwt"},
    )
    assert decoder.decode(good_typ)["iss"] == ISSUER_A


def test_typ_is_not_checked_when_unset():
    profile = IssuerProfile(
        issuer=ISSUER_B,
        algorithms=("HS512",),
        audience="api-b",
        keys={"k1": SECRET_B},
    )
    decoder = IssuerProfileDecoder(IssuerProfileRegistry([profile]))
    token = make_token(
        base_claims(ISSUER_B, aud="api-b"),
        secret=SECRET_B,
        algorithm="HS512",
        headers={"kid": "k1", "typ": "at+jwt"},
    )
    assert decoder.decode(token)["iss"] == ISSUER_B


def test_max_token_age_is_enforced():
    decoder = IssuerProfileDecoder(make_registry())
    now = int(time.time())

    fresh = make_token(
        base_claims(ISSUER_A, iat=now - 100, exp_delta=1000),
        headers={"kid": "k1"},
    )
    assert decoder.decode(fresh)["iss"] == ISSUER_A

    old = make_token(
        base_claims(ISSUER_A, iat=now - 400, exp_delta=1000),
        headers={"kid": "k1"},
    )
    with pytest.raises(TokenTooOldError):
        decoder.decode(old)

    claims = base_claims(ISSUER_A, iat=now - 400, exp_delta=1000)
    del claims["iat"]
    with pytest.raises(MissingRequiredClaimError, match="iat"):
        decoder.decode(make_token(claims, headers={"kid": "k1"}))


def test_max_token_age_respects_independent_leeway():
    profile = IssuerProfile(
        issuer=ISSUER_A,
        algorithms=("HS256",),
        audience="api-a",
        keys={"k1": SECRET_A},
        max_token_age=100,
        leeway=10,
    )
    decoder = IssuerProfileDecoder(IssuerProfileRegistry([profile]))
    now = int(time.time())
    within_leeway = make_token(
        base_claims(ISSUER_A, iat=now - 108, exp_delta=1000),
        headers={"kid": "k1"},
    )
    assert decoder.decode(within_leeway)["iss"] == ISSUER_A

    too_old = make_token(
        base_claims(ISSUER_A, iat=now - 112, exp_delta=1000),
        headers={"kid": "k1"},
    )
    with pytest.raises(TokenTooOldError):
        decoder.decode(too_old)


def test_leeway_applies_to_expiry_independently_per_profile():
    profile_a = IssuerProfile(
        issuer=ISSUER_A,
        algorithms=("HS256",),
        audience="api-a",
        keys={"k1": SECRET_A},
        leeway=30,
    )
    profile_b = IssuerProfile(
        issuer=ISSUER_B,
        algorithms=("HS512",),
        audience="api-b",
        keys={"k1": SECRET_B},
        leeway=0,
    )
    decoder = IssuerProfileDecoder(IssuerProfileRegistry([profile_a, profile_b]))
    now = int(time.time())

    token_a = make_token(
        base_claims(ISSUER_A, iat=now - 20, exp_delta=10),
        headers={"kid": "k1"},
    )
    assert decoder.decode(token_a)["iss"] == ISSUER_A

    token_b = make_token(
        base_claims(ISSUER_B, iat=now - 20, exp_delta=10, aud="api-b"),
        secret=SECRET_B,
        algorithm="HS512",
        headers={"kid": "k1"},
    )
    with pytest.raises(ExpiredSignatureError):
        decoder.decode(token_b)


def test_timedelta_values_are_accepted():
    profile = IssuerProfile(
        issuer=ISSUER_A,
        algorithms=("HS256",),
        audience="api-a",
        keys={"k1": SECRET_A},
        max_token_age=timedelta(minutes=5),
        leeway=timedelta(seconds=5),
    )
    decoder = IssuerProfileDecoder(IssuerProfileRegistry([profile]))
    token = make_token(base_claims(ISSUER_A), headers={"kid": "k1"})
    assert decoder.decode(token)["iss"] == ISSUER_A


def test_required_claims_are_enforced():
    decoder = IssuerProfileDecoder(make_registry())
    claims = base_claims(ISSUER_A)
    del claims["sub"]
    token = make_token(claims, headers={"kid": "k1"})
    with pytest.raises(MissingRequiredClaimError, match="sub"):
        decoder.decode(token)


def test_strict_aud_is_enforced():
    profile = IssuerProfile(
        issuer=ISSUER_A,
        algorithms=("HS256",),
        audience="api-a",
        keys={"k1": SECRET_A},
        strict_aud=True,
    )
    decoder = IssuerProfileDecoder(IssuerProfileRegistry([profile]))
    token = make_token(
        base_claims(ISSUER_A, aud=["api-a", "other"]),
        headers={"kid": "k1"},
    )
    with pytest.raises(InvalidAudienceError):
        decoder.decode(token)


def test_audience_is_not_verified_when_unset():
    profile = IssuerProfile(
        issuer=ISSUER_A,
        algorithms=("HS256",),
        keys={"k1": SECRET_A},
    )
    decoder = IssuerProfileDecoder(IssuerProfileRegistry([profile]))
    claims = {"iss": ISSUER_A, "sub": "user-1"}
    token = make_token(claims, headers={"kid": "k1"})
    assert decoder.decode(token) == claims


def test_profile_is_immutable():
    source_keys = {"k1": SECRET_A}
    profile = IssuerProfile(
        issuer=ISSUER_A,
        algorithms=["HS256"],
        audience=["api-a"],
        keys=source_keys,
        required_claims=["sub"],
    )

    with pytest.raises(dataclasses.FrozenInstanceError):
        profile.issuer = ISSUER_B

    source_keys["k1"] = SECRET_B
    assert profile.keys["k1"] == SECRET_A
    assert isinstance(profile.algorithms, tuple)
    assert isinstance(profile.required_claims, tuple)

    with pytest.raises(TypeError):
        profile.keys["k1"] = SECRET_B


def test_profile_construction_validates_arguments():
    with pytest.raises(ValueError):
        IssuerProfile(issuer="", algorithms=("HS256",), default_key="x")
    with pytest.raises(ValueError):
        IssuerProfile(issuer=ISSUER_A, algorithms=(), default_key="x")
    with pytest.raises(ValueError):
        IssuerProfile(issuer=ISSUER_A, algorithms=("HS256",))
    with pytest.raises(ValueError):
        IssuerProfile(
            issuer=ISSUER_A,
            algorithms=("HS256",),
            keys={1: SECRET_A},
        )
    with pytest.raises(ValueError):
        IssuerProfile(
            issuer=ISSUER_A,
            algorithms=("HS256",),
            default_key=SECRET_A,
            max_token_age=0,
        )


def test_registry_register_unregister_and_lookup():
    registry = IssuerProfileRegistry()
    profile = IssuerProfile(
        issuer=ISSUER_A,
        algorithms=("HS256",),
        keys={"k1": SECRET_A},
    )
    registry.register(profile)
    assert ISSUER_A in registry
    assert len(registry) == 1
    assert registry.get(ISSUER_A) is profile
    assert registry.get("missing") is None
    assert registry.issuers == (ISSUER_A,)

    registry.unregister(ISSUER_A)
    assert ISSUER_A not in registry
    with pytest.raises(KeyError):
        registry.unregister(ISSUER_A)


def test_registry_rejects_duplicate_profiles_in_constructor():
    profile = IssuerProfile(
        issuer=ISSUER_A,
        algorithms=("HS256",),
        keys={"k1": SECRET_A},
    )
    with pytest.raises(ValueError):
        IssuerProfileRegistry([profile, profile])

    with pytest.raises(TypeError):
        IssuerProfileRegistry([("not", "a", "profile")])  # type: ignore[list-item]


def test_registry_snapshot_is_a_consistent_version():
    registry = make_registry()
    snapshot = registry.snapshot()

    registry.register(
        IssuerProfile(
            issuer="https://idp-c.example.com",
            algorithms=("HS256",),
            keys={"k1": "secret-c"},
        )
    )
    registry.unregister(ISSUER_A)

    assert set(snapshot) == {ISSUER_A, ISSUER_B}
    with pytest.raises(TypeError):
        snapshot[ISSUER_A] = None


def test_registry_update_does_not_affect_inflight_request_versions():
    registry = IssuerProfileRegistry(
        [
            IssuerProfile(
                issuer=ISSUER_A,
                algorithms=("HS256",),
                audience="api-a",
                keys={"k1": SECRET_A},
            )
        ]
    )
    decoder = IssuerProfileDecoder(registry)

    old_version = registry.snapshot()
    registry.register(
        IssuerProfile(
            issuer=ISSUER_A,
            algorithms=("HS256",),
            audience="new-api",
            keys={"k1": "rotated-secret"},
        )
    )

    token = make_token(base_claims(ISSUER_A), headers={"kid": "k1"})
    # A request that captured its version before the update still validates
    # against the complete old profile.
    with patch.object(registry, "snapshot", return_value=old_version):
        assert decoder.decode(token)["aud"] == "api-a"
    assert old_version[ISSUER_A].keys["k1"] == SECRET_A

    # New requests observe the rotated profile.
    with pytest.raises(InvalidSignatureError):
        decoder.decode(token)


def test_registry_updates_are_visible_to_future_requests():
    registry = IssuerProfileRegistry(
        [
            IssuerProfile(
                issuer=ISSUER_A,
                algorithms=("HS256",),
                audience="api-a",
                keys={"k1": SECRET_A},
            )
        ]
    )
    decoder = IssuerProfileDecoder(registry)
    token = make_token(base_claims(ISSUER_A), headers={"kid": "k1"})
    assert decoder.decode(token)["aud"] == "api-a"

    registry.register(
        IssuerProfile(
            issuer=ISSUER_A,
            algorithms=("HS256",),
            audience="new-api",
            keys={"k1": "rotated-secret"},
        )
    )

    with pytest.raises(InvalidSignatureError):
        decoder.decode(token)

    rotated = make_token(
        base_claims(ISSUER_A, aud="new-api"),
        secret="rotated-secret",
        headers={"kid": "k1"},
    )
    assert decoder.decode(rotated)["aud"] == "new-api"


def test_concurrent_updates_and_decodes_are_consistent():
    registry = IssuerProfileRegistry(
        [
            IssuerProfile(
                issuer=ISSUER_A,
                algorithms=("HS256",),
                audience="api-a",
                keys={"k1": SECRET_A},
            )
        ]
    )
    decoder = IssuerProfileDecoder(registry)
    token = make_token(base_claims(ISSUER_A), headers={"kid": "k1"})
    errors = []
    stop = threading.Event()

    def writer():
        for index in range(200):
            registry.register(
                IssuerProfile(
                    issuer=f"https://idp-{index}.example.com",
                    algorithms=("HS256",),
                    keys={"k1": "secret"},
                )
            )
        stop.set()

    def reader():
        while not stop.is_set():
            try:
                claims = decoder.decode(token)
                assert claims["iss"] == ISSUER_A
                assert claims["aud"] == "api-a"
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)
                return

    threads = [threading.Thread(target=writer)]
    threads += [threading.Thread(target=reader) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []


def test_original_decode_interface_still_works():
    token = jwt.encode({"some": "payload"}, "secret", algorithm="HS256")
    assert jwt.decode(token, "secret", algorithms=["HS256"]) == {"some": "payload"}


def test_malformed_token_is_rejected():
    decoder = IssuerProfileDecoder(make_registry())
    with pytest.raises(DecodeError):
        decoder.decode("not-a-token")
    with pytest.raises(DecodeError):
        decoder.decode(123)  # type: ignore[arg-type]


def test_error_hierarchy_distinguishes_trust_domain_failures():
    assert issubclass(UnknownIssuerError, InvalidTokenError)
    assert issubclass(InvalidTokenTypeError, InvalidTokenError)
    assert issubclass(TokenTooOldError, InvalidTokenError)
