"""Tests for the RFC 9068 ``JWTBearerTokenValidator``.

The validation is split into five layers: signature trust, issuer binding,
token type and purpose, claim structure, and resource audience. Every
failure becomes a generic RFC 6750 ``invalid_token`` error for the client,
while the internal joserfc error keeps the failing claim for the audits.
"""

import json
import logging
import time

import pytest
from joserfc import jws
from joserfc import jwt
from joserfc.errors import InvalidClaimError
from joserfc.errors import MissingClaimError
from joserfc.jwk import KeySet
from joserfc.jwk import OctKey
from joserfc.jwk import RSAKey

from authlib.oauth2.rfc6750.errors import InvalidTokenError
from authlib.oauth2.rfc9068 import JWTBearerTokenValidator

ISSUER = "https://auth.example.com"
OTHER_ISSUER = "https://other-auth.example.com"
RESOURCE_SERVER = "https://api.example.com"


@pytest.fixture
def key():
    return OctKey.generate_key()


def _make_validator(key, **kwargs):
    class Validator(JWTBearerTokenValidator):
        def get_jwks(self, issuer=None):
            return key

    return Validator(issuer=ISSUER, resource_server=RESOURCE_SERVER, **kwargs)


def _base_claims(**overrides):
    claims = {
        "iss": ISSUER,
        "aud": RESOURCE_SERVER,
        "sub": "user-1",
        "client_id": "client-1",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "jti": "unique-jti",
    }
    claims.update(overrides)
    return claims


def _encode_token(key, claims=None, header=None):
    token_header = {"alg": "HS256", "typ": "at+jwt"}
    if header:
        token_header.update(header)
    return jwt.encode(token_header, claims or _base_claims(), key)


def _validate(validator, token_string, scopes=None):
    token = validator.authenticate_token(token_string)
    validator.validate_token(token, scopes, None)
    return token


# --- Layer 1: signature trust ------------------------------------------------


def test_valid_token():
    key = OctKey.generate_key()
    validator = _make_validator(key)

    token = _validate(validator, _encode_token(key))

    assert token["sub"] == "user-1"


def test_invalid_signature_raises_invalid_token_error():
    signing_key = OctKey.generate_key()
    validator = _make_validator(OctKey.generate_key())

    with pytest.raises(InvalidTokenError):
        validator.authenticate_token(_encode_token(signing_key))


def test_mismatched_kid_raises_invalid_token_error():
    """InvalidKeyIdError (not a subclass of DecodeError) must be caught."""
    key = RSAKey.generate_key(2048, private=True, parameters={"kid": "key-1"})
    validator = _make_validator(KeySet(keys=[key]))

    other_key = RSAKey.generate_key(2048, private=True, parameters={"kid": "key-999"})
    token_string = jwt.encode(
        {"alg": "RS256", "kid": "key-999", "typ": "at+jwt"},
        _base_claims(),
        other_key,
    )

    with pytest.raises(InvalidTokenError):
        validator.authenticate_token(token_string)


def test_garbage_token_raises_invalid_token_error():
    validator = _make_validator(OctKey.generate_key())

    with pytest.raises(InvalidTokenError):
        validator.authenticate_token("not.a.jwt")


@pytest.mark.parametrize(
    ("key_header", "value"),
    [
        ("jku", "https://attacker.example/keys.json"),
        ("jwk", {"kty": "oct", "k": "attacker"}),
    ],
)
def test_token_provided_key_header_is_never_trusted(key, key_header, value):
    header = {key_header: value}
    token_string = _encode_token(key, header=header)
    validator = _make_validator(key)

    with pytest.raises(InvalidTokenError):
        validator.authenticate_token(token_string)


# --- Layer 2: issuer binding -------------------------------------------------


def test_wrong_issuer_is_rejected(key):
    validator = _make_validator(key)
    token_string = _encode_token(key, _base_claims(iss="https://evil.example.com"))

    with pytest.raises(InvalidTokenError):
        _validate(validator, token_string)


def test_multi_issuer_selects_issuer_bound_key_and_audience():
    first_key = OctKey.generate_key()
    second_key = OctKey.generate_key()

    class Validator(JWTBearerTokenValidator):
        def get_jwks(self, issuer=None):
            return {ISSUER: first_key, OTHER_ISSUER: second_key}[issuer]

    validator = Validator(
        issuer={
            ISSUER: {"resource_server": RESOURCE_SERVER},
            OTHER_ISSUER: {"resource_server": "https://other-api.example.com"},
        }
    )

    token_string = _encode_token(
        second_key,
        _base_claims(
            iss=OTHER_ISSUER,
            aud="https://other-api.example.com",
        ),
    )
    token = _validate(validator, token_string)
    assert token["iss"] == OTHER_ISSUER


def test_multi_issuer_rejects_unknown_issuer(key):
    validator = JWTBearerTokenValidator(
        issuer={ISSUER: {"jwks": key, "resource_server": RESOURCE_SERVER}}
    )
    token_string = _encode_token(key, _base_claims(iss="https://unknown.example.com"))

    with pytest.raises(InvalidTokenError):
        validator.authenticate_token(token_string)


def test_cross_issuer_signature_is_rejected():
    issuer_key = OctKey.generate_key()
    foreign_key = OctKey.generate_key()
    validator = JWTBearerTokenValidator(
        issuer={
            ISSUER: {"jwks": issuer_key, "resource_server": RESOURCE_SERVER},
            OTHER_ISSUER: {"jwks": foreign_key, "resource_server": RESOURCE_SERVER},
        }
    )
    # The token claims to come from ISSUER but is signed with the other key.
    token_string = _encode_token(foreign_key, _base_claims(iss=ISSUER))

    with pytest.raises(InvalidTokenError):
        validator.authenticate_token(token_string)


def test_multi_issuer_supports_dynamic_get_jwks():
    first_key = OctKey.generate_key()
    second_key = OctKey.generate_key()
    key_sets = {ISSUER: first_key, OTHER_ISSUER: second_key}

    class Validator(JWTBearerTokenValidator):
        def get_jwks(self, issuer=None):
            return key_sets[issuer]

    validator = Validator(
        issuer={
            ISSUER: {"resource_server": RESOURCE_SERVER},
            OTHER_ISSUER: {"resource_server": RESOURCE_SERVER},
        }
    )
    token_string = _encode_token(second_key, _base_claims(iss=OTHER_ISSUER))

    token = _validate(validator, token_string)
    assert token["iss"] == OTHER_ISSUER


def test_multi_issuer_malformed_configuration_is_invalid_token(key):
    validator = JWTBearerTokenValidator(issuer={ISSUER: "not-a-mapping"})
    token_string = _encode_token(key, _base_claims())

    with pytest.raises(InvalidTokenError):
        validator.authenticate_token(token_string)


# --- Layer 3: type and purpose -----------------------------------------------


@pytest.mark.parametrize("typ", ["at+jwt", "application/at+jwt"])
def test_accepted_access_token_types(key, typ):
    validator = _make_validator(key)
    token = _validate(validator, _encode_token(key, header={"typ": typ}))
    assert token.header["typ"] == typ


@pytest.mark.parametrize("typ", ["JWT", "jwt", "rt+jwt", ""])
def test_wrong_typ_is_rejected(key, typ):
    validator = _make_validator(key)
    with pytest.raises(InvalidTokenError):
        _validate(validator, _encode_token(key, header={"typ": typ}))


def test_missing_typ_is_rejected(key):
    validator = _make_validator(key)
    token_string = jws.serialize_compact(
        {"alg": "HS256"},
        json.dumps(_base_claims()),
        key,
    )
    with pytest.raises(InvalidTokenError):
        _validate(validator, token_string)


def test_strict_mode_requires_canonical_typ(key):
    validator = _make_validator(key, strict=True)

    _validate(validator, _encode_token(key, header={"typ": "at+jwt"}))
    with pytest.raises(InvalidTokenError):
        _validate(
            validator,
            _encode_token(key, header={"typ": "application/at+jwt"}),
        )


# --- Layer 4: claim structure ------------------------------------------------


@pytest.mark.parametrize(
    "claim", ["iss", "sub", "client_id", "aud", "exp", "iat", "jti"]
)
def test_missing_required_claim_raises_missing_claim_error(key, claim):
    claims = _base_claims()
    del claims[claim]
    token_string = _encode_token(key, claims)
    validator = _make_validator(key)
    token = validator.authenticate_token(token_string)

    with pytest.raises(MissingClaimError) as exc_info:
        token.validate_claim_structure()
    assert exc_info.value.claim == claim

    # The client still only gets the generic RFC 6750 error.
    with pytest.raises(InvalidTokenError):
        validator.validate_token(token, None, None)


@pytest.mark.parametrize(
    ("claim", "value"),
    [
        ("iss", 123),
        ("sub", 123),
        ("client_id", 123),
        ("aud", 123),
        ("exp", "soon"),
        ("iat", "soon"),
        ("jti", 123),
    ],
)
def test_claim_wrong_type_raises_invalid_claim_error(key, claim, value):
    token_string = _encode_token(key, _base_claims(**{claim: value}))
    validator = _make_validator(key)
    token = validator.authenticate_token(token_string)

    with pytest.raises(InvalidClaimError) as exc_info:
        token.validate_claim_structure()
    assert exc_info.value.claim == claim


def test_boolean_is_not_a_numeric_date(key):
    token_string = _encode_token(key, _base_claims(exp=True))
    validator = _make_validator(key)
    token = validator.authenticate_token(token_string)

    with pytest.raises(InvalidClaimError) as exc_info:
        token.validate_claim_structure()
    assert exc_info.value.claim == "exp"


def test_scope_array_accepted_by_default_but_rejected_in_strict_mode(key):
    token_string = _encode_token(key, _base_claims(scope=["profile", "email"]))

    default_validator = _make_validator(key)
    token = _validate(default_validator, token_string, scopes=["profile"])
    assert token.get_scope() == ["profile", "email"]

    strict_validator = _make_validator(key, strict=True)
    with pytest.raises(InvalidTokenError):
        _validate(strict_validator, token_string)


def test_strict_mode_accepts_space_separated_scope_string(key):
    token_string = _encode_token(key, _base_claims(scope="profile email"))
    validator = _make_validator(key, strict=True)

    token = _validate(validator, token_string, scopes=["email"])
    assert token.get_scope() == "profile email"


# --- Layer 5: resource audience ----------------------------------------------


def test_wrong_audience_is_rejected(key):
    validator = _make_validator(key)
    token_string = _encode_token(
        key, _base_claims(aud="https://another-api.example.com")
    )

    with pytest.raises(InvalidTokenError):
        _validate(validator, token_string)


def test_audience_list_is_supported(key):
    validator = _make_validator(key)
    token_string = _encode_token(
        key,
        _base_claims(aud=[RESOURCE_SERVER, "https://other-api.example.com"]),
    )

    token = _validate(validator, token_string)
    assert RESOURCE_SERVER in token["aud"]


def test_expired_token_is_rejected(key):
    validator = _make_validator(key)
    token_string = _encode_token(key, _base_claims(exp=int(time.time()) - 1))

    with pytest.raises(InvalidTokenError):
        _validate(validator, token_string)


# --- Error reporting ---------------------------------------------------------


def test_failure_logs_keep_claim_name_but_not_token_or_jti(key, caplog):
    validator = _make_validator(key)
    token_string = _encode_token(
        key, _base_claims(aud="wrong-audience", jti="super-secret-jti")
    )

    with caplog.at_level(logging.DEBUG, logger="authlib.oauth2.rfc9068"):
        with pytest.raises(InvalidTokenError):
            _validate(validator, token_string)

    logs = "\n".join(record.getMessage() for record in caplog.records)
    assert "aud" in logs
    assert "super-secret-jti" not in logs
    assert token_string not in logs


def test_client_error_contains_no_internal_detail(key):
    validator = _make_validator(key)
    token_string = _encode_token(key, _base_claims(client_id=42))

    with pytest.raises(InvalidTokenError) as exc_info:
        _validate(validator, token_string)

    error = exc_info.value
    assert error.error == "invalid_token"
    # The description stays the generic RFC 6750 sentence.
    assert "client_id" not in error.get_error_description()
