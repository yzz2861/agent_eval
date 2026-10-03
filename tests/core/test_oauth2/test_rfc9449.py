import pytest

from authlib.common.encoding import json_b64encode
from authlib.common.encoding import json_dumps
from authlib.common.encoding import to_unicode
from authlib.common.encoding import urlsafe_b64encode
from authlib.jose import JsonWebKey
from authlib.jose import JsonWebSignature
from authlib.oauth2.rfc6749 import JsonRequest
from authlib.oauth2.rfc6750 import InvalidTokenError
from authlib.oauth2.rfc9449 import DPoPNonceProvider
from authlib.oauth2.rfc9449 import DPoPTokenEndpointValidator
from authlib.oauth2.rfc9449 import DPoPTokenValidator
from authlib.oauth2.rfc9449 import InMemoryDPoPReplayStore
from authlib.oauth2.rfc9449 import InvalidDPoPProofError
from authlib.oauth2.rfc9449 import UseDPoPNonceError
from authlib.oauth2.rfc9449 import compute_ath
from authlib.oauth2.rfc9449 import normalize_htu
from authlib.oauth2.rfc9449.dpop import DPoPProofValidator

NOW = 1700000000
TOKEN_ENDPOINT = "https://as.example.com/token"
RESOURCE_URL = "https://rs.example.com/resource"
ACCESS_TOKEN = "example-access-token"

jws = JsonWebSignature()


@pytest.fixture
def key():
    return JsonWebKey.generate_key("EC", "P-256", is_private=True)


@pytest.fixture
def other_key():
    return JsonWebKey.generate_key("EC", "P-256", is_private=True)


def make_proof(key, method="GET", url=RESOURCE_URL, **overrides):
    claims = {
        "jti": overrides.pop("jti", "unique-proof-id"),
        "htm": overrides.pop("htm", method),
        "htu": overrides.pop("htu", url),
        "iat": overrides.pop("iat", NOW),
    }
    claims.update(overrides.pop("claims", {}))
    header = {
        "typ": overrides.pop("typ", "dpop+jwt"),
        "alg": overrides.pop("alg", "ES256"),
        "jwk": overrides.pop("jwk", key.as_dict()),
    }
    header.update(overrides.pop("header", {}))
    assert not overrides, f"unexpected overrides: {overrides}"
    return to_unicode(jws.serialize_compact(header, json_dumps(claims), key))


def make_validator(**kwargs):
    kwargs.setdefault("now", lambda: NOW)
    return DPoPProofValidator(**kwargs)


def make_request(method="GET", url=RESOURCE_URL, proof=None, token=ACCESS_TOKEN):
    headers = {}
    if proof is not None:
        headers["DPoP"] = proof
    if token is not None:
        headers["Authorization"] = f"DPoP {token}"
    return JsonRequest(method, url, headers)


def test_normalize_htu_strips_query_and_fragment():
    assert (
        normalize_htu("https://RS.example.com:443/resource?a=1#frag")
        == "https://rs.example.com/resource"
    )
    assert normalize_htu("http://example.com:80/") == "http://example.com/"
    assert normalize_htu("https://example.com:8443/x") == "https://example.com:8443/x"


def test_valid_proof(key):
    validator = make_validator()
    proof = make_proof(key)
    result = validator.validate(proof, "GET", RESOURCE_URL)
    assert result.claims["htm"] == "GET"
    assert result.jkt == key.thumbprint().rstrip("=")


def test_proof_with_query_string_in_request_url(key):
    # the query string of the request URI is not part of the htu binding
    validator = make_validator()
    proof = make_proof(key, htu=RESOURCE_URL)
    result = validator.validate(proof, "GET", RESOURCE_URL + "?foo=bar&baz=1")
    assert result.claims["htu"] == RESOURCE_URL


def test_invalid_typ(key):
    validator = make_validator()
    proof = make_proof(key, typ="jwt")
    with pytest.raises(InvalidDPoPProofError):
        validator.validate(proof, "GET", RESOURCE_URL)


def test_symmetric_alg_rejected(key):
    validator = make_validator()
    oct_key = JsonWebKey.import_key({"kty": "oct", "k": "c2VjcmV0"})
    proof = make_proof(oct_key, alg="HS256")
    with pytest.raises(InvalidDPoPProofError):
        validator.validate(proof, "GET", RESOURCE_URL)


def test_none_alg_rejected(key):
    validator = make_validator()
    header = {"typ": "dpop+jwt", "alg": "none", "jwk": key.as_dict()}
    claims = {"jti": "x", "htm": "GET", "htu": RESOURCE_URL, "iat": NOW}
    proof = (
        to_unicode(json_b64encode(header))
        + "."
        + to_unicode(urlsafe_b64encode(json_dumps(claims).encode()))
        + "."
    )
    with pytest.raises(InvalidDPoPProofError):
        validator.validate(proof, "GET", RESOURCE_URL)


def test_alg_not_in_allowed_list(key):
    validator = make_validator(allowed_algs=["ES384"])
    proof = make_proof(key, alg="ES256")
    with pytest.raises(InvalidDPoPProofError):
        validator.validate(proof, "GET", RESOURCE_URL)


def test_private_jwk_rejected(key):
    validator = make_validator()
    proof = make_proof(key, jwk=key.as_dict(is_private=True))
    with pytest.raises(InvalidDPoPProofError):
        validator.validate(proof, "GET", RESOURCE_URL)


def test_missing_jwk_rejected(key):
    validator = make_validator()
    proof = make_proof(key, jwk=None)
    with pytest.raises(InvalidDPoPProofError):
        validator.validate(proof, "GET", RESOURCE_URL)


def test_bad_signature(key, other_key):
    validator = make_validator()
    # signed with other_key, but embeds key as the public jwk
    proof = make_proof(other_key, jwk=key.as_dict())
    with pytest.raises(InvalidDPoPProofError):
        validator.validate(proof, "GET", RESOURCE_URL)


def test_htm_mismatch(key):
    validator = make_validator()
    proof = make_proof(key, htm="POST")
    with pytest.raises(InvalidDPoPProofError):
        validator.validate(proof, "GET", RESOURCE_URL)


def test_htu_mismatch(key):
    validator = make_validator()
    proof = make_proof(key, htu="https://rs.example.com/other")
    with pytest.raises(InvalidDPoPProofError):
        validator.validate(proof, "GET", RESOURCE_URL)


def test_iat_in_future(key):
    validator = make_validator()
    proof = make_proof(key, iat=NOW + 3600)
    with pytest.raises(InvalidDPoPProofError):
        validator.validate(proof, "GET", RESOURCE_URL)


def test_iat_too_old(key):
    validator = make_validator()
    proof = make_proof(key, iat=NOW - 3600)
    with pytest.raises(InvalidDPoPProofError):
        validator.validate(proof, "GET", RESOURCE_URL)


def test_missing_jti(key):
    validator = make_validator()
    proof = make_proof(key, claims={"jti": None})
    # claims.update with None jti
    with pytest.raises(InvalidDPoPProofError):
        validator.validate(proof, "GET", RESOURCE_URL)


def test_ath_mismatch(key):
    validator = make_validator()
    proof = make_proof(key, claims={"ath": compute_ath("other-token")})
    with pytest.raises(InvalidDPoPProofError):
        validator.validate(proof, "GET", RESOURCE_URL, access_token=ACCESS_TOKEN)


def test_ath_match(key):
    validator = make_validator()
    proof = make_proof(key, claims={"ath": compute_ath(ACCESS_TOKEN)})
    result = validator.validate(proof, "GET", RESOURCE_URL, access_token=ACCESS_TOKEN)
    assert result.claims["ath"] == compute_ath(ACCESS_TOKEN)


def test_replay_rejected(key):
    store = InMemoryDPoPReplayStore(now=lambda: NOW)
    validator = make_validator(replay_store=store)
    proof = make_proof(key)
    validator.validate(proof, "GET", RESOURCE_URL)
    with pytest.raises(InvalidDPoPProofError):
        validator.validate(proof, "GET", RESOURCE_URL)


def test_replay_store_atomic():
    store = InMemoryDPoPReplayStore(now=lambda: NOW)
    assert store.check_and_store("k1", NOW + 300) is True
    assert store.check_and_store("k1", NOW + 300) is False
    assert store.check_and_store("k2", NOW + 300) is True


def test_replay_store_expires():
    clock = {"now": NOW}
    store = InMemoryDPoPReplayStore(now=lambda: clock["now"])
    assert store.check_and_store("k1", NOW + 300) is True
    clock["now"] = NOW + 301
    assert store.check_and_store("k1", NOW + 600) is True


def test_same_jti_different_keys_not_replay(key, other_key):
    store = InMemoryDPoPReplayStore(now=lambda: NOW)
    validator = make_validator(replay_store=store)
    validator.validate(make_proof(key), "GET", RESOURCE_URL)
    validator.validate(make_proof(other_key), "GET", RESOURCE_URL)


class StaticNonceProvider(DPoPNonceProvider):
    def __init__(self):
        self.issued = set()
        self.counter = 0

    def get_nonce(self):
        self.counter += 1
        nonce = f"server-nonce-{self.counter}"
        self.issued.add(nonce)
        return nonce

    def validate_nonce(self, nonce):
        return nonce in self.issued


def test_nonce_challenge_and_retry(key):
    provider = StaticNonceProvider()
    validator = make_validator(nonce_provider=provider)

    proof = make_proof(key, jti="no-nonce-proof")
    with pytest.raises(UseDPoPNonceError) as exc_info:
        validator.validate(proof, "GET", RESOURCE_URL)
    headers = dict(exc_info.value.get_headers())
    nonce = headers["DPoP-Nonce"]
    assert nonce in provider.issued

    # client retries with a fresh proof containing the server nonce
    retry = make_proof(key, jti="with-nonce-proof", claims={"nonce": nonce})
    result = validator.validate(retry, "GET", RESOURCE_URL)
    assert result.claims["nonce"] == nonce


def test_invalid_nonce_rejected(key):
    provider = StaticNonceProvider()
    validator = make_validator(nonce_provider=provider)
    proof = make_proof(key, claims={"nonce": "forged-nonce"})
    with pytest.raises(UseDPoPNonceError):
        validator.validate(proof, "GET", RESOURCE_URL)


def test_token_endpoint_validator(key):
    validator = DPoPTokenEndpointValidator(now=lambda: NOW)
    proof = make_proof(key, method="POST", url=TOKEN_ENDPOINT)
    request = make_request("POST", TOKEN_ENDPOINT, proof=proof, token=None)
    jkt = validator.validate_request(request)
    assert jkt == key.thumbprint().rstrip("=")


def test_token_endpoint_validator_without_proof():
    validator = DPoPTokenEndpointValidator(now=lambda: NOW)
    request = make_request("POST", TOKEN_ENDPOINT, token=None)
    assert validator.validate_request(request) is None


def test_token_endpoint_wrong_target(key):
    validator = DPoPTokenEndpointValidator(now=lambda: NOW)
    # proof bound to the resource URL cannot be used at the token endpoint
    proof = make_proof(key, method="POST", url=RESOURCE_URL)
    request = make_request("POST", TOKEN_ENDPOINT, proof=proof, token=None)
    with pytest.raises(InvalidDPoPProofError):
        validator.validate_request(request)


class Token:
    def __init__(self, jkt=None):
        self.cnf = {"jkt": jkt} if jkt else None

    def is_expired(self):
        return False

    def is_revoked(self):
        return False

    def get_scope(self):
        return "profile"


def make_resource_validator(**kwargs):
    kwargs.setdefault("now", lambda: NOW)
    proof_validator = DPoPProofValidator(**kwargs)
    return DPoPTokenValidator(proof_validator=proof_validator)


def test_resource_request_valid(key):
    validator = make_resource_validator()
    proof = make_proof(key, claims={"ath": compute_ath(ACCESS_TOKEN)})
    request = make_request(proof=proof)
    validator.validate_request(request)
    token = Token(jkt=key.thumbprint().rstrip("="))
    validator.validate_token(token, ["profile"], request)
    assert request.dpop_proof.jkt == token.cnf["jkt"]


def test_resource_request_missing_proof(key):
    validator = make_resource_validator()
    request = make_request()
    with pytest.raises(InvalidDPoPProofError):
        validator.validate_request(request)


def test_resource_request_wrong_token(key):
    validator = make_resource_validator()
    # proof ath is computed for another access token
    proof = make_proof(key, claims={"ath": compute_ath("other-token")})
    request = make_request(proof=proof)
    with pytest.raises(InvalidDPoPProofError):
        validator.validate_request(request)


def test_resource_request_token_bound_to_other_key(key, other_key):
    validator = make_resource_validator()
    proof = make_proof(key, claims={"ath": compute_ath(ACCESS_TOKEN)})
    request = make_request(proof=proof)
    validator.validate_request(request)
    token = Token(jkt=other_key.thumbprint().rstrip("="))
    with pytest.raises(InvalidTokenError):
        validator.validate_token(token, ["profile"], request)


def test_resource_request_token_without_binding(key):
    validator = make_resource_validator()
    proof = make_proof(key, claims={"ath": compute_ath(ACCESS_TOKEN)})
    request = make_request(proof=proof)
    validator.validate_request(request)
    with pytest.raises(InvalidTokenError):
        validator.validate_token(Token(), ["profile"], request)


def test_resource_proof_reuse_rejected(key):
    store = InMemoryDPoPReplayStore(now=lambda: NOW)
    validator = make_resource_validator(replay_store=store)
    proof = make_proof(key, claims={"ath": compute_ath(ACCESS_TOKEN)})
    validator.validate_request(make_request(proof=proof))
    with pytest.raises(InvalidDPoPProofError):
        validator.validate_request(make_request(proof=proof))


def test_resource_proof_from_other_endpoint_rejected(key):
    validator = make_resource_validator()
    # proof minted for the token endpoint cannot be replayed at the resource
    proof = make_proof(
        key,
        method="POST",
        url=TOKEN_ENDPOINT,
        claims={"ath": compute_ath(ACCESS_TOKEN)},
    )
    request = make_request("POST", RESOURCE_URL, proof=proof)
    with pytest.raises(InvalidDPoPProofError):
        validator.validate_request(request)
