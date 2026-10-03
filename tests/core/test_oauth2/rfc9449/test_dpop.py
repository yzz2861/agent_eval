import json
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from joserfc.jwk import ECKey
from joserfc.jws import JWSRegistry
from joserfc.jws import serialize_compact

from authlib.oauth2.rfc6749.resource_protector import ResourceProtector
from authlib.oauth2.rfc9449 import DPoPProofExtension
from authlib.oauth2.rfc9449 import DPoPProofValidator
from authlib.oauth2.rfc9449 import DPoPTokenValidator
from authlib.oauth2.rfc9449 import InMemoryDPoPReplayCache
from authlib.oauth2.rfc9449 import InvalidDPoPProofError
from authlib.oauth2.rfc9449 import InvalidDPoPResourceProofError
from authlib.oauth2.rfc9449 import UseDPoPNonceError
from authlib.oauth2.rfc9449 import UseDPoPNonceResourceError
from authlib.oauth2.rfc9449 import access_token_hash


TOKEN_URL = "https://server.example.com/token"
RESOURCE_URL = "https://resource.example.com/messages?page=1"
ACCESS_TOKEN = "access-token-value"
NOW = 1_700_000_000
JWS_ALL_ALGORITHMS = JWSRegistry(algorithms=JWSRegistry.algorithms.keys())


class Request:
    def __init__(self, method, uri, headers=None):
        self.method = method
        self.uri = uri
        self.headers = headers or {}


class BearerValidator:
    TOKEN_TYPE = "dpop"
    realm = None
    extra_attributes = {}
    unknown_token = False

    def authenticate_token(self, token_string):
        if self.unknown_token:
            return None
        return {"cnf": {"jkt": self.jkt}}

    def validate_token(self, token, scopes, request, **kwargs):
        token["validated"] = True


class FixedNoncePolicy:
    def __init__(self, nonce="server-nonce"):
        self.nonce = nonce

    def get_nonce(self, request):
        return self.nonce

    def validate(self, nonce, request):
        return nonce == self.nonce


@pytest.fixture
def key():
    return ECKey.generate_key("P-256")


@pytest.fixture
def clock():
    return {"value": NOW}


@pytest.fixture
def replay_cache():
    return InMemoryDPoPReplayCache()


def make_proof(
    key,
    *,
    method="POST",
    url=TOKEN_URL,
    iat=NOW,
    jti="proof-jti",
    ath=Ellipsis,
    nonce=None,
    typ="dpop+jwt",
    alg="ES256",
    header_jwk=None,
    sign_key=Ellipsis,
    extra_claims=None,
):
    claims = {
        "jti": jti,
        "htm": method,
        "htu": url,
        "iat": iat,
    }
    if ath is not Ellipsis:
        claims["ath"] = ath
    if nonce is not None:
        claims["nonce"] = nonce
    if extra_claims:
        claims.update(extra_claims)
    protected = {
        "alg": alg,
        "typ": typ,
        "jwk": key.as_dict(private=False) if header_jwk is None else header_jwk,
    }
    signing_key = key if sign_key is Ellipsis else sign_key
    return serialize_compact(
        protected,
        json.dumps(claims),
        signing_key,
        registry=JWS_ALL_ALGORITHMS,
    )


def make_validator(clock, replay_cache, target_url=TOKEN_URL, nonce_policy=None):
    return DPoPProofValidator(
        target_url,
        replay_cache=replay_cache,
        nonce_policy=nonce_policy,
        leeway=0,
        max_age=300,
        time_func=lambda: clock["value"],
    )


def make_resource_protector(
    key, clock, replay_cache, nonce_policy=None, unknown_token=False
):
    proof_validator = make_validator(
        clock,
        replay_cache,
        RESOURCE_URL,
        nonce_policy=nonce_policy,
    )
    bearer_validator = BearerValidator()
    bearer_validator.jkt = key.thumbprint()
    bearer_validator.unknown_token = unknown_token
    protector = ResourceProtector()
    protector.register_token_validator(
        DPoPTokenValidator(bearer_validator, proof_validator)
    )
    return protector


def resource_request(
    key,
    jti="resource-jti",
    method="GET",
    url="https://resource.example.com/messages",
    request_method=None,
    request_url=None,
    **claims,
):
    proof = make_proof(
        key,
        method=method,
        url=url,
        jti=jti,
        ath=access_token_hash(ACCESS_TOKEN),
        **claims,
    )
    return Request(
        request_method or method,
        request_url or RESOURCE_URL,
        {
            "Authorization": f"DPoP {ACCESS_TOKEN}",
            "DPoP": proof,
        },
    )


def test_token_request_binds_proof_public_key(key, clock, replay_cache):
    validator = make_validator(clock, replay_cache)
    proof = make_proof(key)
    request = Request("POST", TOKEN_URL, {"DPoP": proof})

    class FakeGrant:
        def __init__(self):
            self.request = request

        def generate_token(self):
            return {"access_token": ACCESS_TOKEN, "token_type": "Bearer"}

        def create_token_response(self):
            return 200, generated_token, []

    grant = FakeGrant()
    generated_token = None
    DPoPProofExtension(validator)(grant)

    generated_token = grant.generate_token()

    assert generated_token["token_type"] == "DPoP"
    assert generated_token["cnf"] == {"jkt": key.thumbprint()}


@pytest.mark.parametrize(
    ("method", "url"),
    [
        ("GET", TOKEN_URL),
        ("POST", "https://server.example.com/other"),
    ],
)
def test_token_request_rejects_changed_method_or_target(
    key, clock, replay_cache, method, url
):
    validator = make_validator(clock, replay_cache)
    proof = make_proof(key, method=method, url=url)

    with pytest.raises(InvalidDPoPProofError):
        validator.validate_token_request(Request("POST", TOKEN_URL, {"DPoP": proof}))


def test_query_and_fragment_are_not_part_of_binding(key, clock, replay_cache):
    validator = make_validator(clock, replay_cache, TOKEN_URL)
    valid_proof = make_proof(key)
    validated = validator.validate_token_request(
        Request("POST", TOKEN_URL + "?prompt=none", {"DPoP": valid_proof})
    )
    assert validated.claims["htu"] == TOKEN_URL

    replay_cache = InMemoryDPoPReplayCache()
    validator = make_validator(clock, replay_cache, TOKEN_URL)
    invalid_proof = make_proof(key, url=TOKEN_URL + "?prompt=none", jti="query-jti")
    with pytest.raises(InvalidDPoPProofError):
        validator.validate_token_request(
            Request("POST", TOKEN_URL, {"DPoP": invalid_proof})
        )


def test_request_query_is_not_included_in_target_comparison(
    key, clock, replay_cache
):
    validator = make_validator(clock, replay_cache, TOKEN_URL)
    proof = make_proof(key, jti="query-request")

    validated = validator.validate_token_request(
        Request("POST", TOKEN_URL + "?different=true", {"DPoP": proof})
    )

    assert "?" not in validated.claims["htu"]


def test_target_comparison_normalizes_scheme_host_and_default_port(
    key, clock, replay_cache
):
    validator = make_validator(clock, replay_cache, TOKEN_URL)
    proof = make_proof(
        key,
        url="https://SERVER.example.com:443/token",
        jti="normalized-target",
    )

    validated = validator.validate_token_request(
        Request("POST", TOKEN_URL, {"DPoP": proof})
    )

    assert validated.claims["htu"] == "https://SERVER.example.com:443/token"


def test_resource_request_validates_ath_binding_and_reuse(key, clock, replay_cache):
    protector = make_resource_protector(key, clock, replay_cache)
    request = resource_request(key)

    token = protector.validate_request(None, request)
    assert token["validated"] is True
    assert token["cnf"]["jkt"] == key.thumbprint()

    with pytest.raises(InvalidDPoPResourceProofError):
        protector.validate_request(None, request)


def test_resource_request_rejects_changed_token(key, clock, replay_cache):
    protector = make_resource_protector(key, clock, replay_cache)
    request = resource_request(key)
    request.headers["Authorization"] = "DPoP another-token"

    with pytest.raises(InvalidDPoPResourceProofError):
        protector.validate_request(None, request)


def test_resource_request_rejects_unknown_token(key, clock, replay_cache):
    protector = make_resource_protector(
        key,
        clock,
        replay_cache,
        unknown_token=True,
    )
    request = resource_request(key, jti="unknown-token-proof")

    with pytest.raises(InvalidDPoPResourceProofError):
        protector.validate_request(None, request)


def test_resource_request_rejects_changed_key_binding(key, clock, replay_cache):
    other_key = ECKey.generate_key("P-256")
    protector = make_resource_protector(key, clock, replay_cache)
    request = resource_request(other_key)

    with pytest.raises(InvalidDPoPResourceProofError):
        protector.validate_request(None, request)


@pytest.mark.parametrize(
    ("method", "url"),
    [
        ("POST", "https://resource.example.com/messages"),
        ("GET", "https://resource.example.com/other"),
    ],
)
def test_resource_request_rejects_changed_method_or_target(
    key, clock, replay_cache, method, url
):
    protector = make_resource_protector(key, clock, replay_cache)
    request = resource_request(
        key,
        method=method,
        url=url,
        jti=url,
        request_method="GET",
        request_url=RESOURCE_URL,
    )

    with pytest.raises(InvalidDPoPResourceProofError):
        protector.validate_request(None, request)


@pytest.mark.parametrize(
    ("kwargs", "jti"),
    [
        ({"typ": "JWT"}, "typ-jti"),
        ({"iat": NOW - 301}, "old-jti"),
        ({"iat": NOW + 1}, "future-jti"),
        ({"extra_claims": {"jti": ""}}, "empty-jti"),
    ],
)
def test_resource_request_rejects_invalid_claims(
    key, clock, replay_cache, kwargs, jti
):
    protector = make_resource_protector(key, clock, replay_cache)
    request = resource_request(key, jti=jti, **kwargs)

    with pytest.raises(InvalidDPoPResourceProofError):
        protector.validate_request(None, request)


def test_replay_cache_claim_is_atomic(replay_cache):
    barrier = threading.Barrier(16)

    def claim():
        barrier.wait()
        return replay_cache.claim("same-jti", 300, NOW)

    pool = ThreadPoolExecutor(max_workers=16)
    try:
        futures = [pool.submit(claim) for _ in range(16)]
        results = [future.result() for future in futures]
    finally:
        pool.shutdown()

    assert results.count(True) == 1


def test_replay_cache_releases_jti_after_ttl():
    cache = InMemoryDPoPReplayCache()

    assert cache.claim("expiring-jti", 300, NOW) is True
    assert cache.claim("expiring-jti", 300, NOW + 300) is True
    assert len(cache) == 1


def test_nonce_challenge_then_retry_succeeds(key, clock, replay_cache):
    policy = FixedNoncePolicy()
    validator = make_validator(clock, replay_cache, TOKEN_URL, policy)
    request = Request("POST", TOKEN_URL, {})

    with pytest.raises(UseDPoPNonceError) as challenge:
        validator.validate_token_request(request)
    assert challenge.value.dpop_nonce == "server-nonce"

    proof = make_proof(key, jti="nonce-retry", nonce="server-nonce")
    request.headers["DPoP"] = proof
    validated = validator.validate_token_request(request)
    assert validated.claims["nonce"] == "server-nonce"


def test_resource_nonce_challenge_is_401(key, clock, replay_cache):
    policy = FixedNoncePolicy()
    protector = make_resource_protector(key, clock, replay_cache, policy)
    request = Request(
        "GET",
        RESOURCE_URL,
        {"Authorization": f"DPoP {ACCESS_TOKEN}"},
    )

    with pytest.raises(UseDPoPNonceResourceError) as challenge:
        protector.validate_request(None, request)
    assert challenge.value.status_code == 401
    assert dict(challenge.value.get_headers())["DPoP-Nonce"] == "server-nonce"


def test_invalid_signature_is_rejected(key, clock, replay_cache):
    other_key = ECKey.generate_key("P-256")
    validator = make_validator(clock, replay_cache)
    proof = make_proof(key, sign_key=other_key, jti="bad-signature")

    with pytest.raises(InvalidDPoPProofError):
        validator.validate_token_request(Request("POST", TOKEN_URL, {"DPoP": proof}))


def test_disallowed_algorithm_is_rejected(key, clock, replay_cache):
    validator = DPoPProofValidator(
        TOKEN_URL,
        algorithms=("ES256",),
        replay_cache=replay_cache,
        leeway=0,
        max_age=300,
        time_func=lambda: clock["value"],
    )
    es384_key = ECKey.generate_key("P-384")
    proof = make_proof(es384_key, alg="ES384", jti="es384-proof")

    with pytest.raises(InvalidDPoPProofError):
        validator.validate_token_request(Request("POST", TOKEN_URL, {"DPoP": proof}))


def test_unexpected_ath_is_rejected_at_token_endpoint(key, clock, replay_cache):
    validator = make_validator(clock, replay_cache)
    proof = make_proof(
        key,
        jti="token-ath-proof",
        ath=access_token_hash(ACCESS_TOKEN),
    )

    with pytest.raises(InvalidDPoPProofError):
        validator.validate_token_request(Request("POST", TOKEN_URL, {"DPoP": proof}))


def test_private_jwk_is_rejected(key, clock, replay_cache):
    validator = make_validator(clock, replay_cache)
    proof = make_proof(
        key,
        header_jwk=key.as_dict(private=True),
        jti="private-jwk-proof",
    )

    with pytest.raises(InvalidDPoPProofError):
        validator.validate_token_request(Request("POST", TOKEN_URL, {"DPoP": proof}))
