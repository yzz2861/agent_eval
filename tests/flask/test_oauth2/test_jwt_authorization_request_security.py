import json
import threading
import time
from unittest.mock import Mock

import pytest
from joserfc import jwe
from joserfc import jwk
from joserfc import jwt

from authlib.common.urls import add_params_to_uri
from authlib.oauth2 import rfc9101
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from tests.util import read_file_path

from .models import Client
from .models import CodeGrantMixin
from .models import save_authorization_code

authorize_url = "/oauth/authorize"

ISSUER = "https://provider.test"
OTHER_ISSUER = "https://other-tenant.example"


@pytest.fixture(autouse=True)
def server(server):
    class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
        TOKEN_ENDPOINT_AUTH_METHODS = [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ]

        def save_authorization_code(self, code, request):
            return save_authorization_code(code, request)

    server.register_grant(AuthorizationCodeGrant)
    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "profile address",
            "token_endpoint_auth_method": "client_secret_basic",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
            "jwks": read_file_path("jwks_public.json"),
            "require_signed_request_object": False,
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def register_security_extension(
    server,
    *,
    metadata=None,
    require_iss=False,
    require_aud=False,
    require_exp=False,
    require_jti=False,
    allow_encrypted_request_object=False,
    allow_nested_request_object=False,
):
    class JWTAuthenticationRequest(rfc9101.JWTAuthenticationRequest):
        def resolve_client_public_key(self, client):
            return read_file_path("jwk_public.json")

        def get_server_metadata(self):
            return metadata or {}

        def get_client_require_signed_request_object(self, client):
            return client.client_metadata.get("require_signed_request_object", False)

    extension = JWTAuthenticationRequest(
        require_iss=require_iss,
        require_aud=require_aud,
        require_exp=require_exp,
        require_jti=require_jti,
        allow_encrypted_request_object=allow_encrypted_request_object,
        allow_nested_request_object=allow_nested_request_object,
    )
    server.register_extension(extension)
    return extension


def encode_request_object(claims, header=None):
    payload = {"response_type": "code", "client_id": "client-id", **claims}
    return jwt.encode(
        header or {"alg": "RS256"},
        payload,
        jwk.import_key(read_file_path("jwk_private.json")),
    )


def authorize(test_client, request_object, extra_params=None):
    params = {"client_id": "client-id", "request": request_object}
    if extra_params:
        params.update(extra_params)
    return test_client.get(add_params_to_uri(authorize_url, params))


def test_legal_request_object_flow_unchanged(test_client, server):
    """A fully valid strict request object still reaches the login page and
    the error/metadata behavior of the authorization code flow is untouched."""
    now = int(time.time())
    register_security_extension(
        server,
        metadata={"issuer": ISSUER},
        require_iss=True,
        require_aud=True,
        require_exp=True,
        require_jti=True,
    )
    request_object = encode_request_object(
        {
            "iss": "client-id",
            "aud": ISSUER,
            "iat": now,
            "nbf": now - 1,
            "exp": now + 300,
            "jti": "jti-legal",
        }
    )
    response = authorize(test_client, request_object)
    assert response.status_code == 200
    assert response.data == b"login"


def test_missing_jti_rejected_under_strict_policy(test_client, server):
    register_security_extension(server, require_jti=True)
    response = authorize(test_client, encode_request_object({}))
    assert response.status_code == 400
    assert response.json["error"] == "invalid_request_object"


def test_jti_accepted_without_strict_policy(test_client, server):
    """Without the strict policy, the existing permissive behavior remains."""
    register_security_extension(server)
    response = authorize(test_client, encode_request_object({"jti": "ignored"}))
    assert response.data == b"login"


def test_replayed_request_object_rejected(test_client, server):
    """The same signed request object cannot be replayed once its jti was
    consumed."""
    register_security_extension(server, require_jti=True)
    request_object = encode_request_object({"jti": "jti-replay"})
    first = authorize(test_client, request_object)
    assert first.data == b"login"

    second = authorize(test_client, request_object)
    assert second.status_code == 400
    assert second.json["error"] == "invalid_request_object"
    assert second.json["error_description"] == "The request object was already used."


def test_jti_replay_scoped_per_client(test_client, server, db):
    """The same jti value can be used by two distinct clients: replay
    protection is scoped to the (client_id, jti) pair."""
    extension = register_security_extension(server, require_jti=True)
    other = Client(user_id=1, client_id="other-client", client_secret="secret")
    other.set_client_metadata(
        {
            "redirect_uris": ["https://other.test"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "jwks": read_file_path("jwks_public.json"),
        }
    )
    db.session.add(other)
    db.session.commit()

    first = authorize(test_client, encode_request_object({"jti": "shared"}))
    assert first.data == b"login"

    other_object = jwt.encode(
        {"alg": "RS256"},
        {
            "response_type": "code",
            "client_id": "other-client",
            "jti": "shared",
        },
        jwk.import_key(read_file_path("jwk_private.json")),
    )
    response = test_client.get(
        add_params_to_uri(
            authorize_url,
            {"client_id": "other-client", "request": other_object},
        )
    )
    assert response.data == b"login"
    assert ("client-id", "shared") in extension._consumed_jtis
    assert ("other-client", "shared") in extension._consumed_jtis


def test_failed_validation_does_not_consume_jti(test_client, server):
    """A request rejected for another reason must leave the jti untouched, so
    the corrected request object can still be used once."""
    register_security_extension(
        server, metadata={"issuer": ISSUER}, require_aud=True, require_jti=True
    )
    request_object = encode_request_object(
        {"aud": OTHER_ISSUER, "jti": "jti-not-consumed"}
    )
    rejected = authorize(test_client, request_object)
    assert rejected.json["error"] == "invalid_request_object"

    # Same jti, correct audience: accepted because the first attempt did not
    # write any replay state.
    valid = encode_request_object({"aud": ISSUER, "jti": "jti-not-consumed"})
    assert authorize(test_client, valid).data == b"login"


def test_concurrent_same_jti_only_one_wins(test_client, server):
    """Concurrent submissions of the same jti are serialized atomically."""
    extension = register_security_extension(server, require_jti=True)
    barrier = threading.Barrier(2)
    client = Mock()
    client.get_client_id.return_value = "client-id"
    outcomes = []

    def worker():
        barrier.wait()
        try:
            extension._consume_jti(client, {"jti": "race"}, None)
            outcomes.append("won")
        except rfc9101.errors.JTIReplayError:
            outcomes.append("lost")

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(outcomes) == ["lost", "won"]
    assert outcomes.count("won") == 1


def test_cross_tenant_audience_rejected(test_client, server):
    """A request object minted for another tenant cannot be replayed against
    this issuer, even when its signature is valid."""
    register_security_extension(server, metadata={"issuer": ISSUER}, require_aud=True)
    request_object = encode_request_object({"aud": OTHER_ISSUER})
    response = authorize(test_client, request_object)
    assert response.status_code == 400
    assert response.json["error"] == "invalid_request_object"


def test_missing_audience_rejected_under_strict_policy(test_client, server):
    register_security_extension(server, metadata={"issuer": ISSUER}, require_aud=True)
    response = authorize(test_client, encode_request_object({}))
    assert response.status_code == 400
    assert response.json["error"] == "invalid_request_object"


def test_audience_list_with_issuer_accepted(test_client, server):
    register_security_extension(server, metadata={"issuer": ISSUER}, require_aud=True)
    request_object = encode_request_object({"aud": [OTHER_ISSUER, ISSUER]})
    assert authorize(test_client, request_object).data == b"login"


def test_issuer_bound_to_client(test_client, server):
    """The iss claim must identify the sending client."""
    register_security_extension(server, require_iss=True)
    response = authorize(test_client, encode_request_object({"iss": "other-client"}))
    assert response.status_code == 400
    assert response.json["error"] == "invalid_request_object"
    assert response.json["error_description"] == (
        "The 'iss' claim does not identify the client."
    )


def test_missing_issuer_rejected_under_strict_policy(test_client, server):
    register_security_extension(server, require_iss=True)
    response = authorize(test_client, encode_request_object({}))
    assert response.status_code == 400
    assert response.json["error"] == "invalid_request_object"


def test_tenant_issuer_policy(test_client, server):
    """An integration can bind iss to a tenant-specific identifier."""

    class TenantJAR(rfc9101.JWTAuthenticationRequest):
        def resolve_client_public_key(self, client):
            return read_file_path("jwk_public.json")

        def get_expected_request_object_issuer(self, client):
            return f"https://tenant.test/{client.get_client_id()}"

    extension = TenantJAR(require_iss=True)
    server.register_extension(extension)

    accepted = encode_request_object({"iss": "https://tenant.test/client-id"})
    assert authorize(test_client, accepted).data == b"login"

    rejected = encode_request_object({"iss": "client-id"})
    response = authorize(test_client, rejected)
    assert response.json["error"] == "invalid_request_object"


@pytest.mark.parametrize(
    "claim,delta,description",
    [
        ("exp", -300, None),
        ("nbf", 300, None),
        ("iat", 300, None),
    ],
)
def test_time_window_claims_enforced(test_client, server, claim, delta, description):
    register_security_extension(server, require_exp=True)
    now = int(time.time())
    claims = {"exp": now + 300, claim: now + delta}
    response = authorize(test_client, encode_request_object(claims))
    assert response.status_code == 400
    assert response.json["error"] == "invalid_request_object"


def test_exp_required_under_strict_policy(test_client, server):
    register_security_extension(server, require_exp=True)
    response = authorize(test_client, encode_request_object({}))
    assert response.status_code == 400
    assert response.json["error"] == "invalid_request_object"


def test_clock_leeway_accepted(test_client, server):
    now = int(time.time())
    extension = register_security_extension(server, require_exp=True)
    extension.get_clock_leeway = lambda: 60
    request_object = encode_request_object({"exp": now - 30})
    assert authorize(test_client, request_object).data == b"login"


def test_algorithm_tampering_rejected(test_client, server):
    """Changing the JWS header alg without a valid signature is rejected."""
    register_security_extension(
        server, metadata={"require_signed_request_object": True}
    )
    request_object = encode_request_object({})
    header, payload, signature = request_object.split(".")
    import base64

    tampered_header = (
        base64.urlsafe_b64encode(json.dumps({"alg": "ES256", "typ": "JWT"}).encode())
        .rstrip(b"=")
        .decode()
    )
    tampered = ".".join([tampered_header, payload, signature])
    response = authorize(test_client, tampered)
    assert response.status_code == 400
    assert response.json["error"] == "invalid_request_object"


def test_disallowed_algorithm_rejected(test_client, server):
    """An algorithm outside the configured list is rejected before claims are
    trusted."""
    extension = register_security_extension(server)
    extension.get_request_object_signing_algorithms = lambda client: ["ES256"]
    response = authorize(test_client, encode_request_object({}))
    assert response.status_code == 400
    assert response.json["error"] == "invalid_request"


def test_symmetric_algorithm_rejected_by_default(test_client, server):
    """HS256 must not verify against the client public JWK."""
    register_security_extension(server)
    shared_key = jwk.generate_key("oct", 256)
    request_object = jwt.encode(
        {"alg": "HS256"},
        {"response_type": "code", "client_id": "client-id"},
        shared_key,
        algorithms=["HS256"],
    )
    response = authorize(test_client, request_object)
    assert response.status_code == 400


def test_hs256_key_confusion_uses_registered_key_only(test_client, server):
    """The signature key only comes from resolve_client_public_key: an HS256
    token signed with different secret material can never pass."""
    extension = register_security_extension(server)
    extension.allow_symmetric_signing_algorithm = lambda client: True
    extension.get_request_object_signing_algorithms = lambda client: ["HS256"]
    registered = jwk.generate_key("oct", 256)
    extension.resolve_client_public_key = lambda client: registered
    request_object = jwt.encode(
        {"alg": "HS256"},
        {"response_type": "code", "client_id": "client-id"},
        jwk.generate_key("oct", 256),
        algorithms=["HS256"],
    )
    response = authorize(test_client, request_object)
    assert response.status_code == 400
    assert response.json["error"] == "invalid_request_object"


def test_symmetric_algorithm_opt_in(test_client, server):
    extension = register_security_extension(server)
    extension.allow_symmetric_signing_algorithm = lambda client: True
    extension.get_request_object_signing_algorithms = lambda client: [
        "RS256",
        "HS256",
    ]
    oct_key = jwk.generate_key("oct", 256)
    extension.resolve_client_public_key = lambda client: oct_key
    request_object = jwt.encode(
        {"alg": "HS256"},
        {"response_type": "code", "client_id": "client-id"},
        oct_key,
        algorithms=["HS256"],
    )
    assert authorize(test_client, request_object).data == b"login"


@pytest.mark.parametrize(
    "name,outer,inner,expected_status",
    [
        ("redirect_uri", "https://evil.test", "https://client.test", 400),
        ("response_type", "token", "code", 400),
        ("state", "outer-state", "inner-state", 400),
        ("scope", "profile", "address", 400),
        ("code_challenge", "aaa", "bbb", 400),
        # Equal duplicated values are harmless and must keep working.
        ("state", "same", "same", 200),
    ],
)
def test_conflicting_security_parameter_rejected(
    test_client, server, name, outer, inner, expected_status
):
    register_security_extension(server)
    request_object = encode_request_object({name: inner})
    response = authorize(test_client, request_object, {name: outer})
    assert response.status_code == expected_status
    if expected_status == 400:
        assert response.json["error"] == "invalid_request_object"
        assert name in response.json["error_description"]


def test_request_object_takes_precedence_for_non_security_parameter(
    test_client, server
):
    """Parameters outside the protected set may still be supplied only in the
    request object, which remains the source of truth."""
    register_security_extension(server)
    request_object = encode_request_object({"custom_param": "from-object"})
    response = authorize(test_client, request_object)
    assert response.data == b"login"


def build_nested_request_object():
    inner = encode_request_object({})
    encryption_key = jwk.generate_key("oct", 256)
    nested = jwe.encrypt_compact(
        {"alg": "dir", "enc": "A256GCM"}, inner.encode(), encryption_key
    )
    return nested, encryption_key


def test_encrypted_request_object_disabled_by_default(test_client, server):
    register_security_extension(server)
    nested, _ = build_nested_request_object()
    response = authorize(test_client, nested)
    assert response.status_code == 400
    assert response.json["error"] == "invalid_request_object"


@pytest.mark.parametrize("raw_object", ["a.b", "a.b.c.d", "a.b.c.d.e.f", ""])
def test_malformed_compact_serialization_rejected(test_client, server, raw_object):
    register_security_extension(server)
    response = authorize(test_client, raw_object)
    assert response.status_code == 400
    assert response.json["error"] == "invalid_request_object"


def test_nested_request_object_requires_explicit_switch(test_client, server):
    nested, encryption_key = build_nested_request_object()
    extension = register_security_extension(server, allow_encrypted_request_object=True)
    extension.resolve_client_private_key = lambda client: encryption_key
    extension.get_request_object_encryption_algorithms = lambda client: [
        "dir",
        "A256GCM",
    ]
    response = authorize(test_client, nested)
    assert response.status_code == 400
    assert response.json["error"] == "invalid_request_object"
    assert response.json["error_description"] == (
        "Nested request objects are not supported by this server."
    )


def test_nested_request_object_accepted_when_enabled(test_client, server):
    nested, encryption_key = build_nested_request_object()
    extension = register_security_extension(
        server,
        allow_encrypted_request_object=True,
        allow_nested_request_object=True,
    )
    extension.resolve_client_private_key = lambda client: encryption_key
    extension.get_request_object_encryption_algorithms = lambda client: [
        "dir",
        "A256GCM",
    ]
    response = authorize(test_client, nested)
    assert response.data == b"login"


def test_encrypted_request_object_without_nested_jws_rejected(test_client, server):
    """Encryption alone must not bypass the signature policy."""
    encryption_key = jwk.generate_key("oct", 256)
    encrypted_claims = jwe.encrypt_compact(
        {"alg": "dir", "enc": "A256GCM"},
        b'{"response_type": "code", "client_id": "client-id"}',
        encryption_key,
    )
    extension = register_security_extension(
        server,
        allow_encrypted_request_object=True,
        allow_nested_request_object=True,
    )
    extension.resolve_client_private_key = lambda client: encryption_key
    extension.get_request_object_encryption_algorithms = lambda client: [
        "dir",
        "A256GCM",
    ]
    response = authorize(test_client, encrypted_claims)
    assert response.status_code == 400
    assert response.json["error"] == "invalid_request_object"


def test_error_responses_do_not_leak_key_material(test_client, server):
    """No validation error includes key bytes or cryptographic details."""
    register_security_extension(
        server,
        metadata={"issuer": ISSUER},
        require_iss=True,
        require_aud=True,
        require_exp=True,
        require_jti=True,
    )
    private_jwk = json.dumps(read_file_path("jwk_private.json"))
    cases = [
        encode_request_object({"aud": OTHER_ISSUER}),
        encode_request_object({"iss": "attacker"}),
        encode_request_object({"jti": "x"}),
        "not-a-jwt",
    ]
    for request_object in cases:
        response = authorize(test_client, request_object)
        body = json.dumps(response.json)
        assert response.status_code == 400
        assert private_jwk not in body
        assert "BEGIN" not in body
        assert "key" not in body.lower() or response.json["error"] in (
            "invalid_request_object",
            "invalid_request",
        )
