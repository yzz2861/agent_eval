import hashlib
import time
from contextlib import nullcontext

import pytest
from flask import json
from joserfc import jwt
from joserfc.errors import InvalidClaimError
from joserfc.errors import MissingClaimError
from joserfc.jwk import OctKey
from joserfc.jwk import RSAKey

from authlib.common.encoding import to_native
from authlib.common.encoding import urlsafe_b64encode
from authlib.common.urls import url_decode
from authlib.common.urls import url_encode
from authlib.common.urls import urlparse
from authlib.deprecate import AuthlibDeprecationWarning
from authlib.oauth2.multiple_response_types import MultipleResponseTypes
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc6749.requests import BasicOAuth2Payload
from authlib.oauth2.rfc6749.requests import OAuth2Request
from authlib.oidc.core import HybridIDToken
from authlib.oidc.core.grants import OpenIDCode as _OpenIDCode
from authlib.oidc.core.grants import OpenIDHybridGrant as _OpenIDHybridGrant
from authlib.oidc.core.util import create_half_hash
from authlib.oidc.core.util import get_response_type_spec
from tests.util import HMAC_SECRET
from tests.util import parse_form
from tests.util import read_file_path

from .models import AuthorizationCode
from .models import CodeGrantMixin
from .models import Token
from .models import exists_nonce
from .models import save_authorization_code
from .oauth2_server import SupportedPromptValues
from .oauth2_server import create_basic_header
from .oauth2_server import register_form_post


class IDTokenConfigMixin:
    def resolve_client_private_key(self, client):
        return OctKey.import_key(HMAC_SECRET)

    def get_client_claims(self, client):
        return {"iss": "Authlib", "aud": [client.get_client_id()]}


def deprecated_response_mode():
    """Using response_mode without MultipleResponseTypes is deprecated."""
    return pytest.warns(AuthlibDeprecationWarning, match="MultipleResponseTypes")


@pytest.fixture(autouse=True)
def server(server):
    class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
        def save_authorization_code(self, code, request):
            return save_authorization_code(code, request)

    class OpenIDCode(IDTokenConfigMixin, _OpenIDCode):
        def exists_nonce(self, nonce, request):
            return exists_nonce(nonce, request)

        def generate_user_info(self, user, scopes):
            return user.generate_user_info(scopes)

    class OpenIDHybridGrant(IDTokenConfigMixin, _OpenIDHybridGrant):
        def save_authorization_code(self, code, request):
            return save_authorization_code(code, request)

        def exists_nonce(self, nonce, request):
            return exists_nonce(nonce, request)

        def generate_user_info(self, user, scopes):
            return user.generate_user_info(scopes)

    server.register_grant(OpenIDHybridGrant)
    server.register_grant(AuthorizationCodeGrant, [OpenIDCode()])
    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "openid profile address",
            "response_types": [
                "code id_token",
                "code token",
                "code id_token token",
            ],
            "grant_types": ["authorization_code"],
            "id_token_signed_response_alg": "HS256",
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def validate_claims(id_token, params, alg="HS256", key=None):
    if key is None:
        key = OctKey.import_key(HMAC_SECRET)
    token = jwt.decode(id_token, key, algorithms=[alg])
    claims = HybridIDToken(token.claims, token.header, params=params)
    claims.validate()


def create_hybrid_request(client, user):
    request = OAuth2Request("POST", "https://server.test/authorize")
    request.payload = BasicOAuth2Payload({"nonce": "abc"})
    request.client = client
    request.user = user
    return request


def test_prompt_create(test_client, server):
    """PromptValues sets the grant prompt to 'create' in the hybrid flow."""
    server.register_extension(SupportedPromptValues())
    query = url_encode(
        [
            ("response_type", "code id_token"),
            ("client_id", "client-id"),
            ("scope", "openid profile"),
            ("state", "bar"),
            ("nonce", "abc"),
            ("redirect_uri", "https://client.test"),
            ("prompt", "create"),
        ]
    )
    rv = test_client.get("/oauth/authorize?" + query)
    assert rv.data == b"create"


HYBRID_PARAMS = [
    ("response_type", "code id_token"),
    ("client_id", "client-id"),
    ("scope", "openid profile"),
    ("state", "bar"),
    ("nonce", "abc"),
    ("redirect_uri", "https://client.test"),
    ("user_id", "1"),
]


def test_max_age(test_client):
    """An authentication older than max_age asks for a login, and errors go
    in the fragment."""
    old = str(int(time.time()) - 7200)
    query = url_encode(HYBRID_PARAMS + [("max_age", "3600"), ("auth_time", old)])
    rv = test_client.get("/oauth/authorize?" + query)
    assert rv.data == b"login"

    query = url_encode(
        HYBRID_PARAMS + [("max_age", "3600"), ("auth_time", old), ("prompt", "none")]
    )
    rv = test_client.get("/oauth/authorize?" + query)
    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    assert params["error"] == "login_required"


def test_auth_time_claim(test_client):
    """The auth_time claim of the front-channel ID token comes from
    get_auth_time."""
    rv = test_client.post(
        "/oauth/authorize", data=dict(HYBRID_PARAMS + [("auth_time", "1000000000")])
    )
    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    token = jwt.decode(
        params["id_token"], OctKey.import_key(HMAC_SECRET), algorithms=["HS256"]
    )
    assert token.claims["auth_time"] == 1000000000


def test_auth_time_claim_after_code_exchange(test_client):
    """The ID token of the token endpoint has the auth_time of the
    authorization request."""
    rv = test_client.post(
        "/oauth/authorize", data=dict(HYBRID_PARAMS + [("auth_time", "1000000000")])
    )
    code = dict(url_decode(urlparse.urlparse(rv.location).fragment))["code"]
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "redirect_uri": "https://client.test",
            "code": code,
        },
        headers=create_basic_header("client-id", "client-secret"),
    )
    id_token = json.loads(rv.data)["id_token"]
    token = jwt.decode(id_token, OctKey.import_key(HMAC_SECRET), algorithms=["HS256"])
    assert token.claims["auth_time"] == 1000000000


def test_invalid_client_id(test_client):
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": "code token",
            "state": "bar",
            "nonce": "abc",
            "scope": "openid profile",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"

    rv = test_client.post(
        "/oauth/authorize",
        data={
            "client_id": "invalid-client",
            "response_type": "code token",
            "state": "bar",
            "nonce": "abc",
            "scope": "openid profile",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"


def test_require_nonce(test_client):
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "client_id": "client-id",
            "response_type": "code token",
            "scope": "openid profile",
            "state": "bar",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    assert "error=invalid_request" in rv.location
    assert "nonce" in rv.location


def test_invalid_response_type(test_client):
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "client_id": "client-id",
            "response_type": "code id_token invalid",
            "state": "bar",
            "nonce": "abc",
            "scope": "profile",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    assert params["error"] == "unsupported_response_type"


def test_invalid_scope(test_client):
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "client_id": "client-id",
            "response_type": "code id_token",
            "state": "bar",
            "nonce": "abc",
            "scope": "profile",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    assert "error=invalid_scope" in rv.location


@pytest.mark.parametrize(
    "response_type", ["code id_token", "code token", "code id_token token"]
)
def test_reject_openid_scope_not_allowed_for_client(
    test_client, client, db, response_type
):
    client.set_client_metadata({**client.client_metadata, "scope": "profile"})
    db.session.commit()

    rv = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": response_type,
            "client_id": "client-id",
            "scope": "openid profile",
            "nonce": "abc",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    assert params["error"] == "invalid_scope"
    assert "code" not in params
    assert "id_token" not in params
    assert "access_token" not in params
    assert AuthorizationCode.query.count() == 0


@pytest.mark.parametrize(
    "response_type", ["code id_token", "code token", "code id_token token"]
)
def test_custom_token_generator_receives_allowed_scope(
    test_client, server, response_type
):
    def generate_token(client, grant_type, user, scope, **kwargs):
        return {
            "access_token": "custom-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": scope,
        }

    server.register_token_generator("implicit", generate_token)
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "response_type": response_type,
            "client_id": "client-id",
            "scope": "openid profile email",
            "nonce": "abc",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    assert params["scope"] == "openid profile"
    code = AuthorizationCode.query.filter_by(code=params["code"]).one()
    assert code.scope == "openid profile"


def test_missing_openid_in_scope_does_not_redirect_to_unregistered_uri(test_client):
    """An unregistered redirect_uri must not be followed even when openid scope is missing."""
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "client_id": "client-id",
            "response_type": "code id_token",
            "state": "s",
            "nonce": "n",
            "scope": "profile",
            "redirect_uri": "https://evil.example.com/phish",
        },
    )
    assert rv.status_code == 400
    assert rv.headers.get("Location") is None


def test_access_denied(test_client):
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "client_id": "client-id",
            "response_type": "code token",
            "state": "bar",
            "nonce": "abc",
            "scope": "openid profile",
            "redirect_uri": "https://client.test",
        },
    )
    assert "error=access_denied" in rv.location
    assert "state=bar" in rv.location


def test_code_access_token(test_client):
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "client_id": "client-id",
            "response_type": "code token",
            "state": "bar",
            "nonce": "abc",
            "scope": "openid profile",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    assert "code=" in rv.location
    assert "access_token=" in rv.location
    assert "id_token=" not in rv.location

    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    assert params["state"] == "bar"

    code = params["code"]
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "redirect_uri": "https://client.test",
            "code": code,
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp
    assert "id_token" in resp


def test_code_id_token(test_client):
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "client_id": "client-id",
            "response_type": "code id_token",
            "state": "bar",
            "nonce": "abc",
            "scope": "openid profile",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    assert "code=" in rv.location
    assert "id_token=" in rv.location
    assert "access_token=" not in rv.location

    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    assert params["state"] == "bar"

    params["nonce"] = "abc"
    params["client_id"] = "client-id"
    validate_claims(params["id_token"], params)

    code = params["code"]
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "redirect_uri": "https://client.test",
            "code": code,
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp
    assert "id_token" in resp


@pytest.mark.parametrize(
    "response_type", ["code id_token token", "token id_token code"]
)
@pytest.mark.parametrize("registered", ["code id_token token", "id_token token code"])
def test_code_id_token_access_token(test_client, db, client, response_type, registered):
    """The order of the response_type values does not matter, in the request
    and in the client metadata."""
    client.set_client_metadata(
        {
            **client.client_metadata,
            "response_types": ["code id_token", "code token", registered],
        }
    )
    db.session.add(client)
    db.session.commit()
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "client_id": "client-id",
            "response_type": response_type,
            "state": "bar",
            "nonce": "abc",
            "scope": "openid profile",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    assert "code=" in rv.location
    assert "id_token=" in rv.location
    assert "access_token=" in rv.location

    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    assert params["state"] == "bar"
    validate_claims(params["id_token"], params)

    code = params["code"]
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "redirect_uri": "https://client.test",
            "code": code,
        },
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp
    assert "id_token" in resp


@pytest.mark.parametrize("registered", [True, False])
@pytest.mark.parametrize("response_mode", ["query", "unknown"])
@pytest.mark.parametrize("user_id", ["1", None])
def test_response_mode_unsupported(
    test_client, server, response_mode, user_id, registered
):
    """The query response mode and unknown response modes are refused.

    The error is returned in the fragment. Before the login, it is returned
    without redirection.
    """
    data = {
        "client_id": "client-id",
        "response_type": "code id_token token",
        "response_mode": response_mode,
        "state": "bar",
        "nonce": "abc",
        "scope": "openid profile",
        "redirect_uri": "https://client.test",
    }
    if user_id:
        data["user_id"] = user_id

    if registered:
        server.register_extension(MultipleResponseTypes())

    with nullcontext() if registered else deprecated_response_mode():
        rv = test_client.post("/oauth/authorize", data=data)

    if not user_id:
        assert rv.status_code == 400
        assert rv.json["error"] == "invalid_request"
        return

    assert rv.status_code == 303
    location = urlparse.urlparse(rv.location)
    assert not location.query
    params = dict(url_decode(location.fragment))
    assert params["error"] == "invalid_request"
    assert params["state"] == "bar"
    assert "code" not in params


@pytest.mark.parametrize("registered", [True, False])
def test_response_mode_form_post(test_client, server, registered):
    if registered:
        register_form_post(server)

    with nullcontext() if registered else deprecated_response_mode():
        rv = test_client.post(
            "/oauth/authorize",
            data={
                "client_id": "client-id",
                "response_type": "code id_token token",
                "response_mode": "form_post",
                "state": "bar",
                "nonce": "abc",
                "scope": "openid profile",
                "redirect_uri": "https://client.test",
                "user_id": "1",
            },
        )

    assert b'name="code"' in rv.data
    assert b'name="id_token"' in rv.data
    assert b'name="access_token"' in rv.data


@pytest.mark.parametrize("user_id", ["1", None])
@pytest.mark.parametrize("registered", [True, False])
def test_response_mode_form_post_values(test_client, server, user_id, registered):
    """The client receives the form_post values unchanged. Without the
    extension, a denial is sent in the fragment, like the other errors."""
    if registered:
        register_form_post(server)

    state = "a b&c\"<>%'"
    data = {
        "client_id": "client-id",
        "response_type": "code id_token token",
        "response_mode": "form_post",
        "state": state,
        "nonce": "abc",
        "scope": "openid profile",
        "redirect_uri": "https://client.test",
    }
    if user_id:
        data["user_id"] = user_id

    with nullcontext() if registered else deprecated_response_mode():
        rv = test_client.post("/oauth/authorize", data=data)

    if not registered and not user_id:
        params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
        assert params["error"] == "access_denied"
        assert params["state"] == state
        return

    assert rv.headers["Cache-Control"] == "no-store"
    form = parse_form(rv.data)
    assert form.action == "https://client.test"
    assert form.values["state"] == state
    if not user_id:
        assert form.values["error_description"] == (
            "The resource owner or authorization server denied the request"
        )


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "javascript://client.test/%0Aalert(1)",
        "JavaScript://client.test/\nalert(1)",
        "com.example.app://client.test/callback",
    ],
)
@pytest.mark.parametrize("user_id", ["1", None])
@pytest.mark.parametrize("default_response_mode", [False, True])
@pytest.mark.parametrize("registered", [False, True])
def test_response_mode_form_post_non_http_redirect_uri(
    test_client,
    server,
    db,
    client,
    monkeypatch,
    redirect_uri,
    user_id,
    default_response_mode,
    registered,
):
    """A form_post response must not target a non-HTTP redirect URI.

    The request is refused before any form is rendered, whether the user
    approves or denies the authorization.
    """
    client.set_client_metadata(
        {
            "redirect_uris": [redirect_uri],
            "scope": "openid profile address",
            "response_types": ["code id_token", "code token", "code id_token token"],
            "grant_types": ["authorization_code"],
            "id_token_signed_response_alg": "HS256",
        }
    )
    db.session.add(client)
    db.session.commit()

    data = {
        "client_id": "client-id",
        "response_type": "code id_token token",
        "response_mode": "form_post",
        "state": "bar",
        "nonce": "abc",
        "scope": "openid profile",
        "redirect_uri": redirect_uri,
    }
    if user_id:
        data["user_id"] = user_id
    if default_response_mode:
        monkeypatch.setattr(_OpenIDHybridGrant, "RESPONSE_MODE", "form_post")
        del data["response_mode"]

    if registered:
        register_form_post(server)

    with (
        nullcontext()
        if default_response_mode or registered
        else deprecated_response_mode()
    ):
        rv = test_client.post("/oauth/authorize", data=data)

    assert rv.status_code == 400
    assert rv.json["error"] == "invalid_request"
    assert rv.location is None
    assert b"<form" not in rv.data


MATRIX_KEYS = {
    "HS256": (OctKey.import_key(HMAC_SECRET),) * 2,
    "HS384": (OctKey.import_key(HMAC_SECRET),) * 2,
    "HS512": (OctKey.import_key(HMAC_SECRET),) * 2,
    "RS256": (
        RSAKey.import_key(read_file_path("jwk_private.json")),
        RSAKey.import_key(read_file_path("jwk_public.json")),
    ),
}


@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512", "RS256"])
@pytest.mark.parametrize(
    "response_type", ["code id_token", "code token", "code id_token token"]
)
def test_response_matrix(test_client, client, db, monkeypatch, alg, response_type):
    """The generated response matches the matrix of its response type, and
    its ID Token passes the validation of the same matrix: the c_hash
    covers the code of the response, the at_hash its access_token, and the
    nonce the one of the request.
    """
    private_key, public_key = MATRIX_KEYS[alg]
    monkeypatch.setattr(
        IDTokenConfigMixin,
        "resolve_client_private_key",
        lambda self, client: private_key,
    )
    client.set_client_metadata(
        {**client.client_metadata, "id_token_signed_response_alg": alg}
    )
    db.session.commit()

    rv = test_client.post(
        "/oauth/authorize",
        data={
            "client_id": "client-id",
            "response_type": response_type,
            "state": "bar",
            "nonce": "abc",
            "scope": "openid profile",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    spec = get_response_type_spec(response_type)

    for name in spec["params"]:
        assert name in params
    for name in ("code", "id_token", "access_token"):
        if name not in spec["params"]:
            assert name not in params

    assert AuthorizationCode.query.count() == 1
    assert Token.query.count() == (1 if "token" in response_type.split() else 0)

    if "id_token" not in spec["params"]:
        return

    token = jwt.decode(params["id_token"], public_key, algorithms=[alg])
    for claim, param in spec["hash_claims"].items():
        expected = to_native(create_half_hash(params[param], alg))
        assert token.claims[claim] == expected
    assert token.claims["nonce"] == "abc"

    params["client_id"] = "client-id"
    validate_claims(params["id_token"], params, alg=alg, key=public_key)


def test_alg_none_is_rejected_atomically(test_client, client, db):
    """The 'none' alg is refused in hybrid flows, before the code and the
    token are saved."""
    client.set_client_metadata(
        {**client.client_metadata, "id_token_signed_response_alg": "none"}
    )
    db.session.commit()
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "client_id": "client-id",
            "response_type": "code id_token token",
            "state": "bar",
            "nonce": "abc",
            "scope": "openid profile",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    assert params["error"] == "invalid_request"
    assert "code" not in params
    assert AuthorizationCode.query.count() == 0
    assert Token.query.count() == 0


def test_generator_missing_access_token(test_client, server):
    """A token generator that omits the access_token of a 'code token'
    response is refused with a minimal error, and nothing is saved."""

    def generate_token(client, grant_type, user, scope, **kwargs):
        return {"token_type": "Bearer", "expires_in": 3600, "scope": scope}

    server.register_token_generator("implicit", generate_token)
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "client_id": "client-id",
            "response_type": "code token",
            "state": "bar",
            "nonce": "abc",
            "scope": "openid profile",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    assert params["error"] == "server_error"
    assert "error_description" not in params
    assert "code" not in params
    assert AuthorizationCode.query.count() == 0
    assert Token.query.count() == 0


def test_generator_duplicate_code(test_client, server):
    """A token generator cannot add a second code to the response."""

    def generate_token(client, grant_type, user, scope, **kwargs):
        return {
            "access_token": "access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": scope,
            "code": "injected-code",
        }

    server.register_token_generator("implicit", generate_token)
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "client_id": "client-id",
            "response_type": "code token",
            "state": "bar",
            "nonce": "abc",
            "scope": "openid profile",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    assert params["error"] == "server_error"
    assert AuthorizationCode.query.count() == 0
    assert Token.query.count() == 0


def test_generator_non_string_access_token(test_client, server):
    """A token generator that returns a non-string access_token is
    refused, and nothing is saved."""

    def generate_token(client, grant_type, user, scope, **kwargs):
        return {
            "access_token": b"raw-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": scope,
        }

    server.register_token_generator("implicit", generate_token)
    rv = test_client.post(
        "/oauth/authorize",
        data={
            "client_id": "client-id",
            "response_type": "code token",
            "state": "bar",
            "nonce": "abc",
            "scope": "openid profile",
            "redirect_uri": "https://client.test",
            "user_id": "1",
        },
    )
    params = dict(url_decode(urlparse.urlparse(rv.location).fragment))
    assert params["error"] == "server_error"
    assert AuthorizationCode.query.count() == 0
    assert Token.query.count() == 0


def make_id_token_claims(**extra):
    now = int(time.time())
    claims = {
        "iss": "Authlib",
        "sub": "1",
        "aud": ["client-id"],
        "exp": now + 3600,
        "iat": now,
        "auth_time": now,
        "nonce": "abc",
    }
    claims.update(extra)
    return claims


def validate_id_token_claims(claims, params, alg="HS256"):
    key = OctKey.import_key(HMAC_SECRET)
    id_token = jwt.encode({"alg": alg}, claims, key, [alg])
    token = jwt.decode(id_token, key, algorithms=[alg])
    HybridIDToken(token.claims, token.header, params=params).validate()


@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
def test_valid_code_id_token_token_claims(alg):
    """The claims of a valid 'code id_token token' response pass the
    validation of the matrix."""
    claims = make_id_token_claims(
        c_hash=to_native(create_half_hash("this-code", alg)),
        at_hash=to_native(create_half_hash("this-token", alg)),
    )
    params = {
        "code": "this-code",
        "access_token": "this-token",
        "nonce": "abc",
        "client_id": "client-id",
    }
    validate_id_token_claims(claims, params, alg=alg)


def test_c_hash_must_cover_the_code_of_the_same_response():
    """A c_hash that covers the code of another response is refused."""
    claims = make_id_token_claims(
        c_hash=to_native(create_half_hash("other-code", "HS256"))
    )
    params = {"code": "this-code", "nonce": "abc", "client_id": "client-id"}
    with pytest.raises(InvalidClaimError, match="c_hash"):
        validate_id_token_claims(claims, params)


def test_at_hash_must_cover_the_access_token_of_the_same_response():
    """An at_hash that covers the access_token of another response is
    refused."""
    claims = make_id_token_claims(
        at_hash=to_native(create_half_hash("other-token", "HS256"))
    )
    params = {
        "access_token": "this-token",
        "nonce": "abc",
        "client_id": "client-id",
    }
    with pytest.raises(InvalidClaimError, match="at_hash"):
        validate_id_token_claims(claims, params)


def test_c_hash_computed_with_another_alg():
    """A c_hash computed with another alg than the JOSE header is
    refused."""
    claims = make_id_token_claims(
        c_hash=to_native(create_half_hash("this-code", "HS512"))
    )
    params = {"code": "this-code", "nonce": "abc", "client_id": "client-id"}
    with pytest.raises(InvalidClaimError, match="c_hash"):
        validate_id_token_claims(claims, params, alg="HS256")


def test_hash_claim_with_wrong_truncation():
    """A c_hash truncated at the wrong length is refused."""
    digest = hashlib.sha256(b"this-code").digest()
    claims = make_id_token_claims(c_hash=to_native(urlsafe_b64encode(digest)))
    params = {"code": "this-code", "nonce": "abc", "client_id": "client-id"}
    with pytest.raises(InvalidClaimError, match="c_hash"):
        validate_id_token_claims(claims, params)


def test_missing_c_hash():
    claims = make_id_token_claims()
    params = {"code": "this-code", "nonce": "abc", "client_id": "client-id"}
    with pytest.raises(MissingClaimError, match="c_hash"):
        validate_id_token_claims(claims, params)


def test_missing_at_hash():
    claims = make_id_token_claims()
    params = {
        "access_token": "this-token",
        "nonce": "abc",
        "client_id": "client-id",
    }
    with pytest.raises(MissingClaimError, match="at_hash"):
        validate_id_token_claims(claims, params)


@pytest.mark.parametrize("c_hash", [123, ["c_hash"], {"c_hash": "x"}])
def test_c_hash_must_be_a_string(c_hash):
    claims = make_id_token_claims(c_hash=c_hash)
    params = {"code": "this-code", "nonce": "abc", "client_id": "client-id"}
    with pytest.raises(InvalidClaimError, match="c_hash"):
        validate_id_token_claims(claims, params)


def test_nonce_mismatch():
    """The nonce of another response is refused."""
    claims = make_id_token_claims(nonce="other-nonce")
    params = {"code": "this-code", "nonce": "abc", "client_id": "client-id"}
    with pytest.raises(InvalidClaimError, match="nonce"):
        validate_id_token_claims(claims, params)


def test_nonce_must_be_a_string():
    claims = make_id_token_claims(nonce=["abc"])
    params = {"code": "this-code", "nonce": "abc", "client_id": "client-id"}
    with pytest.raises(InvalidClaimError, match="nonce"):
        validate_id_token_claims(claims, params)


def test_missing_nonce_claim():
    claims = make_id_token_claims()
    del claims["nonce"]
    params = {"code": "this-code", "nonce": "abc", "client_id": "client-id"}
    with pytest.raises(MissingClaimError, match="nonce"):
        validate_id_token_claims(claims, params)
