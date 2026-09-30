import time

import pytest
import requests
from flask import json
from joserfc import jwk
from joserfc import jwt

from authlib.common.security import generate_token
from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.integrations.requests_client import OAuth2Session
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc7636 import CodeChallenge as _CodeChallenge
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from authlib.oauth2.rfc9101 import JWTAuthenticationRequest
from tests.util import read_file_path

from .models import CodeGrantMixin
from .models import save_authorization_code
from .oauth2_server import create_basic_header


@pytest.fixture
def app(app):
    app.config["OAUTH2_ENABLE_PAR"] = True
    return app


class WSGIAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, app):
        super().__init__()
        self.app = app

    def send(self, request, *args, **kwargs):
        parsed = urlparse.urlsplit(request.url)
        data = request.body
        if isinstance(data, str):
            data = data.encode()

        response = requests.Response()
        response.request = request
        client = self.app.test_client()
        rv = client.open(
            parsed.path,
            query_string=parsed.query,
            method=request.method,
            data=data,
            headers={key: value for key, value in request.headers.items()},
        )
        response.status_code = rv.status_code
        response._content = rv.data
        response.headers.update(rv.headers)
        response.url = request.url
        response.encoding = "utf-8"
        return response


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


@pytest.fixture(autouse=True)
def server(server):
    server.register_grant(AuthorizationCodeGrant, [_CodeChallenge(required=True)])
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
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def push_authorization(test_client, **overrides):
    data = {
        "response_type": "code",
        "client_id": "client-id",
        "redirect_uri": "https://client.test",
        "scope": "profile",
        "state": "pushed-state",
    }
    headers = overrides.pop(
        "headers", create_basic_header("client-id", "client-secret")
    )
    data.update(overrides)
    if overrides.get("client_id") is None:
        data.pop("client_id", None)
    return test_client.post("/oauth/par", data=data, headers=headers)


def test_push_and_consume_authorization_code_flow(app, test_client):
    verifier = generate_token(48)
    challenge = create_s256_code_challenge(verifier)
    rv = push_authorization(
        test_client,
        code_challenge=challenge,
        code_challenge_method="S256",
    )

    assert rv.status_code == 201
    response = json.loads(rv.data)
    assert response["expires_in"] == 60
    request_uri = response["request_uri"]
    assert request_uri.startswith("urn:ietf:params:oauth:request_uri:")

    authorize_url = f"/oauth/authorize?request_uri={request_uri}&client_id=client-id"
    rv = test_client.post(authorize_url, data={"user_id": "1"})
    assert rv.status_code == 302
    location = rv.location
    assert "response_type=" not in location
    assert "code_challenge=" not in location
    assert "state=pushed-state" in location

    params = dict(url_decode(urlparse.urlparse(location).query))
    assert params["state"] == "pushed-state"

    with OAuth2Session(redirect_uri="https://client.test") as oauth_client:
        oauth_client.mount("http://", WSGIAdapter(app))
        token = oauth_client.fetch_token(
            "http://provider.test/oauth/token",
            grant_type="authorization_code",
            code=params["code"],
            state="pushed-state",
            auth=("client-id", "client-secret"),
            code_verifier=verifier,
        )

    assert "access_token" in token

    rv = test_client.post(authorize_url)
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_request_uri"


def test_pushed_parameters_cannot_be_overridden(test_client):
    rv = push_authorization(test_client, scope="profile", state="original-state")
    request_uri = json.loads(rv.data)["request_uri"]
    authorize_url = (
        f"/oauth/authorize?request_uri={request_uri}&client_id=client-id"
        "&scope=address&state=later-state"
    )

    rv = test_client.post(authorize_url, data={"user_id": "1"})
    assert "state=original-state" in rv.location
    assert "state=later-state" not in rv.location


def test_wrong_client_is_invalid_request_uri(test_client):
    rv = push_authorization(test_client)
    request_uri = json.loads(rv.data)["request_uri"]
    rv = test_client.get(
        f"/oauth/authorize?request_uri={request_uri}&client_id=other-client"
    )

    response = json.loads(rv.data)
    assert response["error"] == "invalid_request_uri"
    assert "another client" in response["error_description"]


def test_expired_request_uri(test_client, server):
    endpoint = server._endpoints["pushed_authorization_request"][0]
    endpoint.expires_in = 0
    rv = push_authorization(test_client)
    request_uri = json.loads(rv.data)["request_uri"]
    time.sleep(0.01)

    rv = test_client.get(
        f"/oauth/authorize?request_uri={request_uri}&client_id=client-id"
    )
    response = json.loads(rv.data)
    assert response["error"] == "invalid_request_uri"
    assert "expired" in response["error_description"]


def test_par_requires_client_authentication(test_client):
    rv = push_authorization(test_client, headers=None)
    response = json.loads(rv.data)
    assert response["error"] == "invalid_client"


def test_basic_client_id_in_body_is_optional(test_client):
    rv = push_authorization(test_client, client_id=None)
    assert rv.status_code == 201


def test_public_client_par(test_client, client, db):
    client.client_secret = ""
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "profile address",
            "token_endpoint_auth_method": "none",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(client)
    db.session.commit()

    rv = test_client.post(
        "/oauth/par",
        data={
            "response_type": "code",
            "client_id": "client-id",
            "redirect_uri": "https://client.test",
            "code_challenge": create_s256_code_challenge(generate_token(48)),
            "code_challenge_method": "S256",
        },
    )
    assert rv.status_code == 201


def test_client_secret_post_par(test_client, client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "profile address",
            "token_endpoint_auth_method": "client_secret_post",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(client)
    db.session.commit()

    rv = test_client.post(
        "/oauth/par",
        data={
            "response_type": "code",
            "client_id": "client-id",
            "client_secret": "client-secret",
            "redirect_uri": "https://client.test",
        },
    )
    assert rv.status_code == 201


def test_pushed_request_uri_is_rejected(test_client):
    rv = push_authorization(
        test_client,
        request_uri="urn:ietf:params:oauth:request_uri:existing",
    )
    response = json.loads(rv.data)
    assert response["error"] == "invalid_request"


def test_invalid_pushed_scope_is_rejected(test_client, server):
    server.scopes_supported = ["profile"]
    rv = push_authorization(test_client, scope="invalid")
    response = json.loads(rv.data)
    assert response["error"] == "invalid_scope"


def test_invalid_pushed_code_challenge_is_rejected(test_client):
    rv = push_authorization(
        test_client,
        code_challenge="abc",
        code_challenge_method="S256",
    )
    response = json.loads(rv.data)
    assert response["error"] == "invalid_request"
    assert "code_challenge" in response["error_description"].lower()


def test_pushed_request_object_is_decoded(test_client, server):
    class RequestObjectExtension(JWTAuthenticationRequest):
        def resolve_client_public_key(self, client):
            return read_file_path("jwk_public.json")

        def get_server_metadata(self):
            return {}

        def get_client_require_signed_request_object(self, client):
            return False

    server.register_extension(RequestObjectExtension())
    request_object = jwt.encode(
        {"alg": "RS256"},
        {
            "response_type": "code",
            "client_id": "client-id",
            "redirect_uri": "https://client.test",
            "state": "request-object-state",
        },
        jwk.import_key(read_file_path("jwk_private.json")),
    )
    rv = push_authorization(test_client, request=request_object)
    request_uri = json.loads(rv.data)["request_uri"]

    rv = test_client.get(
        f"/oauth/authorize?request_uri={request_uri}&client_id=client-id"
    )
    assert rv.data == b"ok"


def test_client_builds_pushed_authorization_url(app):
    with OAuth2Session(
        client_id="client-id",
        client_secret="client-secret",
        redirect_uri="https://client.test",
        scope="profile",
    ) as client:
        client.mount("http://", WSGIAdapter(app))
        result = client.create_pushed_authorization_url(
            "http://provider.test/oauth/authorize",
            "http://provider.test/oauth/par",
            state="client-state",
        )

    assert "response_type=" not in result["url"]
    assert "request_uri=" in result["url"]
    assert "client_id=" not in result["url"]
    assert result["state"] == "client-state"
