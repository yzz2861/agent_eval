import json

import pytest
from httpx import WSGITransport

from authlib.common.security import generate_token
from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.integrations.httpx_client import OAuth2Client
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc7636 import CodeChallenge as _CodeChallenge
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from authlib.oauth2.rfc9126 import PushedAuthorizationRequest

from .models import CodeGrantMixin
from .models import User
from .models import db
from .models import save_authorization_code
from .oauth2_server import create_basic_header


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


class CodeChallenge(_CodeChallenge):
    SUPPORTED_CODE_CHALLENGE_METHOD = ["plain", "S256"]


@pytest.fixture(autouse=True)
def configured_client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test/callback"],
            "scope": "profile address",
            "token_endpoint_auth_method": "client_secret_basic",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


@__import__("pytest").fixture(autouse=True)
def par_server(app, server):
    server.register_grant(AuthorizationCodeGrant, [CodeChallenge(required=True)])
    endpoint = PushedAuthorizationRequest()
    server.register_endpoint(endpoint)

    @app.route("/oauth/par", methods=["POST"])
    def par():
        return server.create_endpoint_response(endpoint.ENDPOINT_NAME)

    @app.route("/oauth/authorize_auto")
    def authorize_auto():
        user = db.session.get(User, 1)
        grant = server.get_consent_grant(end_user=user)
        return server.create_authorization_response(grant=grant, grant_user=user)

    return endpoint


def push_authorization_request(test_client, **overrides):
    data = {
        "response_type": "code",
        "redirect_uri": "https://client.test/callback",
        "scope": "profile",
        "state": "pushed-state",
    }
    data.update(overrides)
    response = test_client.post(
        "/oauth/par",
        data=data,
        headers=create_basic_header("client-id", "client-secret"),
    )
    return response, json.loads(response.data) if response.data else None


def test_par_code_flow_with_pkce_and_state(app):
    code_verifier = generate_token(48)
    transport = WSGITransport(app)
    with OAuth2Client(
        "client-id",
        "client-secret",
        redirect_uri="https://client.test/callback",
        scope="profile",
        code_challenge_method="S256",
        base_url="https://server.test",
        transport=transport,
    ) as client:
        url, state = client.create_par_authorization_url(
            "https://server.test/oauth/authorize_auto",
            "https://server.test/oauth/par",
            state="pushed-state",
            code_verifier=code_verifier,
        )

    assert url.startswith(
        "https://server.test/oauth/authorize_auto?request_uri="
        "urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3A"
    )
    assert "response_type=" not in url
    assert "client_id=" not in url
    assert "state=" not in url
    assert "code_challenge=" not in url

    with OAuth2Client(
        "client-id",
        "client-secret",
        redirect_uri="https://client.test/callback",
        base_url="https://server.test",
        transport=WSGITransport(app),
    ) as client:
        response = client.request(
            "GET", url, withhold_token=True, follow_redirects=False
        )
        assert response.status_code == 302
        params = dict(url_decode(urlparse.urlparse(response.headers["location"]).query))
        assert params["state"] == state

        token = client.fetch_token(
            "/oauth/token",
            authorization_response=response.headers["location"],
            state=state,
            code_verifier=code_verifier,
        )

    assert "access_token" in token


def test_par_code_flow_with_public_client_and_pkce(app, configured_client, db):
    configured_client.client_secret = ""
    configured_client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test/callback"],
            "scope": "profile address",
            "token_endpoint_auth_method": "none",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
        }
    )
    db.session.add(configured_client)
    db.session.commit()

    code_verifier = generate_token(48)
    transport = WSGITransport(app)
    with OAuth2Client(
        "client-id",
        token_endpoint_auth_method="none",
        redirect_uri="https://client.test/callback",
        scope="profile",
        code_challenge_method="S256",
        base_url="https://server.test",
        transport=transport,
    ) as client:
        url, state = client.create_par_authorization_url(
            "https://server.test/oauth/authorize_auto",
            "https://server.test/oauth/par",
            state="public-state",
            code_verifier=code_verifier,
        )
        response = client.request(
            "GET", url, withhold_token=True, follow_redirects=False
        )
        token = client.fetch_token(
            "https://server.test/oauth/token",
            authorization_response=response.headers["location"],
            state=state,
            code_verifier=code_verifier,
            redirect_uri="https://client.test/callback",
        )

    assert "access_token" in token


def test_par_query_parameters_do_not_override_pushed_request(
    app, test_client, par_server
):
    _, pushed = push_authorization_request(
        test_client,
        code_challenge=create_s256_code_challenge("original-verifier" * 4),
        code_challenge_method="S256",
    )
    from urllib.parse import urlencode

    url = "/oauth/authorize_auto?" + urlencode(
        {
            "request_uri": pushed["request_uri"],
            "client_id": "client-id",
            "state": "later-state",
            "scope": "address",
            "code_challenge": "changed",
            "code_challenge_method": "plain",
        }
    )
    response = test_client.get(url)
    assert response.status_code == 302
    params = dict(url_decode(urlparse.urlparse(response.location).query))
    assert params["state"] == "pushed-state"

    token_response = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": params["code"],
            "code_verifier": "original-verifier" * 4,
            "redirect_uri": "https://client.test/callback",
        },
        headers=create_basic_header("client-id", "client-secret"),
    )
    assert "access_token" in json.loads(token_response.data)


def test_par_invalid_client_authentication(test_client):
    response = test_client.post(
        "/oauth/par",
        data={
            "response_type": "code",
            "redirect_uri": "https://client.test/callback",
        },
        headers=create_basic_header("client-id", "wrong-secret"),
    )
    assert json.loads(response.data)["error"] == "invalid_client"


def test_par_invalid_authorization_parameters(test_client):
    response, _ = push_authorization_request(
        test_client, response_type=None, state="bad-state"
    )
    assert response.status_code == 302
    assert "error=unsupported_response_type" in response.location


def test_par_request_uri_rejects_other_client_id(test_client):
    _, pushed = push_authorization_request(test_client)
    from urllib.parse import urlencode

    url = "/oauth/authorize?" + urlencode(
        {"request_uri": pushed["request_uri"], "client_id": "other"}
    )
    response = test_client.get(url)
    assert json.loads(response.data)["error"] == "invalid_client"


def test_par_request_uri_is_single_use(test_client):
    _, pushed = push_authorization_request(test_client)
    url = "/oauth/authorize?request_uri=" + pushed["request_uri"]

    assert test_client.get(url).data == b"ok"
    response = test_client.get(url)
    assert json.loads(response.data)["error"] == "invalid_request_uri"


def test_par_request_uri_expires(test_client, par_server):
    _, pushed = push_authorization_request(test_client)
    stored_request = par_server.storage._requests[pushed["request_uri"]]
    stored_request["expires_at"] = 0

    response = test_client.get(
        "/oauth/authorize?request_uri=" + pushed["request_uri"]
    )
    assert json.loads(response.data)["error"] == "invalid_request_uri"
