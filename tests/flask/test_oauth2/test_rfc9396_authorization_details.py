import json
from urllib.parse import quote

import pytest

from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc7662 import IntrospectionEndpoint
from authlib.oauth2.rfc9396 import MAX_AUTHORIZATION_DETAILS_LENGTH

from .models import CodeGrantMixin
from .models import Token
from .models import db
from .models import save_authorization_code
from .oauth2_server import create_basic_header

PAYMENT_TYPE = "payment_initiation"


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "none"]

    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


class MyIntrospectionEndpoint(IntrospectionEndpoint):
    def check_permission(self, token, client, request):
        return True

    def query_token(self, token_string, token_type_hint):
        return (
            db.session.query(Token)
            .filter_by(access_token=token_string)
            .first()
        )

    def introspect_token(self, token):
        return {
            "active": True,
            "client_id": token.client_id,
            "scope": token.scope,
        }


def validate_payment_detail(client, detail, request):
    if not isinstance(detail.get("amount"), int) or detail["amount"] <= 0:
        raise ValueError()


def narrow_payment_details(client, detail, user, request):
    if detail.get("amount", 0) > 10:
        return {**detail, "amount": 10, "action": "read"}
    return detail


@pytest.fixture(autouse=True)
def rar_server(app, server):
    server.register_grant(AuthorizationCodeGrant)
    server.register_endpoint(MyIntrospectionEndpoint)
    server.register_authorization_detail_type(
        PAYMENT_TYPE, validate_payment_detail, narrow_payment_details
    )

    @app.route("/oauth/introspect", methods=["POST"])
    def introspect_token():
        return server.create_endpoint_response("introspection")

    return server


def get_code(test_client, details):
    url = (
        "/oauth/authorize?response_type=code&client_id=client-id"
        "&redirect_uri=https%3A%2F%2Fclient.test%2Fauthorized"
        f"&authorization_details={quote(json.dumps(details))}"
    )
    response = test_client.post(url, data={"user_id": "1"})
    assert response.status_code == 302, response.data
    location = response.location
    if isinstance(location, bytes):
        location = location.decode()
    params = dict(url_decode(urlparse.urlparse(location).query))
    return params["code"]


def exchange_code(test_client, code, authorization_details=None):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "https://client.test/authorized",
    }
    if authorization_details is not None:
        data["authorization_details"] = json.dumps(authorization_details)
    return test_client.post(
        "/oauth/token",
        data=data,
        headers=create_basic_header("client-id", "client-secret"),
    )


def test_approved_details_are_narrowed_and_introspected(
    test_client, client
):
    requested = [
        {"type": PAYMENT_TYPE, "amount": 100, "action": "pay"}
    ]
    approved = [
        {"type": PAYMENT_TYPE, "amount": 10, "action": "read"}
    ]

    code = get_code(test_client, requested)
    response = exchange_code(test_client, code)
    token = response.get_json()

    assert response.status_code == 200
    assert token["authorization_details"] == approved

    introspection = test_client.post(
        "/oauth/introspect",
        data={"token": token["access_token"]},
        headers=create_basic_header("client-id", "client-secret"),
    ).get_json()
    assert introspection["authorization_details"] == approved
    assert introspection["authorization_details"] != requested


def test_token_exchange_cannot_expand_authorization_details(
    test_client, client
):
    requested = [{"type": PAYMENT_TYPE, "amount": 5}]
    code = get_code(test_client, requested)
    expanded = [{"type": PAYMENT_TYPE, "amount": 500, "action": "pay"}]

    response = exchange_code(test_client, code, expanded)
    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_authorization_details"


def test_invalid_authorization_details_request(test_client, client, details):
    url = (
        "/oauth/authorize?response_type=code&client_id=client-id"
        "&redirect_uri=https%3A%2F%2Fclient.test%2Fauthorized"
        f"&authorization_details={quote(details)}"
    )
    response = test_client.post(url, data={"user_id": "1"})

    assert response.status_code == 302
    assert "error=invalid_authorization_details" in response.location


test_invalid_authorization_details_request = pytest.mark.parametrize(
    "details",
    [
        "not-json",
        "{}",
        '[{"amount": 1}]',
        '[{"type": "unknown", "amount": 1}]',
        "x" * (MAX_AUTHORIZATION_DETAILS_LENGTH + 1),
    ],
)(test_invalid_authorization_details_request)


def test_application_validator_rejects_business_rule(test_client, client):
    response = test_client.post(
        "/oauth/authorize?response_type=code&client_id=client-id"
        "&redirect_uri=https%3A%2F%2Fclient.test%2Fauthorized"
        f"&authorization_details={quote(json.dumps([{'type': PAYMENT_TYPE}]))}",
        data={"user_id": "1"},
    )
    assert "error=invalid_authorization_details" in response.location
