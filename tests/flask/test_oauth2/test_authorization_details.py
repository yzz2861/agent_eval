import time
from urllib.parse import quote

import pytest
from flask import json

from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.integrations.sqla_oauth2 import create_query_token_func
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oauth2.rfc6749.grants import RefreshTokenGrant as _RefreshTokenGrant
from authlib.oauth2.rfc7662 import IntrospectionEndpoint
from authlib.oauth2.rfc9396 import AuthorizationDetailsRegistry
from authlib.oauth2.rfc9396 import InvalidAuthorizationDetailsError

from .models import AuthorizationCode
from .models import CodeGrantMixin
from .models import Token
from .models import User
from .models import db
from .models import save_authorization_code
from .oauth2_server import create_basic_header

authorize_url = "/oauth/authorize?response_type=code&client_id=client-id"


def validate_payment(detail, request):
    amount = detail.get("amount")
    if not isinstance(amount, int) or amount <= 0:
        raise InvalidAuthorizationDetailsError("Invalid 'amount' in 'payment'.")


def payment_subsumed(requested, approved):
    return requested.get("amount", 0) <= approved.get("amount", 0)


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


class RefreshTokenGrant(_RefreshTokenGrant):
    def authenticate_refresh_token(self, refresh_token):
        item = Token.query.filter_by(refresh_token=refresh_token).first()
        if item and item.is_refresh_token_active():
            return item

    def authenticate_user(self, credential):
        return db.session.get(User, credential.user_id)

    def revoke_old_credential(self, credential):
        now = int(time.time())
        credential.access_token_revoked_at = now
        credential.refresh_token_revoked_at = now
        db.session.add(credential)
        db.session.commit()


class MyIntrospectionEndpoint(IntrospectionEndpoint):
    def check_permission(self, token, client, request):
        return True

    def query_token(self, token, token_type_hint):
        return create_query_token_func(db.session, Token)(token, token_type_hint)

    def introspect_token(self, token):
        return {
            "active": True,
            "client_id": token.client_id,
            "scope": token.scope,
        }


@pytest.fixture(autouse=True)
def server(server, app):
    server.register_grant(AuthorizationCodeGrant)
    server.register_grant(RefreshTokenGrant)
    server.register_authorization_details_type(
        "payment", validate=validate_payment, is_subsumed=payment_subsumed
    )
    # registered without callables: only exact matches can be narrowed
    server.register_authorization_details_type("account")
    server.register_endpoint(MyIntrospectionEndpoint)

    @app.route("/oauth/introspect", methods=["POST"])
    def introspect_token():
        return server.create_endpoint_response("introspection")

    return server


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "profile",
            "token_endpoint_auth_method": "client_secret_basic",
            "response_types": ["code"],
            "grant_types": ["authorization_code", "refresh_token"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def run_authorize(test_client, details=None, approved=None, raw=None):
    url = authorize_url
    if raw is not None:
        url += "&authorization_details=" + quote(raw)
    elif details is not None:
        url += "&authorization_details=" + quote(json.dumps(details))
    data = {"user_id": "1"}
    if approved is not None:
        data["approved_authorization_details"] = json.dumps(approved)
    return test_client.post(url, data=data)


def get_code(rv):
    assert rv.status_code == 302
    params = dict(url_decode(urlparse.urlparse(rv.location).query))
    return params["code"]


def exchange_code(test_client, code, details=None):
    data = {"grant_type": "authorization_code", "code": code}
    if details is not None:
        data["authorization_details"] = json.dumps(details)
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post("/oauth/token", data=data, headers=headers)
    return json.loads(rv.data)


def test_approved_details_in_token_response(test_client, db):
    requested = [{"type": "payment", "amount": 100}]
    approved = [{"type": "payment", "amount": 50}]
    code = get_code(run_authorize(test_client, requested, approved))

    # the code carries the approved details, not the requested ones
    auth_code = AuthorizationCode.query.filter_by(code=code).one()
    assert auth_code.get_authorization_details() == approved

    resp = exchange_code(test_client, code)
    assert "access_token" in resp
    assert resp["authorization_details"] == approved

    token = Token.query.filter_by(access_token=resp["access_token"]).one()
    assert token.get_authorization_details() == approved


def test_token_request_can_narrow_details(test_client):
    approved = [{"type": "payment", "amount": 50}]
    code = get_code(run_authorize(test_client, approved=approved))
    resp = exchange_code(test_client, code, [{"type": "payment", "amount": 30}])
    assert "access_token" in resp
    assert resp["authorization_details"] == [{"type": "payment", "amount": 30}]


def test_token_request_cannot_widen_details(test_client):
    approved = [{"type": "payment", "amount": 50}]
    code = get_code(run_authorize(test_client, approved=approved))
    resp = exchange_code(test_client, code, [{"type": "payment", "amount": 80}])
    assert resp["error"] == "invalid_authorization_details"


def test_token_request_details_without_grant(test_client):
    code = get_code(run_authorize(test_client))
    resp = exchange_code(test_client, code, [{"type": "payment", "amount": 30}])
    assert resp["error"] == "invalid_authorization_details"


def test_token_request_unknown_type(test_client):
    approved = [{"type": "payment", "amount": 50}]
    code = get_code(run_authorize(test_client, approved=approved))
    resp = exchange_code(test_client, code, [{"type": "unknown"}])
    assert resp["error"] == "invalid_authorization_details"


def test_default_narrowing_requires_exact_match(test_client):
    approved = [{"type": "account", "id": "a1"}]
    code = get_code(run_authorize(test_client, approved=approved))
    resp = exchange_code(test_client, code, [{"type": "account", "id": "a1"}])
    assert "access_token" in resp
    assert resp["authorization_details"] == approved

    code = get_code(run_authorize(test_client, approved=approved))
    resp = exchange_code(test_client, code, [{"type": "account", "id": "a2"}])
    assert resp["error"] == "invalid_authorization_details"


def test_unknown_type_in_authorization_request(test_client):
    rv = run_authorize(test_client, [{"type": "unknown"}])
    assert "error=invalid_authorization_details" in rv.location


def test_invalid_payment_in_authorization_request(test_client):
    rv = run_authorize(test_client, [{"type": "payment", "amount": -1}])
    assert "error=invalid_authorization_details" in rv.location


def test_malformed_json_in_authorization_request(test_client):
    rv = run_authorize(test_client, raw='[{"type": "payment"')
    assert "error=invalid_request" in rv.location


def test_malformed_objects_in_authorization_request(test_client):
    # not a JSON array
    rv = run_authorize(test_client, raw='{"type": "payment", "amount": 1}')
    assert "error=invalid_authorization_details" in rv.location

    # element is not an object
    rv = run_authorize(test_client, raw='["payment"]')
    assert "error=invalid_authorization_details" in rv.location

    # missing type
    rv = run_authorize(test_client, raw='[{"amount": 1}]')
    assert "error=invalid_authorization_details" in rv.location


def test_authorization_details_limits(test_client, server):
    registry = AuthorizationDetailsRegistry(
        max_details_count=1, max_data_length=100, max_data_depth=3
    )
    registry.register("payment")
    server.authorization_details_registry = registry

    # too many objects
    details = [{"type": "payment"}, {"type": "payment"}]
    rv = run_authorize(test_client, details)
    assert "error=invalid_authorization_details" in rv.location

    # value too large
    rv = run_authorize(
        test_client, raw='[{"type": "payment", "pad": "' + "x" * 100 + '"}]'
    )
    assert "error=invalid_authorization_details" in rv.location

    # too deeply nested
    details = [{"type": "payment", "a": {"b": {"c": {"d": 1}}}}]
    rv = run_authorize(test_client, details)
    assert "error=invalid_authorization_details" in rv.location


def test_introspection_returns_approved_details(test_client, db):
    approved = [{"type": "payment", "amount": 50}]
    code = get_code(run_authorize(test_client, approved=approved))
    token = exchange_code(test_client, code)

    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/introspect",
        data={"token": token["access_token"]},
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["active"] is True
    assert resp["authorization_details"] == approved


def test_introspection_without_details(test_client, db, token):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/introspect",
        data={"token": "a1"},
        headers=headers,
    )
    resp = json.loads(rv.data)
    assert resp["active"] is True
    assert "authorization_details" not in resp


def create_refresh_token(db, details):
    item = Token(
        user_id=1,
        client_id="client-id",
        token_type="bearer",
        access_token="a1",
        refresh_token="r1",
        scope="profile",
        expires_in=3600,
        authorization_details=details,
    )
    db.session.add(item)
    db.session.commit()
    return item


def refresh(test_client, details=None):
    data = {"grant_type": "refresh_token", "refresh_token": "r1"}
    if details is not None:
        data["authorization_details"] = json.dumps(details)
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post("/oauth/token", data=data, headers=headers)
    return json.loads(rv.data)


def test_refresh_token_inherits_granted_details(test_client, db):
    granted = [{"type": "payment", "amount": 50}]
    create_refresh_token(db, granted)
    resp = refresh(test_client)
    assert "access_token" in resp
    assert resp["authorization_details"] == granted


def test_refresh_token_can_narrow_details(test_client, db):
    create_refresh_token(db, [{"type": "payment", "amount": 50}])
    resp = refresh(test_client, [{"type": "payment", "amount": 20}])
    assert "access_token" in resp
    assert resp["authorization_details"] == [{"type": "payment", "amount": 20}]


def test_refresh_token_cannot_widen_details(test_client, db):
    create_refresh_token(db, [{"type": "payment", "amount": 50}])
    resp = refresh(test_client, [{"type": "payment", "amount": 100}])
    assert resp["error"] == "invalid_authorization_details"


def test_refresh_token_details_without_grant(test_client, db):
    create_refresh_token(db, None)
    resp = refresh(test_client, [{"type": "payment", "amount": 20}])
    assert resp["error"] == "invalid_authorization_details"
