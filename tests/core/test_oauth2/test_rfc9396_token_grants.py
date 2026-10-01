from types import SimpleNamespace

from authlib.oauth2.rfc6749.grants.client_credentials import ClientCredentialsGrant
from authlib.oauth2.rfc9396 import InvalidAuthorizationDetailsError
from authlib.oauth2.rfc9396.authorization_server import grant_authorization_details
from authlib.oauth2.rfc9396.authorization_server import (
    register_authorization_detail_type,
)
from authlib.oauth2.rfc9396.authorization_server import (
    reject_token_authorization_details,
)
from authlib.oauth2.rfc9396.authorization_server import (
    validate_request_authorization_details,
)

TYPE = "client_permission"


class RequestPayload:
    def __init__(self, data):
        self.data = data
        self.datalist = {key: [value] for key, value in data.items()}


class Request:
    def __init__(self, data):
        self.client = object()
        self.user = None
        self.payload = RequestPayload(data)
        self.authorization_details = None


def test_client_credentials_token_request_uses_approved_details():
    server = SimpleNamespace(_authorization_detail_types={})

    def validator(client, detail, request):
        assert detail["level"] in ("read", "write")

    def narrower(client, detail, user, request):
        assert user is None
        return {"type": TYPE, "level": "read"}

    register_authorization_detail_type(
        server, TYPE, validator, narrower
    )
    request = Request(
        {"authorization_details": f'[{{"type":"{TYPE}","level":"write"}}]'}
    )

    validate_request_authorization_details(server, request)
    granted = grant_authorization_details(server, request, None)

    assert granted == [{"type": TYPE, "level": "read"}]
    assert request.authorization_details == granted


def test_token_request_rejects_expanded_details():
    request = SimpleNamespace(
        form={"authorization_details": '[{"type":"other"}]'}
    )
    try:
        reject_token_authorization_details(request)
    except InvalidAuthorizationDetailsError as error:
        assert error.error == "invalid_authorization_details"
    else:  # pragma: no cover
        raise AssertionError("Expected InvalidAuthorizationDetailsError")


def test_grant_marker_accepts_client_credentials_rar_only():
    assert (
        ClientCredentialsGrant.TOKEN_ENDPOINT_ACCEPTS_AUTHORIZATION_DETAILS
        is True
    )
