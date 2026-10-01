import json
from types import SimpleNamespace

import pytest

from authlib.oauth2.rfc9396 import MAX_AUTHORIZATION_DETAILS
from authlib.oauth2.rfc9396 import MAX_AUTHORIZATION_DETAILS_LENGTH
from authlib.oauth2.rfc9396 import parse_authorization_details
from authlib.oauth2.rfc9396.authorization_server import grant_authorization_details
from authlib.oauth2.rfc9396.authorization_server import (
    register_authorization_detail_type,
)
from authlib.oauth2.rfc9396.authorization_server import (
    validate_request_authorization_details,
)
from authlib.oauth2.rfc9396.errors import InvalidAuthorizationDetailsError

TYPE = "example"


def test_parse_authorization_details():
    value = json.dumps([{"type": TYPE, "level": "read"}])
    assert parse_authorization_details(value) == [
        {"type": TYPE, "level": "read"}
    ]
    assert parse_authorization_details(None) is None


@pytest.mark.parametrize(
    "value",
    [
        "not-json",
        "{}",
        "[\"invalid\"]",
        "[{}]",
        "[{\"type\": 5}]",
        "[{\"type\": \"\"}]",
        "x" * (MAX_AUTHORIZATION_DETAILS_LENGTH + 1),
    ],
)
def test_parse_invalid_authorization_details(value):
    with pytest.raises(InvalidAuthorizationDetailsError):
        parse_authorization_details(value)


def test_registered_type_validates_and_narrows_each_detail():
    calls = []

    def validator(client, detail, request):
        calls.append(("validate", client, detail, request))
        if detail.get("level") == "invalid":
            raise ValueError()

    def narrower(client, detail, user, request):
        calls.append(("narrow", client, detail, user, request))
        return {"type": TYPE, "level": "read"}

    server = SimpleNamespace(_authorization_detail_types={})
    register_authorization_detail_type(
        server, TYPE, validator, narrower
    )
    client = object()
    request = SimpleNamespace(client=client, payload=SimpleNamespace())
    request.payload.data = {
        "authorization_details": json.dumps(
            [
                {"type": TYPE, "level": "write"},
                {"type": TYPE, "level": "write"},
            ]
        )
    }
    request.payload.datalist = {
        "authorization_details": [request.payload.data["authorization_details"]]
    }
    request.user = None

    requested = validate_request_authorization_details(server, request)
    granted = grant_authorization_details(
        server, request, SimpleNamespace(id="user")
    )

    assert requested == [
        {"type": TYPE, "level": "write"},
        {"type": TYPE, "level": "write"},
    ]
    assert granted == [
        {"type": TYPE, "level": "read"},
        {"type": TYPE, "level": "read"},
    ]
    assert [call[0] for call in calls] == [
        "validate",
        "validate",
        "narrow",
        "narrow",
        "validate",
        "validate",
    ]
    assert request.authorization_details == granted
    assert request.authorization_details is not requested


def test_unknown_type_and_application_error_are_protocol_errors():
    request = SimpleNamespace(
        client=None,
        authorization_details=[{"type": "unknown"}],
    )
    with pytest.raises(InvalidAuthorizationDetailsError):
        grant_authorization_details(
            SimpleNamespace(_authorization_detail_types={}), request, None
        )


def test_too_many_authorization_details():
    details = [
        {"type": TYPE} for _ in range(MAX_AUTHORIZATION_DETAILS + 1)
    ]
    with pytest.raises(InvalidAuthorizationDetailsError):
        parse_authorization_details(json.dumps(details))
