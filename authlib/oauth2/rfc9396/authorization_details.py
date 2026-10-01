import copy
import json

from authlib.common.encoding import json_dumps
from authlib.common.encoding import json_loads

from .errors import InvalidAuthorizationDetailsError

__all__ = [
    "AuthorizationDetailType",
    "MAX_AUTHORIZATION_DETAILS",
    "MAX_AUTHORIZATION_DETAILS_LENGTH",
    "MAX_AUTHORIZATION_DETAIL_TYPE_LENGTH",
    "get_authorization_details",
    "parse_authorization_details",
]

#: Maximum wire length for the authorization_details parameter.
MAX_AUTHORIZATION_DETAILS_LENGTH = 8192
#: Maximum number of authorization detail objects in one request.
MAX_AUTHORIZATION_DETAILS = 100
#: Maximum length of an authorization detail type identifier.
MAX_AUTHORIZATION_DETAIL_TYPE_LENGTH = 255


class AuthorizationDetailType:
    """Application-defined validation and narrowing for one RAR type."""

    def __init__(self, type_name, validator=None, narrower=None):
        self.type_name = type_name
        self._validator = validator
        self._narrower = narrower

    def validate(self, client, detail, request):
        """Validate a requested detail object. Raise an OAuth2Error on failure."""
        if self._validator is None:
            return
        self._validator(client, detail, request)

    def narrow(self, client, detail, user, request):
        """Return the detail actually approved by the resource owner."""
        if self._narrower is None:
            return detail
        return self._narrower(client, detail, user, request)


def parse_authorization_details(value, *, multiple=False):
    """Parse and validate the structural shape of RFC 9396 details."""
    if multiple:
        raise InvalidAuthorizationDetailsError(
            "Multiple 'authorization_details' in request."
        )

    if value is None:
        return None

    if not isinstance(value, str):
        raise InvalidAuthorizationDetailsError()

    if len(value) > MAX_AUTHORIZATION_DETAILS_LENGTH:
        raise InvalidAuthorizationDetailsError(
            "'authorization_details' exceeds the maximum allowed length."
        )

    try:
        details = json_loads(value)
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        raise InvalidAuthorizationDetailsError() from error

    return validate_authorization_details_structure(details)


def validate_authorization_details_structure(details):
    if not isinstance(details, list):
        raise InvalidAuthorizationDetailsError()

    if len(details) > MAX_AUTHORIZATION_DETAILS:
        raise InvalidAuthorizationDetailsError(
            "'authorization_details' exceeds the maximum number of objects."
        )

    for detail in details:
        if not isinstance(detail, dict):
            raise InvalidAuthorizationDetailsError()

        type_name = detail.get("type")
        if not isinstance(type_name, str) or not type_name:
            raise InvalidAuthorizationDetailsError()

        if len(type_name) > MAX_AUTHORIZATION_DETAIL_TYPE_LENGTH:
            raise InvalidAuthorizationDetailsError(
                "'type' exceeds the maximum allowed length."
            )

    return details


def get_authorization_details(value):
    """Read persisted details from either JSON data or a JSON-encoded string."""
    if value is None:
        return None

    if isinstance(value, str):
        try:
            value = json_loads(value)
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            raise InvalidAuthorizationDetailsError() from error

    details = validate_authorization_details_structure(value)
    encoded_length = len(json_dumps(details))
    if encoded_length > MAX_AUTHORIZATION_DETAILS_LENGTH:
        raise InvalidAuthorizationDetailsError(
            "'authorization_details' exceeds the maximum allowed length."
        )
    return details


def dump_authorization_details(details):
    if details is None:
        return None
    return json_dumps(validate_authorization_details_structure(details))


def read_request_authorization_details(request):
    values = request.payload.datalist.get("authorization_details", [])
    value = request.payload.data.get("authorization_details")
    return parse_authorization_details(value, multiple=len(values) > 1)


def copy_authorization_details(details):
    if details is None:
        return None
    return copy.deepcopy(validate_authorization_details_structure(details))
