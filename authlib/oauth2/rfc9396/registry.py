"""authlib.oauth2.rfc9396.registry.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Registry of ``authorization_details`` types for OAuth 2.0 Rich
Authorization Requests (RFC 9396).

The framework validates the basic JSON structure of the
``authorization_details`` parameter and enforces size limits. The
meaning of each ``type`` is application specific, so validation of
individual objects and the decision of whether requested details are
covered by the details approved by the resource owner are delegated to
functions registered per ``type``.
"""

import json

from ..rfc6749.errors import InvalidRequestError
from .errors import InvalidAuthorizationDetailsError

__all__ = [
    "AuthorizationDetailsRegistry",
    "AuthorizationDetailsType",
    "dumps_authorization_details",
]


class AuthorizationDetailsType:
    """Handler for one ``authorization_details`` type.

    :param type: the ``type`` value of the authorization details object.
    :param validate: optional callable ``validate(detail, request)`` that
        validates one requested authorization details object. It MUST raise
        :class:`InvalidAuthorizationDetailsError` (or return a falsy value)
        when the object is not acceptable.
    :param is_subsumed: optional callable
        ``is_subsumed(requested, approved)`` returning ``True`` when the
        ``requested`` object is covered by the ``approved`` object of the
        same ``type``. When omitted, only an object exactly equal to an
        approved one is accepted.
    """

    def __init__(self, type, validate=None, is_subsumed=None):
        self.type = type
        self._validate = validate
        self._is_subsumed = is_subsumed

    def validate(self, detail, request):
        if self._validate is None:
            return
        if self._validate(detail, request) is False:
            raise InvalidAuthorizationDetailsError(
                f"Invalid authorization details of type '{self.type}'."
            )

    def is_subsumed(self, requested, approved):
        if self._is_subsumed is not None:
            return bool(self._is_subsumed(requested, approved))
        return requested == approved


class AuthorizationDetailsRegistry:
    """Registry of supported ``authorization_details`` types.

    :param max_details_count: maximum number of authorization details
        objects in one ``authorization_details`` parameter.
    :param max_data_length: maximum length in characters of the raw
        ``authorization_details`` JSON value.
    :param max_data_depth: maximum nesting depth of each authorization
        details object.
    """

    MAX_DETAILS_COUNT = 32
    MAX_DATA_LENGTH = 8192
    MAX_DATA_DEPTH = 8

    def __init__(
        self,
        max_details_count=None,
        max_data_length=None,
        max_data_depth=None,
    ):
        self.max_details_count = max_details_count or self.MAX_DETAILS_COUNT
        self.max_data_length = max_data_length or self.MAX_DATA_LENGTH
        self.max_data_depth = max_data_depth or self.MAX_DATA_DEPTH
        self._types = {}

    def register(self, type, validate=None, is_subsumed=None):
        """Register a supported ``authorization_details`` type.

        :param type: the ``type`` value to support.
        :param validate: optional callable to validate one requested
            authorization details object of this type.
        :param is_subsumed: optional callable deciding whether a requested
            object is covered by an approved object of this type.
        :return: the created :class:`AuthorizationDetailsType` handler.
        """
        if not isinstance(type, str) or not type:
            raise ValueError("'type' MUST be a non-empty string")
        handler = AuthorizationDetailsType(type, validate, is_subsumed)
        self._types[type] = handler
        return handler

    def __contains__(self, type):
        return type in self._types

    @property
    def supported_types(self):
        """List of the registered ``authorization_details`` types."""
        return list(self._types)

    def validate_request(self, request):
        """Parse and validate the ``authorization_details`` parameter of
        the given request. Returns the list of authorization details
        objects, or ``None`` when the parameter is absent.

        :param request: OAuth2Request instance.
        """
        raw = request.payload.data.get("authorization_details")
        if raw is None:
            return None
        details = self.parse(raw)
        self.validate_details(details, request)
        return details

    def parse(self, raw):
        """Parse the raw ``authorization_details`` parameter value."""
        if not isinstance(raw, str):
            raise InvalidRequestError("Invalid 'authorization_details' value.")
        if len(raw) > self.max_data_length:
            raise InvalidAuthorizationDetailsError(
                "The 'authorization_details' value exceeds the maximum allowed size."
            )
        try:
            return json.loads(raw)
        except ValueError:
            raise InvalidRequestError(
                "Malformed 'authorization_details' value."
            ) from None

    def validate_details(self, details, request=None):
        """Validate the structure of authorization details objects and run
        the registered ``validate`` callable of each object ``type``.
        """
        self.validate_details_structure(details)
        for detail in details:
            handler = self._types.get(detail["type"])
            if handler is None:
                raise InvalidAuthorizationDetailsError(
                    f"Unknown authorization details type: {detail['type']!r}."
                )
            handler.validate(detail, request)

    def validate_details_structure(self, details):
        """Validate the basic structure of an authorization details list:
        a JSON array of objects, each with a non-empty string ``type``,
        within the configured count and depth limits.
        """
        if not isinstance(details, list):
            raise InvalidAuthorizationDetailsError(
                "The 'authorization_details' value MUST be a JSON array."
            )
        if len(details) > self.max_details_count:
            raise InvalidAuthorizationDetailsError(
                "The 'authorization_details' value contains too many objects."
            )
        for detail in details:
            if not isinstance(detail, dict):
                raise InvalidAuthorizationDetailsError(
                    "Each 'authorization_details' element MUST be a JSON object."
                )
            type_ = detail.get("type")
            if not isinstance(type_, str) or not type_:
                raise InvalidAuthorizationDetailsError(
                    "Each 'authorization_details' element MUST contain a 'type'."
                )
            _check_depth(detail, self.max_data_depth)

    def is_subsumed(self, requested_details, approved_details):
        """Check that every requested authorization details object is
        covered by the approved ones, using the ``is_subsumed`` callable
        registered for each ``type``. The framework does not guess
        containment between business specific objects on its own.
        """
        approved_details = approved_details or []
        for requested in requested_details:
            handler = self._types.get(requested.get("type"))
            if handler is None:
                return False
            candidates = [
                approved
                for approved in approved_details
                if isinstance(approved, dict)
                and approved.get("type") == requested["type"]
            ]
            if not any(
                handler.is_subsumed(requested, approved) for approved in candidates
            ):
                return False
        return True


def _check_depth(value, max_depth, depth=1):
    if depth > max_depth:
        raise InvalidAuthorizationDetailsError(
            "The 'authorization_details' value is too deeply nested."
        )
    if isinstance(value, dict):
        for item in value.values():
            _check_depth(item, max_depth, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _check_depth(item, max_depth, depth + 1)


def dumps_authorization_details(details):
    """Serialize authorization details objects into the JSON string used
    in request parameters. String values are returned unchanged.
    """
    if details is None or isinstance(details, str):
        return details
    return json.dumps(details, separators=(",", ":"))
