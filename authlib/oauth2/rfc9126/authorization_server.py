from __future__ import annotations

import time
from dataclasses import dataclass

from authlib.common.security import generate_token
from authlib.consts import default_json_headers

from ..rfc6749 import Endpoint
from ..rfc6749 import EndpointRequest
from ..rfc6749 import InvalidClientError
from ..rfc6749 import InvalidRequestError
from ..rfc6749 import OAuth2Error
from ..rfc6749.requests import BasicOAuth2Payload
from ..rfc6749.requests import OAuth2Request
from .errors import InvalidPushedRequestUriError
from .storage import LocalPushedAuthorizationRequestStorage
from .storage import PushedAuthorizationRequest
from .storage import PushedAuthorizationRequestStorageStatus


@dataclass
class PushedAuthorizationRequestRequest(EndpointRequest):
    pushed_request: PushedAuthorizationRequest | None = None


class PushedAuthorizationRequestEndpoint(Endpoint):
    """RFC 9126 Pushed Authorization Request endpoint."""

    ENDPOINT_NAME = "pushed_authorization_request"
    DEFAULT_EXPIRES_IN = 60
    REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:"

    _EXCLUDED_PARAMETERS = {
        "client_secret",
        "client_assertion",
        "client_assertion_type",
    }

    def __init__(self, server=None, storage=None, expires_in=None):
        super().__init__(server)
        self.storage = storage or LocalPushedAuthorizationRequestStorage()
        self.expires_in = expires_in or self.DEFAULT_EXPIRES_IN

    @property
    def client_auth_methods(self):
        methods = []
        for grant_cls, _extensions in self.server._token_grants:
            for method in grant_cls.TOKEN_ENDPOINT_AUTH_METHODS:
                if method not in methods:
                    methods.append(method)
        return methods or [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ]

    def validate_request(self, request: OAuth2Request):
        if request.method != "POST":
            raise InvalidRequestError("The request method MUST be POST.")

        client = self.server.authenticate_client(
            request, self.client_auth_methods, "token"
        )
        request.client = client

        client_id = request.payload.client_id or client.get_client_id()
        if client_id != client.get_client_id():
            raise InvalidClientError(
                description="The authenticated client does not match 'client_id'."
            )

        parameters = self._extract_parameters(request, client_id)
        self._validate_authorization_request(request, parameters)

        pushed_request = PushedAuthorizationRequest(
            request_uri="",
            client_id=client_id,
            parameters=parameters,
            expires_at=int(time.time()) + self.expires_in,
        )
        return PushedAuthorizationRequestRequest(
            request=request,
            client=client,
            pushed_request=pushed_request,
        )

    def create_response(self, validated_request: PushedAuthorizationRequestRequest):
        pushed_request = validated_request.pushed_request
        request_uri = self.generate_request_uri()
        stored_request = PushedAuthorizationRequest(
            request_uri=request_uri,
            client_id=pushed_request.client_id,
            parameters=pushed_request.parameters,
            expires_at=pushed_request.expires_at,
        )
        self.storage.save(stored_request, self.expires_in)
        body = {
            "request_uri": request_uri,
            "expires_in": self.expires_in,
        }
        return 201, body, default_json_headers

    def resolve_authorization_request(self, request: OAuth2Request):
        request_uri = request.payload.data.get("request_uri")
        if request_uri is None or not request_uri.startswith(self.REQUEST_URI_PREFIX):
            return

        if len(request.payload.datalist.get("request_uri", [])) > 1:
            raise InvalidRequestError("Multiple 'request_uri' in request.")

        client_id = request.payload.client_id
        if client_id is not None:
            if len(request.payload.datalist.get("client_id", [])) > 1:
                raise InvalidClientError(description="Multiple 'client_id' in request.")

        result = self.storage.consume(request_uri, client_id)
        if isinstance(result, PushedAuthorizationRequestStorageStatus):
            descriptions = {
                PushedAuthorizationRequestStorageStatus.EXPIRED: (
                    "The request_uri has expired."
                ),
                PushedAuthorizationRequestStorageStatus.WRONG_CLIENT: (
                    "The request_uri is bound to another client."
                ),
                PushedAuthorizationRequestStorageStatus.ALREADY_CONSUMED: (
                    "The request_uri has already been used."
                ),
            }
            raise InvalidPushedRequestUriError(description=descriptions.get(result))

        request.payload = BasicOAuth2Payload(result.parameters)
        request.pushed_authorization_request = result

    def generate_request_uri(self):
        return self.REQUEST_URI_PREFIX + generate_token(42)

    def _validate_authorization_request(self, request, parameters):
        request.payload = BasicOAuth2Payload(parameters)
        try:
            grant = self.server._get_authorization_grant(request)
            grant.validate_no_multiple_request_parameter(request)
            grant.validate_consent_request()
        except OAuth2Error as error:
            error.redirect_uri = None
            raise

    def _extract_parameters(self, request: OAuth2Request, client_id: str):
        data = request.payload.data
        datalist = request.payload.datalist
        parameters = {}

        for key in data:
            if key == "request_uri":
                raise InvalidRequestError(
                    "The 'request_uri' parameter must not be pushed."
                )
            if key in self._EXCLUDED_PARAMETERS:
                continue
            if len(datalist.get(key, [])) > 1:
                raise InvalidRequestError(f"Multiple '{key}' in request.")
            value = data.get(key)
            if value is not None:
                parameters[key] = value

        parameters.setdefault("client_id", client_id)
        return parameters
