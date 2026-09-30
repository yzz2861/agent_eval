import time

from authlib.common.security import generate_token
from authlib.consts import default_json_headers

from ..rfc6749 import InvalidClientError
from ..rfc6749 import InvalidRequestError
from ..rfc6749.endpoint import Endpoint
from ..rfc6749.requests import BasicOAuth2Payload
from .errors import InvalidRequestUriError
from .models import PushedAuthorizationRequestNotFoundError
from .storage import InMemoryPushedAuthorizationRequestStorage


class PushedAuthorizationRequest(Endpoint):
    """RFC 9126 Pushed Authorization Request endpoint."""

    ENDPOINT_NAME = "pushed_authorization_request"
    CLIENT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]
    DEFAULT_EXPIRES_IN = 60
    REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:"

    def __init__(self, server=None, storage=None, expires_in=DEFAULT_EXPIRES_IN):
        super().__init__(server)
        self.storage = storage or InMemoryPushedAuthorizationRequestStorage()
        self.expires_in = expires_in
        if server is not None:
            self.register_hooks(server)

    def __call__(self, request):
        return self.create_endpoint_response(request)

    def validate_request(self, request):
        return self.create_pushed_request(request)

    def create_response(self, pushed_request):
        return (
            200,
            {
                "request_uri": pushed_request.request_uri,
                "expires_in": self.expires_in,
            },
            default_json_headers,
        )

    def create_endpoint_response(self, request):
        pushed_request = self.create_pushed_request(request)
        return self.create_response(pushed_request)

    def create_pushed_request(self, request):
        if request.method != "POST":
            raise InvalidRequestError("The request method MUST be POST.")
        client = self.authenticate_client(request)
        data = self.get_pushed_data(request, client)
        request.payload = BasicOAuth2Payload(data)
        request.client = client

        grant = self.server.get_authorization_grant(request)
        grant.validate_no_multiple_request_parameter(request)
        grant.validate_consent_request()

        request_uri = self.generate_request_uri()
        return self.storage.save(
            request_uri,
            client.get_client_id(),
            data,
            int(time.time()) + self.expires_in,
        )

    def authenticate_client(self, request):
        client = self.server.authenticate_client(
            request, self.CLIENT_AUTH_METHODS, "token"
        )
        request.client = client
        return client

    def get_pushed_data(self, request, client):
        data = {}
        for key in request.form:
            values = request.form.getlist(key)
            if len(values) > 1:
                raise InvalidRequestError(f"Multiple '{key}' in request.")
            data[key] = values[0]

        client_id = client.get_client_id()
        requested_client_id = data.get("client_id")
        if requested_client_id is not None and requested_client_id != client_id:
            raise InvalidRequestError("Mismatching 'client_id' in request.")
        data["client_id"] = client_id

        for key in ("client_secret", "client_assertion", "client_assertion_type"):
            data.pop(key, None)
        for key in ("request", "request_uri"):
            if key in data:
                raise InvalidRequestError(
                    f"The '{key}' parameter is not supported in PAR requests.",
                    state=data.get("state"),
                )
        return data

    def generate_request_uri(self):
        return self.REQUEST_URI_PREFIX + generate_token(48)

    def resolve_authorization_request(self, server, request):
        data = request.payload.data
        request_uri = data.get("request_uri")
        if not request_uri or not request_uri.startswith(self.REQUEST_URI_PREFIX):
            return

        if len(request.payload.datalist.get("request_uri", [])) > 1:
            raise InvalidRequestUriError()

        try:
            pushed_request = self.storage.consume(request_uri)
        except PushedAuthorizationRequestNotFoundError as error:
            raise InvalidRequestUriError() from error

        if (
            data.get("client_id") is not None
            and data["client_id"] != pushed_request.get_client_id()
        ):
            raise InvalidClientError(
                description="The request_uri is bound to another client."
            )

        request.payload = BasicOAuth2Payload(pushed_request.get_data())
        request.client = server.query_client(pushed_request.get_client_id())

    def register_hooks(self, server):
        registered = getattr(server, "_pushed_authorization_requests", None)
        if registered is None:
            registered = server._pushed_authorization_requests = []
        if self not in registered:
            registered.append(self)
            server.register_hook(
                "before_get_authorization_grant", self.resolve_authorization_request
            )
