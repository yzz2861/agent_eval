"""
oauthlib.oauth2.rfc6749
~~~~~~~~~~~~~~~~~~~~~~~

This module is an implementation of various logic needed
for consuming and providing OAuth 2.0 RFC6749.
"""
import logging

from oauthlib.common import Request
from oauthlib.oauth2.rfc6749 import errors as oauth2_errors
from oauthlib.oauth2.rfc6749.client_assertion import (
    JWTClientAssertionValidator,
)
from oauthlib.oauth2.rfc6749 import utils

from .base import BaseEndpoint, catch_errors_and_unavailability

log = logging.getLogger(__name__)


class TokenEndpoint(BaseEndpoint):

    """Token issuing endpoint.

    The token endpoint is used by the client to obtain an access token by
    presenting its authorization grant or refresh token.  The token
    endpoint is used with every authorization grant except for the
    implicit grant type (since an access token is issued directly).

    The means through which the client obtains the location of the token
    endpoint are beyond the scope of this specification, but the location
    is typically provided in the service documentation.

    The endpoint URI MAY include an "application/x-www-form-urlencoded"
    formatted (per `Appendix B`_) query component,
    which MUST be retained when adding additional query parameters.  The
    endpoint URI MUST NOT include a fragment component::

        https://example.com/path?query=component             # OK
        https://example.com/path?query=component#fragment    # Not OK

    Since requests to the token endpoint result in the transmission of
    clear-text credentials (in the HTTP request and response), the
    authorization server MUST require the use of TLS as described in
    Section 1.6 when sending requests to the token endpoint::

        # We will deny any request which URI schema is not with https

    The client MUST use the HTTP "POST" method when making access token
    requests::

        # HTTP method is currently not enforced

    Parameters sent without a value MUST be treated as if they were
    omitted from the request.  The authorization server MUST ignore
    unrecognized request parameters.  Request and response parameters
    MUST NOT be included more than once::

        # Delegated to each grant type.

    .. _`Appendix B`: https://tools.ietf.org/html/rfc6749#appendix-B
    """

    valid_request_methods = ('POST',)

    def __init__(self, default_grant_type, default_token_type, grant_types,
                 client_assertion_validator=None):
        BaseEndpoint.__init__(self)
        self._grant_types = grant_types
        self._default_token_type = default_token_type
        self._default_grant_type = default_grant_type
        self._client_assertion_validator = client_assertion_validator

    @property
    def grant_types(self):
        return self._grant_types

    @property
    def default_grant_type(self):
        return self._default_grant_type

    @property
    def default_grant_type_handler(self):
        return self.grant_types.get(self.default_grant_type)

    @property
    def default_token_type(self):
        return self._default_token_type

    @property
    def client_assertion_validator(self):
        """Lazily build the RFC 7523 assertion lifecycle from a grant.

        Constructed on first use so that deployments which only rely on
        ``client_secret_basic``/``client_secret_post`` pay no setup cost and
        keep their existing behaviour unchanged.
        """
        if self._client_assertion_validator is None:
            grant_handler = next(iter(self.grant_types.values()))
            self._client_assertion_validator = JWTClientAssertionValidator(
                grant_handler.request_validator)
        return self._client_assertion_validator

    @client_assertion_validator.setter
    def client_assertion_validator(self, validator):
        self._client_assertion_validator = validator

    @catch_errors_and_unavailability
    def create_token_response(self, uri, http_method='POST', body=None,
                              headers=None, credentials=None, grant_type_for_scope=None,
                              claims=None):
        """Extract grant_type and route to the designated handler."""
        request = Request(
            uri, http_method=http_method, body=body, headers=headers)
        self.validate_token_request(request)

        try:
            reservation = self._validate_client_assertion(request)
        except oauth2_errors.OAuth2Error as error:
            headers_out = {'Content-Type': 'application/json',
                           'Cache-Control': 'no-store',
                           'Pragma': 'no-cache'}
            headers_out.update(error.headers)
            return headers_out, error.json, error.status_code
        if reservation is not None:
            request.client_assertion_authenticated = True
        # 'scope' is an allowed Token Request param in both the "Resource Owner Password Credentials Grant"
        # and "Client Credentials Grant" flows
        # https://tools.ietf.org/html/rfc6749#section-4.3.2
        # https://tools.ietf.org/html/rfc6749#section-4.4.2
        request.scopes = utils.scope_to_list(request.scope)

        request.extra_credentials = credentials
        if grant_type_for_scope:
            request.grant_type = grant_type_for_scope

        # OpenID Connect claims, if provided.  The server using oauthlib might choose
        # to implement the claims parameter of the Authorization Request.  In this case
        # it should retrieve those claims and pass them via the claims argument here,
        # as a dict.
        if claims:
            request.claims = claims

        grant_type_handler = self.grant_types.get(request.grant_type,
                                                  self.default_grant_type_handler)
        log.debug('Dispatching grant_type %s request to %r.',
                  request.grant_type, grant_type_handler)

        if reservation is None:
            return grant_type_handler.create_token_response(
                request, self.default_token_type)

        # The jti is only reserved at this point. Commit it once the token
        # has actually been issued; roll it back on any failure so a rejected
        # exchange cannot leave the assertion in a consumed state.
        client_id, jti = reservation
        try:
            headers_out, body_out, status = grant_type_handler.create_token_response(
                request, self.default_token_type)
        except oauth2_errors.OAuth2Error:
            self.client_assertion_validator.release_reservation(
                client_id, jti, request)
            raise
        except Exception:
            self.client_assertion_validator.release_reservation(
                client_id, jti, request)
            raise
        if status == 200:
            self.client_assertion_validator.commit_reservation(
                client_id, jti, request)
        else:
            self.client_assertion_validator.release_reservation(
                client_id, jti, request)
        return headers_out, body_out, status

    def _validate_client_assertion(self, request):
        """Run the private_key_jwt lifecycle when an assertion is present.

        Requests without ``client_assertion`` follow the unchanged
        ``client_secret_basic``/``client_secret_post`` path.
        """
        assertion_type = getattr(request, 'client_assertion_type', None)
        assertion = getattr(request, 'client_assertion', None)
        if assertion_type is None and assertion is None:
            return None

        if 'client_assertion' in request.duplicate_params or \
                'client_assertion_type' in request.duplicate_params:
            raise oauth2_errors.InvalidRequestError(
                description='Duplicate client assertion parameter.',
                request=request)
        if assertion_type != (
                'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'):
            raise oauth2_errors.InvalidRequestError(
                description='Unsupported client assertion type.',
                request=request)
        if not assertion:
            raise oauth2_errors.InvalidRequestError(
                description='Missing client assertion parameter.',
                request=request)

        # The lifecycle raises distinct, generic OAuth2Error subclasses whose
        # messages never contain the assertion text or key material.
        return self.client_assertion_validator.validate(assertion, request)

    def validate_token_request(self, request):
        self._raise_on_bad_method(request)
        self._raise_on_bad_post_request(request)
        self._raise_on_bad_content_type(
            request,
            allowed_type='application/x-www-form-urlencoded',
        )
