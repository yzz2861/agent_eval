from ..rfc6749 import AccessDeniedError
from ..rfc6749 import AuthorizationResponse
from ..rfc6749 import OAuth2Error
from ..rfc6749.grants import BaseGrant
from ..rfc6749.grants.authorization_code import validate_code_authorization_request
from ..rfc6749.grants.base import AuthorizationEndpointMixin


def validate_response_params(params, required=(), forbidden=()):
    """Validate the parameters of an authorization response.

    The response MUST contain the ``required`` parameters, each of them
    exactly once and as a string, it MUST NOT contain the ``forbidden``
    ones, and no parameter MUST appear twice.

    :param params: the ``(name, value)`` pairs of the response
    :param required: the names of the required parameters
    :param forbidden: the names of the forbidden parameters
    :raises OAuth2Error: a ``server_error``, without details, if the
        parameters do not match
    """
    names = [name for name, _ in params]
    values = dict(params)
    if (
        len(names) != len(values)
        or any(not isinstance(values.get(name), str) for name in required)
        or any(name in values for name in forbidden)
    ):
        raise OAuth2Error(error="server_error")


class NoneResponseTypeGrant(BaseGrant, AuthorizationEndpointMixin):
    """The ``none`` response type. The user grants or denies the request, and
    the client receives no code and no token::

        server.register_grant(NoneResponseTypeGrant)

    Per OAuth 2.0 Multiple Response Type Encoding Practices §4, the response
    contains ``state``, and no code or token.
    """

    RESPONSE_TYPES = {"none"}

    #: Per OAuth 2.0 Multiple Response Type Encoding Practices §4, the default
    #: response mode is the query response mode.
    RESPONSE_MODE = "query"

    def validate_authorization_request(self):
        """Validate the client, the redirect URI and the scope of the request.

        :return: the redirect URI
        """
        return validate_code_authorization_request(self)

    def create_authorization_response(self, redirect_uri, grant_user):
        """Redirect the user to the client, with ``state`` if the request has
        one.

        :param redirect_uri: the redirect URI of the request
        :param grant_user: the user, or *None* if the user denied the request
        :return: an :class:`~authlib.oauth2.rfc6749.AuthorizationResponse`
        :raises AccessDeniedError: if the user denied the request
        """
        if not grant_user:
            raise AccessDeniedError(redirect_uri=redirect_uri)

        self.request.user = grant_user
        params = []
        if self.request.payload.state:
            params.append(("state", self.request.payload.state))

        # Per OAuth 2.0 Multiple Response Type Encoding Practices 4, the
        # response contains no code and no token.
        try:
            validate_response_params(
                params, forbidden=("code", "access_token", "id_token")
            )
        except OAuth2Error as error:
            error.redirect_uri = redirect_uri
            raise

        return AuthorizationResponse(
            redirect_uri, params, self.response_mode or self.RESPONSE_MODE
        )
