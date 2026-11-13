"""
oauthlib.oauth2.rfc6749.request_validator
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import inspect
import logging

log = logging.getLogger(__name__)


class RequestValidator:

    # Return values for the one-time ``jti`` hooks. They make the difference
    # between a replayed assertion and two concurrent exchanges explicit,
    # without requiring host applications to raise library-specific errors.
    JTI_ACCEPTED = 'accepted'
    JTI_REPLAYED = 'replayed'
    JTI_CONCURRENT = 'concurrent'
    JTI_CLOCK_ROLLBACK = 'clock_rollback'

    def client_authentication_required(self, request, *args, **kwargs):
        """Determine if client authentication is required for current request.

        According to the rfc6749, client authentication is required in the following cases:
            - Resource Owner Password Credentials Grant, when Client type is Confidential or when
              Client was issued client credentials or whenever Client provided client
              authentication, see `Section 4.3.2`_.
            - Authorization Code Grant, when Client type is Confidential or when Client was issued
              client credentials or whenever Client provided client authentication,
              see `Section 4.1.3`_.
            - Refresh Token Grant, when Client type is Confidential or when Client was issued
              client credentials or whenever Client provided client authentication, see
              `Section 6`_

        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Resource Owner Password Credentials Grant
            - Refresh Token Grant

        .. _`Section 4.3.2`: https://tools.ietf.org/html/rfc6749#section-4.3.2
        .. _`Section 4.1.3`: https://tools.ietf.org/html/rfc6749#section-4.1.3
        .. _`Section 6`: https://tools.ietf.org/html/rfc6749#section-6
        """
        return True

    def authenticate_client(self, request, *args, **kwargs):
        """Authenticate client through means outside the OAuth 2 spec.

        Means of authentication is negotiated beforehand and may for example
        be `HTTP Basic Authentication Scheme`_ which utilizes the Authorization
        header.

        Headers may be accesses through request.headers and parameters found in
        both body and query can be obtained by direct attribute access, i.e.
        request.client_id for client_id in the URL query.

        The authentication process is required to contain the identification of
        the client (i.e. search the database based on the client_id). In case the
        client doesn't exist based on the received client_id, this method has to
        return False and the HTTP response created by the library will contain
        'invalid_client' message.

        After the client identification succeeds, this method needs to set the
        client on the request, i.e. request.client = client. A client object's
        class must contain the 'client_id' attribute and the 'client_id' must have
        a value.

        This method MUST NOT be used to authenticate public clients. Public
        clients do not authenticate through means outside the OAuth 2 spec and
        are instead validated by :meth:`authenticate_client_id`. If the client
        is public, this method must return False.

        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Resource Owner Password Credentials Grant (may be disabled)
            - Client Credentials Grant
            - Refresh Token Grant
            - Device Code Grant

        .. _`HTTP Basic Authentication Scheme`: https://tools.ietf.org/html/rfc1945#section-11.1
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        """Ensure client_id belong to a non-confidential client.

        A non-confidential client is one that is not required to authenticate
        through other means, such as using HTTP Basic.

        After the client identification succeeds, this method needs to set the
        client on the request, i.e. request.client = client. A client object's
        class must contain the 'client_id' attribute and the 'client_id' must have
        a value.

        :param client_id: Unicode client identifier.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Resource Owner Password Credentials Grant
            - Refresh Token Grant
            - Device Code Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, request,
                             *args, **kwargs):
        """Ensure that the authorization process represented by this authorization
        code began with this 'redirect_uri'.

        If the client specifies a redirect_uri when obtaining code then that
        redirect URI must be bound to the code and verified equal in this
        method, according to RFC 6749 section 4.1.3.  Do not compare against
        the client's allowed redirect URIs, but against the URI used when the
        code was saved.

        :param client_id: Unicode client identifier.
        :param code: Unicode authorization_code.
        :param redirect_uri: Unicode absolute URI.
        :param client: Client object set by you, see ``.authenticate_client``.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant (during token request)
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        """Get the default redirect URI for the client.

        :param client_id: Unicode client identifier.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: The default redirect URI for the client

        Method is used by:
            - Authorization Code Grant
            - Implicit Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        """Get the default scopes for the client.

        :param client_id: Unicode client identifier.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: List of default scopes

        Method is used by all core grant types:
            - Authorization Code Grant
            - Implicit Grant
            - Resource Owner Password Credentials Grant
            - Client Credentials grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        """Get the list of scopes associated with the refresh token.

        :param refresh_token: Unicode refresh token.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: List of scopes.

        Method is used by:
            - Refresh token grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def is_within_original_scope(self, request_scopes, refresh_token, request, *args, **kwargs):
        """Check if requested scopes are within a scope of the refresh token.

        When access tokens are refreshed the scope of the new token
        needs to be within the scope of the original token. This is
        ensured by checking that all requested scopes strings are on
        the list returned by the get_original_scopes. If this check
        fails, is_within_original_scope is called. The method can be
        used in situations where returning all valid scopes from the
        get_original_scopes is not practical.

        :param request_scopes: A list of scopes that were requested by client.
        :param refresh_token: Unicode refresh_token.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Refresh token grant
        """
        return False

    def introspect_token(self, token, token_type_hint, request, *args, **kwargs):
        """Introspect an access or refresh token.

        Called once the introspect request is validated. This method should
        validate the *token*. If the token is currently active, this should return
        a dictionary with the claims associated. If the token is for any reason
        not active (expired, unknown, etc.), this should return `None`. The
        introspection endpoint will then treat any non-``None`` return value as
        an active token, force ``"active": true`` in the response, and ignore or
        remove any ``"active"`` key provided by this method (so returning
        ``{"active": false, ...}`` will not work to mark a token as inactive).

        Below the list of registered claims you should be interested in:

        - scope : space-separated list of scopes
        - client_id : client identifier
        - username : human-readable identifier for the resource owner
        - token_type : type of the token
        - exp : integer timestamp indicating when this token will expire
        - iat : integer timestamp indicating when this token was issued
        - nbf : integer timestamp indicating when it can be "not-before" used
        - sub : subject of the token - identifier of the resource owner
        - aud : list of string identifiers representing the intended audience
        - iss : string representing issuer of this token
        - jti : string identifier for the token

        Note that most of them are coming directly from JWT RFC. More details
        can be found in `Introspect Claims`_ or `JWT Claims`_.

        The implementation can use *token_type_hint* to improve lookup
        efficiency, but must fallback to other types to be compliant with RFC.

        The dict of claims is added to request.token after this method.

        :param token: The token string.
        :param token_type_hint: access_token or refresh_token.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request

        Method is used by:
            - Introspect Endpoint (all grants are compatible)

        .. _`Introspect Claims`: https://tools.ietf.org/html/rfc7662#section-2.2
        .. _`JWT Claims`: https://tools.ietf.org/html/rfc7519#section-4
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        """Invalidate an authorization code after use.

        :param client_id: Unicode client identifier.
        :param code: The authorization code grant (request.code).
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request

        Method is used by:
            - Authorization Code Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def revoke_token(self, token, token_type_hint, request, *args, **kwargs):
        """Revoke an access or refresh token.

        :param token: The token string.
        :param token_type_hint: access_token or refresh_token.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request

        Method is used by:
            - Revocation Endpoint
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def rotate_refresh_token(self, request):
        """Determine whether to rotate the refresh token. Default, yes.

        When access tokens are refreshed the old refresh token can be kept
        or replaced with a new one (rotated). Return True to rotate and
        and False for keeping original.

        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Refresh Token Grant
        """
        return True

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        """Persist the authorization_code.

        The code should at minimum be stored with:
            - the client_id (``client_id``)
            - the redirect URI used (``request.redirect_uri``)
            - a resource owner / user (``request.user``)
            - the authorized scopes (``request.scopes``)

        To support PKCE, you MUST associate the code with:
            - Code Challenge (``request.code_challenge``) and
            - Code Challenge Method (``request.code_challenge_method``)

        To support OIDC, you MUST associate the code with:
            - nonce, if present (``code["nonce"]``)

        The ``code`` argument is actually a dictionary, containing at least a
        ``code`` key with the actual authorization code:

            ``{'code': 'sdf345jsdf0934f'}``

        It may also have a ``claims`` parameter which, when present, will be a dict
        deserialized from JSON as described at
        http://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
        This value should be saved in this method and used again in ``.validate_code``.

        :param client_id: Unicode client identifier.
        :param code: A dict of the authorization code grant and, optionally, state.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request

        Method is used by:
            - Authorization Code Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def save_token(self, token, request, *args, **kwargs):
        """Persist the token with a token type specific method.

        Currently, only save_bearer_token is supported.

        :param token: A (Bearer) token dict.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """
        return self.save_bearer_token(token, request, *args, **kwargs)

    def save_bearer_token(self, token, request, *args, **kwargs):
        """Persist the Bearer token.

        The Bearer token should at minimum be associated with:
            - a client and it's client_id, if available
            - a resource owner / user (request.user)
            - authorized scopes (request.scopes)
            - an expiration time
            - a refresh token, if issued
            - a claims document, if present in request.claims

        The Bearer token dict may hold a number of items::

            {
                'token_type': 'Bearer',
                'access_token': 'askfjh234as9sd8',
                'expires_in': 3600,
                'scope': 'string of space separated authorized scopes',
                'refresh_token': '23sdf876234',  # if issued
                'state': 'given_by_client',  # if supplied by client (implicit ONLY)
            }

        Note that while "scope" is a string-separated list of authorized scopes,
        the original list is still available in request.scopes.

        The token dict is passed as a reference so any changes made to the dictionary
        will go back to the user.  If additional information must return to the client
        user, and it is only possible to get this information after writing the token
        to storage, it should be added to the token dictionary.  If the token
        dictionary must be modified but the changes should not go back to the user,
        a copy of the dictionary must be made before making the changes.

        Also note that if an Authorization Code grant request included a valid claims
        parameter (for OpenID Connect) then the request.claims property will contain
        the claims dict, which should be saved for later use when generating the
        id_token and/or UserInfo response content.

        :param token: A Bearer token dict.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: The default redirect URI for the client

        Method is used by all core grant types issuing Bearer tokens:
            - Authorization Code Grant
            - Implicit Grant
            - Resource Owner Password Credentials Grant (might not associate a client)
            - Client Credentials grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_bearer_token(self, token, scopes, request):
        """Ensure the Bearer token is valid and authorized access to scopes.

        :param token: A string of random characters.
        :param scopes: A list of scopes associated with the protected resource.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request

        A key to OAuth 2 security and restricting impact of leaked tokens is
        the short expiration time of tokens, *always ensure the token has not
        expired!*.

        Two different approaches to scope validation:

            1) all(scopes). The token must be authorized access to all scopes
                            associated with the resource. For example, the
                            token has access to ``read-only`` and ``images``,
                            thus the client can view images but not upload new.
                            Allows for fine grained access control through
                            combining various scopes.

            2) any(scopes). The token must be authorized access to one of the
                            scopes associated with the resource. For example,
                            token has access to ``read-only-images``.
                            Allows for fine grained, although arguably less
                            convenient, access control.

        A powerful way to use scopes would mimic UNIX ACLs and see a scope
        as a group with certain privileges. For a restful API these might
        map to HTTP verbs instead of read, write and execute.

        Note, the request.user attribute can be set to the resource owner
        associated with this token. Similarly the request.client and
        request.scopes attribute can be set to associated client object
        and authorized scopes. If you then use a decorator such as the
        one provided for django these attributes will be made available
        in all protected views as keyword arguments.

        :param token: Unicode Bearer token
        :param scopes: List of scopes (defined by you)
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: True or False

        Method is indirectly used by all core Bearer token issuing grant types:
            - Authorization Code Grant
            - Implicit Grant
            - Resource Owner Password Credentials Grant
            - Client Credentials Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_client_id(self, client_id, request, *args, **kwargs):
        """Ensure client_id belong to a valid and active client.

        After the client identification succeeds, this method needs to set the
        client on the request, i.e. request.client = client. A client object's
        class must contain the 'client_id' attribute and the 'client_id' must have
        a value.

        :param client_id: Unicode client identifier.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Implicit Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        """Verify that the authorization_code is valid and assigned to the given
        client.

        Before returning true, set the following based on the information stored
        with the code in 'save_authorization_code':

            - request.user
            - request.scopes
            - request.claims (if given)

        OBS! The request.user attribute should be set to the resource owner
        associated with this authorization code. Similarly request.scopes
        must also be set.

        The request.claims property, if it was given, should assigned a dict.

        If PKCE is enabled (see 'is_pkce_required' and 'save_authorization_code')
        you MUST set the following based on the information stored:

            - request.code_challenge
            - request.code_challenge_method

        :param client_id: Unicode client identifier.
        :param code: Unicode authorization code.
        :param client: Client object set by you, see ``.authenticate_client``.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        """Ensure client is authorized to use the grant_type requested.

        :param client_id: Unicode client identifier.
        :param grant_type: Unicode grant type, i.e. authorization_code, password.
        :param client: Client object set by you, see ``.authenticate_client``.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Resource Owner Password Credentials Grant
            - Client Credentials Grant
            - Refresh Token Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        """Ensure client is authorized to redirect to the redirect_uri requested.

        All clients should register the absolute URIs of all URIs they intend
        to redirect to. The registration is outside of the scope of oauthlib.

        :param client_id: Unicode client identifier.
        :param redirect_uri: Unicode absolute URI.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Implicit Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        """Ensure the Bearer token is valid and authorized access to scopes.

        OBS! The request.user attribute should be set to the resource owner
        associated with this refresh token.

        :param refresh_token: Unicode refresh token.
        :param client: Client object set by you, see ``.authenticate_client``.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant (indirectly by issuing refresh tokens)
            - Resource Owner Password Credentials Grant (also indirectly)
            - Refresh Token Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        """Ensure client is authorized to use the response_type requested.

        :param client_id: Unicode client identifier.
        :param response_type: Unicode response type, i.e. code, token.
        :param client: Client object set by you, see ``.authenticate_client``.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Implicit Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        """Ensure the client is authorized access to requested scopes.

        :param client_id: Unicode client identifier.
        :param scopes: List of scopes (defined by you).
        :param client: Client object set by you, see ``.authenticate_client``.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: True or False

        Method is used by all core grant types:
            - Authorization Code Grant
            - Implicit Grant
            - Resource Owner Password Credentials Grant
            - Client Credentials Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_user(self, username, password, client, request, *args, **kwargs):
        """Ensure the username and password is valid.

        OBS! The validation should also set the user attribute of the request
        to a valid resource owner, i.e. request.user = username or similar. If
        not set you will be unable to associate a token with a user in the
        persistence method used (commonly, save_bearer_token).

        :param username: Unicode username.
        :param password: Unicode password.
        :param client: Client object set by you, see ``.authenticate_client``.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Resource Owner Password Credentials Grant
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def is_pkce_required(self, client_id, request):
        """Determine if current request requires PKCE. Default, False.
        This is called for both "authorization" and "token" requests.

        Override this method by ``return True`` to enable PKCE for everyone.
        You might want to enable it only for public clients.
        Note that PKCE can also be used in addition of a client authentication.

        OAuth 2.0 public clients utilizing the Authorization Code Grant are
        susceptible to the authorization code interception attack.  This
        specification describes the attack as well as a technique to mitigate
        against the threat through the use of Proof Key for Code Exchange
        (PKCE, pronounced "pixy"). See `RFC7636`_.

        :param client_id: Client identifier.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant

        .. _`RFC7636`: https://tools.ietf.org/html/rfc7636
        """
        return False

    def get_code_challenge(self, code, request):
        """Is called for every "token" requests.

        When the server issues the authorization code in the authorization
        response, it MUST associate the ``code_challenge`` and
        ``code_challenge_method`` values with the authorization code so it can
        be verified later.

        Typically, the ``code_challenge`` and ``code_challenge_method`` values
        are stored in encrypted form in the ``code`` itself but could
        alternatively be stored on the server associated with the code.  The
        server MUST NOT include the ``code_challenge`` value in client requests
        in a form that other entities can extract.

        Return the ``code_challenge`` associated to the code.
        If ``None`` is returned, code is considered to not be associated to any
        challenges.

        :param code: Authorization code.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: code_challenge string

        Method is used by:
            - Authorization Code Grant - when PKCE is active

        """
        return None

    def get_code_challenge_method(self, code, request):
        """Is called during the "token" request processing, when a
        ``code_verifier`` and a ``code_challenge`` has been provided.

        See ``.get_code_challenge``.

        Must return ``plain`` or ``S256``. You can return a custom value if you have
        implemented your own ``AuthorizationCodeGrant`` class.

        :param code: Authorization code.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: code_challenge_method string

        Method is used by:
            - Authorization Code Grant - when PKCE is active

        """
        raise NotImplementedError('Subclasses must implement this method.')

    def is_origin_allowed(self, client_id, origin, request, *args, **kwargs):
        """Indicate if the given origin is allowed to access the token endpoint
        via Cross-Origin Resource Sharing (CORS).  CORS is used by browser-based
        clients, such as Single-Page Applications, to perform the Authorization
        Code Grant.

        (Note:  If performing Authorization Code Grant via a public client such
        as a browser, you should use PKCE as well.)

        If this method returns true, the appropriate CORS headers will be added
        to the response.  By default this method always returns False, meaning
        CORS is disabled.

        :param client_id: Unicode client identifier.
        :param redirect_uri: Unicode origin.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: bool

        Method is used by:
            - Authorization Code Grant
            - Refresh Token Grant

        """
        return False

    # ------------------------------------------------------------------
    # private_key_jwt client assertion lifecycle (RFC 7523)
    #
    # These hooks are intentionally optional. Two deployment shapes are
    # supported:
    #
    # * A host application provides the signature verification key(s), the
    #   clock and an atomic, durable jti store by overriding the hooks below
    #   (for example reserving a row behind a unique index and committing or
    #   releasing it around token issuance).
    # * Tests and single-process deployments use the built-in in-memory
    #   implementation in oauthlib.oauth2.rfc6749.client_assertion instead.
    # ------------------------------------------------------------------

    def get_client_assertion_signing_key(self, client_id, kid, headers,
                                         request, *args, **kwargs):
        """Return the public key registered for an assertion's ``kid``.

        Hosts that verify signatures themselves may leave this unimplemented
        and override :meth:`verify_client_assertion_signature` instead.

        :param client_id: Unicode client identifier bound to the assertion.
        :param kid: The ``kid`` header of the received assertion, or None.
        :param headers: The parsed JOSE header of the assertion.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :rtype: A public key object or PEM string accepted by PyJWT.
        """
        raise NotImplementedError(
            'Subclasses must implement this method or override '
            'verify_client_assertion_signature.')

    def verify_client_assertion_signature(self, client_id, assertion,
                                          headers, request,
                                          signing_key=None, *args, **kwargs):
        """Verify the assertion signature chain and return its claims.

        The default implementation resolves the key through
        :meth:`get_client_assertion_signing_key` and verifies the signature
        with PyJWT, without applying any audience or time-window checks: the
        assertion lifecycle performs those separately so that every failure
        produces a distinct, non-leaking error.

        Host applications that delegate signature verification to an external
        IdP can override this method and return the verified claims dict
        directly.

        :param client_id: Unicode client identifier.
        :param assertion: The raw client assertion string.
        :param headers: The parsed JOSE header.
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :param signing_key: Optional key pre-resolved by the lifecycle.
        :rtype: Dict of verified JWT claims.
        """
        import jwt  # noqa: PLC0415

        key = signing_key
        if key is None:
            key = self.get_client_assertion_signing_key(
                client_id, headers.get('kid'), headers, request)
        options = {
            'verify_signature': True,
            'verify_exp': False,
            'verify_nbf': False,
            'verify_iat': False,
            'verify_aud': False,
            'verify_iss': False,
            'verify_sub': False,
            'require': [],
        }
        return jwt.decode(
            assertion,
            key=key,
            algorithms=[headers.get('alg')],
            options=options,
        )

    def get_client_assertion_time(self, request, *args, **kwargs):
        """Return the authoritative current time as a UNIX timestamp.

        Override this when the host application owns the clock (for example a
        monotonic time service shared across workers).
        """
        import time  # noqa: PLC0415

        return time.time()

    def reserve_client_assertion_jti(self, client_id, jti, expires_at,
                                     request, *args, **kwargs):
        """Atomically reserve a one-time assertion ``jti``.

        The reservation MUST be atomic: only one concurrent request may
        receive :attr:`JTI_ACCEPTED` for the same ``(client_id, jti)`` pair.
        It is committed by :meth:`commit_client_assertion_jti` once the token
        has been issued, or released by
        :meth:`release_client_assertion_jti` if any later step fails, so a
        failed exchange never leaves the assertion in a consumed state.

        :rtype: One of :attr:`JTI_ACCEPTED`, :attr:`JTI_REPLAYED`,
                :attr:`JTI_CONCURRENT` or :attr:`JTI_CLOCK_ROLLBACK`.
        """
        raise NotImplementedError(
            'Subclasses must provide an atomic jti store or use the built-in '
            'InMemoryJtiStore.')

    def commit_client_assertion_jti(self, client_id, jti, request,
                                    *args, **kwargs):
        """Mark a previously reserved ``jti`` as permanently consumed."""
        return None

    def release_client_assertion_jti(self, client_id, jti, request,
                                     *args, **kwargs):
        """Release a reservation so the assertion can be retried.

        This is called whenever validation or token issuance fails after a
        reservation was made. Overriding methods must never raise: cleanup
        problems must not replace the original error.
        """
        return None

    def consume_client_assertion_jti(self, client_id, jti, expires_at,
                                     request, *args, **kwargs):
        """Atomically consume a ``jti`` in a single operation.

        Hosts whose storage only supports an atomic insert (e.g. a unique
        index without explicit reservations) may override this method. The
        default implementation composes reserve + commit, which is what the
        built-in in-memory store uses.

        :rtype: One of the ``JTI_*`` status constants.
        """
        status = self.reserve_client_assertion_jti(
            client_id, jti, expires_at, request)
        if status == self.JTI_ACCEPTED:
            self.commit_client_assertion_jti(client_id, jti, request)
        return status

    def authenticate_client_assertion(self, client_id, request,
                                      claims=None, *args, **kwargs):
        """Bind an authenticated assertion to the request.

        Called only after the signature, claims and jti reservation have all
        succeeded. The default implementation sets ``request.client_id`` and
        a lightweight client object; host applications normally override it
        to load the registered client. Returning False rejects the request
        without consuming the reserved jti.
        """
        request.client_id = client_id
        if getattr(request, 'client', None) is None:
            request.client = type('AssertionClient', (), {
                'client_id': client_id,
            })()
        return True


def call_validator_hook(validator, method_name, kwargs):
    """Invoke a client-assertion validator hook with legacy signature support.

    Custom validators predate these hooks and may define methods with an
    older positional signature (for example ``(client_id, jti, request)``).
    Keyword arguments that the method cannot accept are dropped, and
    variadic methods always receive everything. This keeps every new hook
    callable from the lifecycle without breaking existing subclasses.
    """
    method = getattr(validator, method_name)
    signature = inspect.signature(method)
    parameters = signature.parameters.values()
    accepts_var_kwargs = any(
        p.kind == inspect.Parameter.VAR_KEYWORD for p in parameters)
    if accepts_var_kwargs:
        return method(**kwargs)
    accepted = {
        name: value for name, value in kwargs.items()
        if name in signature.parameters
    }
    return method(**accepted)
