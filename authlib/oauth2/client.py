import time

from authlib.common.errors import AuthlibBaseError
from authlib.common.security import generate_token
from authlib.common.urls import url_decode
from authlib.common.urls import url_encode

from .auth import ClientAuth
from .auth import TokenAuth
from .base import OAuth2Error
from .rfc6749.parameters import parse_authorization_code_response
from .rfc6749.parameters import parse_implicit_response
from .rfc6749.parameters import prepare_grant_uri
from .rfc6749.parameters import prepare_token_request
from .rfc7009 import prepare_revoke_token_request
from .rfc7636 import create_s256_code_challenge
from .rfc8628.client import DEFAULT_EXPIRES_IN
from .rfc8628.client import DEFAULT_POLL_INTERVAL
from .rfc8628.client import DEVICE_CODE_GRANT_TYPE
from .rfc8628.client import DeviceTokenPollState

DEFAULT_HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
}


class OAuth2Client:
    """Construct a new OAuth 2 protocol client.

    :param session: Requests session object to communicate with
                    authorization server.
    :param client_id: Client ID, which you get from client registration.
    :param client_secret: Client Secret, which you get from registration.
    :param token_endpoint_auth_method: client authentication method for
        token endpoint.
    :param revocation_endpoint_auth_method: client authentication method for
        revocation endpoint.
    :param scope: Scope that you needed to access user resources.
    :param state: Shared secret to prevent CSRF attack.
    :param redirect_uri: Redirect URI you registered as callback.
    :param code_challenge_method: PKCE method name, only S256 is supported.
    :param token: A dict of token attributes such as ``access_token``,
        ``token_type`` and ``expires_at``.
    :param token_placement: The place to put token in HTTP request. Available
        values: "header", "body", "uri".
    :param update_token: A function for you to update token. It accept a
        :class:`OAuth2Token` as parameter.
    :param leeway: Time window in seconds before the actual expiration of the
        authentication token, that the token is considered expired and will
        be refreshed.
    """

    client_auth_class = ClientAuth
    token_auth_class = TokenAuth
    oauth_error_class = OAuth2Error

    #: Exceptions raised by the underlying HTTP session when a request
    #: times out. ``poll_device_token`` retries these requests with an
    #: exponential backoff instead of failing.
    network_timeout_exceptions = ()

    EXTRA_AUTHORIZE_PARAMS = ("response_mode", "nonce", "prompt", "login_hint")
    SESSION_REQUEST_PARAMS = []

    def __init__(
        self,
        session,
        client_id=None,
        client_secret=None,
        token_endpoint_auth_method=None,
        revocation_endpoint_auth_method=None,
        scope=None,
        state=None,
        redirect_uri=None,
        code_challenge_method=None,
        token=None,
        token_placement="header",
        update_token=None,
        leeway=60,
        **metadata,
    ):
        self.session = session
        self.client_id = client_id
        self.client_secret = client_secret
        self.state = state

        if token_endpoint_auth_method is None:
            if client_secret:
                token_endpoint_auth_method = "client_secret_basic"
            else:
                token_endpoint_auth_method = "none"

        self.token_endpoint_auth_method = token_endpoint_auth_method

        if revocation_endpoint_auth_method is None:
            if client_secret:
                revocation_endpoint_auth_method = "client_secret_basic"
            else:
                revocation_endpoint_auth_method = "none"

        self.revocation_endpoint_auth_method = revocation_endpoint_auth_method

        self.scope = scope
        self.redirect_uri = redirect_uri
        self.code_challenge_method = code_challenge_method

        self.token_auth = self.token_auth_class(token, token_placement, self)
        self.update_token = update_token

        token_updater = metadata.pop("token_updater", None)
        if token_updater:
            raise ValueError(
                "update token has been redesigned, checkout the documentation"
            )

        self.metadata = metadata

        self.compliance_hook = {
            "access_token_response": set(),
            "refresh_token_request": set(),
            "refresh_token_response": set(),
            "revoke_token_request": set(),
            "introspect_token_request": set(),
        }
        self._auth_methods = {}

        self.leeway = leeway

    def register_client_auth_method(self, auth):
        """Extend client authenticate for token endpoint.

        :param auth: an instance to sign the request
        """
        if isinstance(auth, tuple):
            self._auth_methods[auth[0]] = auth[1]
        else:
            self._auth_methods[auth.name] = auth

    def client_auth(self, auth_method):
        if isinstance(auth_method, str) and auth_method in self._auth_methods:
            auth_method = self._auth_methods[auth_method]
        return self.client_auth_class(
            client_id=self.client_id,
            client_secret=self.client_secret,
            auth_method=auth_method,
        )

    @property
    def token(self):
        return self.token_auth.token

    @token.setter
    def token(self, token):
        self.token_auth.set_token(token)

    def create_authorization_url(self, url, state=None, code_verifier=None, **kwargs):
        """Generate an authorization URL and state.

        :param url: Authorization endpoint url, must be HTTPS.
        :param state: An optional state string for CSRF protection. If not
                      given it will be generated for you.
        :param code_verifier: An optional code_verifier for code challenge.
        :param kwargs: Extra parameters to include.
        :return: authorization_url, state
        """
        if state is None:
            state = generate_token()

        response_type = self.metadata.get("response_type", "code")
        response_type = kwargs.pop("response_type", response_type)
        if "redirect_uri" not in kwargs:
            kwargs["redirect_uri"] = self.redirect_uri
        if "scope" not in kwargs:
            kwargs["scope"] = self.scope

        if (
            code_verifier
            and response_type == "code"
            and self.code_challenge_method == "S256"
        ):
            kwargs["code_challenge"] = create_s256_code_challenge(code_verifier)
            kwargs["code_challenge_method"] = self.code_challenge_method

        for k in self.EXTRA_AUTHORIZE_PARAMS:
            if k not in kwargs and k in self.metadata:
                kwargs[k] = self.metadata[k]

        uri = prepare_grant_uri(
            url,
            client_id=self.client_id,
            response_type=response_type,
            state=state,
            **kwargs,
        )
        return uri, state

    def fetch_token(
        self,
        url=None,
        body="",
        method="POST",
        headers=None,
        auth=None,
        grant_type=None,
        state=None,
        **kwargs,
    ):
        """Generic method for fetching an access token from the token endpoint.

        :param url: Access Token endpoint URL, if not configured,
                    ``authorization_response`` is used to extract token from
                    its fragment (implicit way).
        :param body: Optional application/x-www-form-urlencoded body to add the
                     include in the token request. Prefer kwargs over body.
        :param method: The HTTP method used to make the request. Defaults
                       to POST, but may also be GET. Other methods should
                       be added as needed.
        :param headers: Dict to default request headers with.
        :param auth: An auth tuple or method as accepted by requests.
        :param grant_type: Use specified grant_type to fetch token.
        :param state: Optional "state" value to fetch token.
        :return: A :class:`OAuth2Token` object (a dict too).
        """
        state = state or self.state
        # implicit  grant_type
        authorization_response = kwargs.pop("authorization_response", None)
        if authorization_response and "#" in authorization_response:
            return self.token_from_fragment(authorization_response, state)

        session_kwargs = self._extract_session_request_params(kwargs)

        if authorization_response and "code=" in authorization_response:
            grant_type = "authorization_code"
            params = parse_authorization_code_response(
                authorization_response,
                state=state,
            )
            kwargs["code"] = params["code"]

        if grant_type is None:
            grant_type = self.metadata.get("grant_type")

        if grant_type is None:
            grant_type = _guess_grant_type(kwargs)
            self.metadata["grant_type"] = grant_type

        body = self._prepare_token_endpoint_body(body, grant_type, **kwargs)

        if auth is None:
            auth = self.client_auth(self.token_endpoint_auth_method)

        if headers is None:
            headers = DEFAULT_HEADERS

        if url is None:
            url = self.metadata.get("token_endpoint")

        return self._fetch_token(
            url, body=body, auth=auth, method=method, headers=headers, **session_kwargs
        )

    def token_from_fragment(self, authorization_response, state=None):
        token = parse_implicit_response(authorization_response, state)
        if "error" in token:
            raise self.oauth_error_class(
                error=token["error"], description=token.get("error_description")
            )
        self.token = token
        return token

    def fetch_device_authorization(self, url=None, **kwargs):
        """Request a device code from the device authorization endpoint,
        as defined in `RFC 8628`_ Section 3.1.

        The returned dict contains the ``device_code`` used for polling,
        together with the ``user_code`` and ``verification_uri`` that the
        caller MUST display to the end user. Authlib does NOT open a
        browser for the user.

        :param url: Device authorization endpoint URL. If omitted, the
            ``device_authorization_endpoint`` metadata value is used.
        :param kwargs: Extra parameters for the request, e.g. ``scope``.
        :return: A dict of the device authorization response.

        .. _`RFC 8628`: https://www.rfc-editor.org/rfc/rfc8628
        """
        url, body, auth = self._prepare_device_authorization_request(url, kwargs)
        resp = self._http_post(url, body, auth=auth, headers=DEFAULT_HEADERS)
        return self._parse_device_authorization_response(resp)

    def poll_device_token(
        self,
        device_authorization=None,
        device_code=None,
        url=None,
        interval=None,
        expires_in=None,
        clock=None,
        sleep=None,
        **kwargs,
    ):
        """Poll the token endpoint until the user completes the device
        authorization, as defined in `RFC 8628`_ Section 3.3 and 3.4.

        Polling waits ``interval`` seconds between requests; a
        ``slow_down`` error increases the interval by 5 seconds for all
        subsequent requests, while ``authorization_pending`` leaves it
        unchanged. ``access_denied`` and ``expired_token`` errors are
        raised to the caller. Network timeouts (see
        :attr:`network_timeout_exceptions`) are retried with an
        exponential backoff that is tracked separately from the protocol
        interval. Once the device code lifetime (``expires_in``) is
        reached, polling stops and an ``expired_token`` error is raised.

        The loop runs in the caller's thread: when this method returns or
        raises, no further request for this device code is made, and
        interrupting the caller (e.g. ``KeyboardInterrupt``) stops the
        polling immediately.

        :param device_authorization: The dict returned by
            :meth:`fetch_device_authorization`, or a device code string.
        :param device_code: The device code, if ``device_authorization``
            is not given.
        :param url: Token endpoint URL. If omitted, the ``token_endpoint``
            metadata value is used.
        :param interval: Initial polling interval in seconds. Defaults to
            the ``interval`` of the device authorization response, or 5.
        :param expires_in: Lifetime of the device code in seconds.
            Defaults to the ``expires_in`` of the device authorization
            response, or 900.
        :param clock: A monotonic clock callable, defaults to
            ``time.monotonic``.
        :param sleep: A callable used to wait between requests, defaults
            to ``time.sleep``.
        :param kwargs: Extra parameters passed to the HTTP session.
        :return: A :class:`OAuth2Token` object (a dict too).

        .. _`RFC 8628`: https://www.rfc-editor.org/rfc/rfc8628
        """
        device_code, url, state = self._prepare_device_token_poll(
            device_authorization, device_code, url, interval, expires_in, clock
        )
        if sleep is None:
            sleep = time.sleep

        while not state.expired:
            sleep(state.next_delay())
            if state.expired:
                break
            try:
                return self._fetch_device_token(url, device_code, **kwargs)
            except self.network_timeout_exceptions:
                state.handle_network_timeout()
            except AuthlibBaseError as error:
                if not state.handle_error(error.error):
                    raise

        raise self.oauth_error_class(
            error="expired_token",
            description="The device code expired before the user completed authorization.",
        )

    def refresh_token(
        self, url=None, refresh_token=None, body="", auth=None, headers=None, **kwargs
    ):
        """Fetch a new access token using a refresh token.

        :param url: Refresh Token endpoint, must be HTTPS.
        :param refresh_token: The refresh_token to use.
        :param body: Optional application/x-www-form-urlencoded body to add the
                     include in the token request. Prefer kwargs over body.
        :param auth: An auth tuple or method as accepted by requests.
        :param headers: Dict to default request headers with.
        :return: A :class:`OAuth2Token` object (a dict too).
        """
        session_kwargs = self._extract_session_request_params(kwargs)
        refresh_token = refresh_token or self.token.get("refresh_token")
        if "scope" not in kwargs and self.scope:
            kwargs["scope"] = self.scope
        body = prepare_token_request(
            "refresh_token", body, refresh_token=refresh_token, **kwargs
        )

        if headers is None:
            headers = DEFAULT_HEADERS.copy()

        if url is None:
            url = self.metadata.get("token_endpoint")

        for hook in self.compliance_hook["refresh_token_request"]:
            url, headers, body = hook(url, headers, body)

        if auth is None:
            auth = self.client_auth(self.token_endpoint_auth_method)

        return self._refresh_token(
            url,
            refresh_token=refresh_token,
            body=body,
            headers=headers,
            auth=auth,
            **session_kwargs,
        )

    def ensure_active_token(self, token=None):
        if token is None:
            token = self.token
        if not token.is_expired(leeway=self.leeway):
            return True
        refresh_token = token.get("refresh_token")
        url = self.metadata.get("token_endpoint")
        if refresh_token and url:
            self.refresh_token(url, refresh_token=refresh_token)
            return True
        elif self.metadata.get("grant_type") == "client_credentials":
            access_token = token["access_token"]
            new_token = self.fetch_token(url, grant_type="client_credentials")
            if self.update_token:
                self.update_token(new_token, access_token=access_token)
            return True

    def revoke_token(
        self,
        url,
        token=None,
        token_type_hint=None,
        body=None,
        auth=None,
        headers=None,
        **kwargs,
    ):
        """Revoke token method defined via `RFC7009`_.

        :param url: Revoke Token endpoint, must be HTTPS.
        :param token: The token to be revoked.
        :param token_type_hint: The type of the token that to be revoked.
                                It can be "access_token" or "refresh_token".
        :param body: Optional application/x-www-form-urlencoded body to add the
                     include in the token request. Prefer kwargs over body.
        :param auth: An auth tuple or method as accepted by requests.
        :param headers: Dict to default request headers with.
        :return: Revocation Response

        .. _`RFC7009`: https://tools.ietf.org/html/rfc7009
        """
        if auth is None:
            auth = self.client_auth(self.revocation_endpoint_auth_method)
        return self._handle_token_hint(
            "revoke_token_request",
            url,
            token=token,
            token_type_hint=token_type_hint,
            body=body,
            auth=auth,
            headers=headers,
            **kwargs,
        )

    def introspect_token(
        self,
        url,
        token=None,
        token_type_hint=None,
        body=None,
        auth=None,
        headers=None,
        **kwargs,
    ):
        """Implementation of OAuth 2.0 Token Introspection defined via `RFC7662`_.

        :param url: Introspection Endpoint, must be HTTPS.
        :param token: The token to be introspected.
        :param token_type_hint: The type of the token that to be revoked.
                                It can be "access_token" or "refresh_token".
        :param body: Optional application/x-www-form-urlencoded body to add the
                     include in the token request. Prefer kwargs over body.
        :param auth: An auth tuple or method as accepted by requests.
        :param headers: Dict to default request headers with.
        :return: Introspection Response

        .. _`RFC7662`: https://tools.ietf.org/html/rfc7662
        """
        if auth is None:
            auth = self.client_auth(self.token_endpoint_auth_method)
        return self._handle_token_hint(
            "introspect_token_request",
            url,
            token=token,
            token_type_hint=token_type_hint,
            body=body,
            auth=auth,
            headers=headers,
            **kwargs,
        )

    def register_compliance_hook(self, hook_type, hook):
        """Register a hook for request/response tweaking.

        Available hooks are:

        * access_token_response: invoked before token parsing.
        * refresh_token_request: invoked before refreshing token.
        * refresh_token_response: invoked before refresh token parsing.
        * protected_request: invoked before making a request.
        * revoke_token_request: invoked before revoking a token.
        * introspect_token_request: invoked before introspecting a token.
        """
        if hook_type == "protected_request":
            self.token_auth.hooks.add(hook)
            return

        if hook_type not in self.compliance_hook:
            raise ValueError(
                "Hook type %s is not in %s.", hook_type, self.compliance_hook
            )
        self.compliance_hook[hook_type].add(hook)

    def parse_response_token(self, resp):
        if resp.status_code >= 500:
            resp.raise_for_status()

        token = resp.json()
        if "error" in token:
            raise self.oauth_error_class(
                error=token["error"], description=token.get("error_description")
            )
        self.token = token
        return self.token

    def _fetch_token(
        self, url, body="", headers=None, auth=None, method="POST", **kwargs
    ):
        if method.upper() == "POST":
            resp = self.session.post(
                url, data=dict(url_decode(body)), headers=headers, auth=auth, **kwargs
            )
        else:
            if "?" in url:
                url = "&".join([url, body])
            else:
                url = "?".join([url, body])
            resp = self.session.request(
                method, url, headers=headers, auth=auth, **kwargs
            )

        for hook in self.compliance_hook["access_token_response"]:
            resp = hook(resp)

        return self.parse_response_token(resp)

    def _refresh_token(
        self, url, refresh_token=None, body="", headers=None, auth=None, **kwargs
    ):
        resp = self._http_post(url, body=body, auth=auth, headers=headers, **kwargs)

        for hook in self.compliance_hook["refresh_token_response"]:
            resp = hook(resp)

        token = self.parse_response_token(resp)
        if "refresh_token" not in token:
            self.token["refresh_token"] = refresh_token

        if callable(self.update_token):
            self.update_token(self.token, refresh_token=refresh_token)

        return self.token

    def _handle_token_hint(
        self,
        hook,
        url,
        token=None,
        token_type_hint=None,
        body=None,
        auth=None,
        headers=None,
        **kwargs,
    ):
        if token is None and self.token:
            token = self.token.get("refresh_token") or self.token.get("access_token")

        if body is None:
            body = ""

        body, headers = prepare_revoke_token_request(
            token, token_type_hint, body, headers
        )

        for compliance_hook in self.compliance_hook[hook]:
            url, headers, body = compliance_hook(url, headers, body)

        if auth is None:
            auth = self.client_auth(self.revocation_endpoint_auth_method)

        session_kwargs = self._extract_session_request_params(kwargs)
        return self._http_post(url, body, auth=auth, headers=headers, **session_kwargs)

    def _prepare_device_authorization_request(self, url, kwargs):
        if url is None:
            url = self.metadata.get("device_authorization_endpoint")
        if not url:
            raise ValueError("Missing device authorization endpoint URL")
        if "scope" not in kwargs and self.scope:
            kwargs["scope"] = self.scope
        auth = self.client_auth(self.token_endpoint_auth_method)
        return url, url_encode(kwargs.items()), auth

    def _parse_device_authorization_response(self, resp):
        if resp.status_code >= 500:
            resp.raise_for_status()
        data = resp.json()
        if "error" in data:
            raise self.oauth_error_class(
                error=data["error"], description=data.get("error_description")
            )
        return data

    def _prepare_device_token_poll(
        self, device_authorization, device_code, url, interval, expires_in, clock
    ):
        if isinstance(device_authorization, str):
            if device_code is None:
                device_code = device_authorization
            device_authorization = None
        if device_authorization is None:
            device_authorization = {}
        if device_code is None:
            device_code = device_authorization.get("device_code")
        if not device_code:
            raise ValueError("Missing 'device_code'")
        if interval is None:
            interval = device_authorization.get("interval", DEFAULT_POLL_INTERVAL)
        if expires_in is None:
            expires_in = device_authorization.get("expires_in", DEFAULT_EXPIRES_IN)
        if clock is None:
            clock = time.monotonic
        if url is None:
            url = self.metadata.get("token_endpoint")
        state = DeviceTokenPollState(interval, expires_in, clock)
        return device_code, url, state

    def _fetch_device_token(self, url, device_code, **kwargs):
        body = prepare_token_request(
            DEVICE_CODE_GRANT_TYPE, "", device_code=device_code
        )
        auth = self.client_auth(self.token_endpoint_auth_method)
        return self._fetch_token(
            url, body=body, auth=auth, headers=DEFAULT_HEADERS, **kwargs
        )

    def _prepare_token_endpoint_body(self, body, grant_type, **kwargs):
        if grant_type == "authorization_code":
            if "redirect_uri" not in kwargs:
                kwargs["redirect_uri"] = self.redirect_uri
            return prepare_token_request(grant_type, body, **kwargs)

        if "scope" not in kwargs and self.scope:
            kwargs["scope"] = self.scope
        return prepare_token_request(grant_type, body, **kwargs)

    def _extract_session_request_params(self, kwargs):
        """Extract parameters for session object from the passing ``**kwargs``."""
        rv = {}
        for k in self.SESSION_REQUEST_PARAMS:
            if k in kwargs:
                rv[k] = kwargs.pop(k)
        return rv

    def _http_post(self, url, body=None, auth=None, headers=None, **kwargs):
        return self.session.post(
            url, data=dict(url_decode(body)), headers=headers, auth=auth, **kwargs
        )

    def __del__(self):
        del self.session


def _guess_grant_type(kwargs):
    if "code" in kwargs:
        grant_type = "authorization_code"
    elif "username" in kwargs and "password" in kwargs:
        grant_type = "password"
    else:
        grant_type = "client_credentials"
    return grant_type
