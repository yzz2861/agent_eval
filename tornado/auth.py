#
# Copyright 2009 Facebook
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""This module contains implementations of various third-party
authentication schemes.

All the classes in this file are class mixins designed to be used with
the `tornado.web.RequestHandler` class.  They are used in two ways:

* On a login handler, use methods such as ``authenticate_redirect()``,
  ``authorize_redirect()``, and ``get_authenticated_user()`` to
  establish the user's identity and store authentication tokens to your
  database and/or cookies.
* In non-login handlers, use methods such as ``facebook_request()``
  or ``twitter_request()`` to use the authentication tokens to make
  requests to the respective services.

They all take slightly different arguments due to the fact all these
services implement authentication and authorization slightly differently.
See the individual service classes below for complete documentation.

Example usage for Google OAuth:

.. testsetup::

    import urllib

.. testcode::

    class GoogleOAuth2LoginHandler(tornado.web.RequestHandler,
                                    tornado.auth.GoogleOAuth2Mixin):
        async def get(self):
            # Google requires an exact match for redirect_uri, so it's
            # best to get it from your app configuration instead of from
            # self.request.full_uri().
            redirect_uri = urllib.parse.urljoin(self.application.settings['redirect_base_uri'],
                self.reverse_url('google_oauth'))
            async def get(self):
                if self.get_argument('code', False):
                    access = await self.get_authenticated_user(
                        redirect_uri=redirect_uri,
                        code=self.get_argument('code'))
                    user = await self.oauth2_request(
                        "https://www.googleapis.com/oauth2/v1/userinfo",
                        access_token=access["access_token"])
                    # Save the user and access token. For example:
                    user_cookie = dict(id=user["id"], access_token=access["access_token"])
                    self.set_signed_cookie("user", json.dumps(user_cookie))
                    self.redirect("/")
                else:
                    self.authorize_redirect(
                        redirect_uri=redirect_uri,
                        client_id=self.get_google_oauth_settings()['key'],
                        scope=['profile', 'email'],
                        response_type='code',
                        extra_params={'approval_prompt': 'auto'})

"""

import binascii
import base64
import hashlib
import hmac
import logging
import re
import secrets
import time
import urllib.parse
import uuid
import warnings
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, cast

from tornado import escape, httpclient
from tornado.httputil import url_concat
from tornado.util import unicode_type
from tornado.web import RequestHandler

auth_log = logging.getLogger(__name__)


class AuthError(Exception):
    pass


class OAuth2PKCEError(AuthError):
    """An OAuth 2.0 PKCE login failure that is safe to report to a user.

    .. versionadded:: 6.6
    """

    def __init__(
        self,
        error_code: str,
        status_code: int = 400,
        message: str | None = None,
    ) -> None:
        self.error_code = error_code
        self.status_code = status_code
        super().__init__(message or f"OAuth 2.0 PKCE login failed: {error_code}")


@dataclass(frozen=True, slots=True)
class OAuth2PKCEState:
    """Server-side state for one authorization request.

    .. versionadded:: 6.6
    """

    code_verifier: str
    redirect_uri: str
    client_id: str
    initiator: str
    scope: str | None = None
    extra_params: dict[str, Any] | None = None

    def __repr__(self) -> str:
        return (
            "OAuth2PKCEState("
            f"redirect_uri={self.redirect_uri!r}, client_id={self.client_id!r}, "
            f"scope={self.scope!r})"
        )


@dataclass(frozen=True, slots=True)
class OAuth2PKCEStateConsumption:
    """Result of an atomic state-store consumption attempt.

    .. versionadded:: 6.6
    """

    entry: OAuth2PKCEState | None = None
    initiator_mismatch: bool = False


class OAuth2PKCEStateStore(ABC):
    """Storage for one-use OAuth 2.0 PKCE login state.

    .. versionadded:: 6.6
    """

    @abstractmethod
    async def save(
        self, state: str, entry: OAuth2PKCEState, ttl_seconds: float
    ) -> None:
        raise NotImplementedError

    @abstractmethod
    async def consume(self, state: str, initiator: str) -> OAuth2PKCEStateConsumption:
        """Atomically remove and return one matching, unexpired state."""
        raise NotImplementedError


class InMemoryOAuth2PKCEStateStore(OAuth2PKCEStateStore):
    """Single-process state store suitable for local development and tests.

    .. versionadded:: 6.6
    """

    def __init__(self, *, time_func: Callable[[], float] | None = None) -> None:
        self._time_func = time_func or time.monotonic
        self._states: dict[str, tuple[float, OAuth2PKCEState]] = {}

    async def save(
        self, state: str, entry: OAuth2PKCEState, ttl_seconds: float
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._prune()
        self._states[state] = (self._time_func() + ttl_seconds, entry)

    async def consume(self, state: str, initiator: str) -> OAuth2PKCEStateConsumption:
        now = self._time_func()
        self._prune(now)

        item = self._states.pop(state, None)
        if item is None:
            return OAuth2PKCEStateConsumption()
        expires_at, entry = item
        if expires_at <= now:
            return OAuth2PKCEStateConsumption()
        if not secrets.compare_digest(entry.initiator, initiator):
            self._states[state] = item
            return OAuth2PKCEStateConsumption(entry=entry, initiator_mismatch=True)
        return OAuth2PKCEStateConsumption(entry=entry)

    def _prune(self, now: float | None = None) -> None:
        current = self._time_func() if now is None else now
        expired = [
            state
            for state, (expires_at, _) in self._states.items()
            if expires_at <= current
        ]
        for state in expired:
            del self._states[state]


_DEFAULT_OAUTH2_PKCE_STATE_STORE = InMemoryOAuth2PKCEStateStore()


class OpenIdMixin:
    """Abstract implementation of OpenID and Attribute Exchange.

    Class attributes:

    * ``_OPENID_ENDPOINT``: the identity provider's URI.

    .. deprecated:: 6.5.8
        OpenID 2.0 is no longer widely supported by identity providers.
        This class will be removed in Tornado 6.7.
    """

    def __init__(self) -> None:
        warnings.warn(
            "OpenIdMixin is deprecated and will be removed in Tornado 6.7",
            DeprecationWarning,
            stacklevel=2,
        )

    def authenticate_redirect(
        self,
        callback_uri: str | None = None,
        ax_attrs: list[str] = ["name", "email", "language", "username"],
    ) -> None:
        """Redirects to the authentication URL for this service.

        After authentication, the service will redirect back to the given
        callback URI with additional parameters including ``openid.mode``.

        We request the given attributes for the authenticated user by
        default (name, email, language, and username). If you don't need
        all those attributes for your app, you can request fewer with
        the ax_attrs keyword argument.

        .. versionchanged:: 6.0

            The ``callback`` argument was removed and this method no
            longer returns an awaitable object. It is now an ordinary
            synchronous function.
        """
        handler = cast(RequestHandler, self)
        callback_uri = callback_uri or handler.request.uri
        assert callback_uri is not None
        args = self._openid_args(callback_uri, ax_attrs=ax_attrs)
        endpoint = self._OPENID_ENDPOINT  # type: ignore
        handler.redirect(endpoint + "?" + urllib.parse.urlencode(args))

    async def get_authenticated_user(
        self, http_client: httpclient.AsyncHTTPClient | None = None
    ) -> dict[str, Any]:
        """Fetches the authenticated user data upon redirect.

        This method should be called by the handler that receives the
        redirect from the `authenticate_redirect()` method (which is
        often the same as the one that calls it; in that case you would
        call `get_authenticated_user` if the ``openid.mode`` parameter
        is present and `authenticate_redirect` if it is not).

        The result of this method will generally be used to set a cookie.

        .. versionchanged:: 6.0

            The ``callback`` argument was removed. Use the returned
            awaitable object instead.
        """
        handler = cast(RequestHandler, self)
        # Verify the OpenID response via direct request to the OP
        args: dict[str, str | bytes] = {
            k: v[-1] for k, v in handler.request.arguments.items()
        }
        args["openid.mode"] = "check_authentication"
        url = self._OPENID_ENDPOINT  # type: ignore
        if http_client is None:
            http_client = self.get_auth_http_client()
        resp = await http_client.fetch(
            url, method="POST", body=urllib.parse.urlencode(args)
        )
        return self._on_authentication_verified(resp)

    def _openid_args(
        self,
        callback_uri: str,
        ax_attrs: Iterable[str] = [],
        oauth_scope: str | None = None,
    ) -> dict[str, str]:
        handler = cast(RequestHandler, self)
        url = urllib.parse.urljoin(handler.request.full_url(), callback_uri)
        args = {
            "openid.ns": "http://specs.openid.net/auth/2.0",
            "openid.claimed_id": "http://specs.openid.net/auth/2.0/identifier_select",
            "openid.identity": "http://specs.openid.net/auth/2.0/identifier_select",
            "openid.return_to": url,
            "openid.realm": urllib.parse.urljoin(url, "/"),
            "openid.mode": "checkid_setup",
        }
        if ax_attrs:
            args.update(
                {
                    "openid.ns.ax": "http://openid.net/srv/ax/1.0",
                    "openid.ax.mode": "fetch_request",
                }
            )
            ax_attrs = set(ax_attrs)
            required: list[str] = []
            if "name" in ax_attrs:
                ax_attrs -= {"name", "firstname", "fullname", "lastname"}
                required += ["firstname", "fullname", "lastname"]
                args.update(
                    {
                        "openid.ax.type.firstname": "http://axschema.org/namePerson/first",
                        "openid.ax.type.fullname": "http://axschema.org/namePerson",
                        "openid.ax.type.lastname": "http://axschema.org/namePerson/last",
                    }
                )
            known_attrs = {
                "email": "http://axschema.org/contact/email",
                "language": "http://axschema.org/pref/language",
                "username": "http://axschema.org/namePerson/friendly",
            }
            for name in ax_attrs:
                args["openid.ax.type." + name] = known_attrs[name]
                required.append(name)
            args["openid.ax.required"] = ",".join(required)
        if oauth_scope:
            args.update(
                {
                    "openid.ns.oauth": "http://specs.openid.net/extensions/oauth/1.0",
                    "openid.oauth.consumer": handler.request.host.split(":")[0],
                    "openid.oauth.scope": oauth_scope,
                }
            )
        return args

    def _on_authentication_verified(
        self, response: httpclient.HTTPResponse
    ) -> dict[str, Any]:
        handler = cast(RequestHandler, self)
        if re.search(rb"(?m)^is_valid:true$", response.body) is None:
            raise AuthError("Invalid OpenID response: %r" % response.body)

        # Make sure we got back at least an email from attribute exchange
        ax_ns = None
        for key in handler.request.arguments:
            if (
                key.startswith("openid.ns.")
                and handler.get_argument(key) == "http://openid.net/srv/ax/1.0"
            ):
                ax_ns = key[10:]
                break

        def get_ax_arg(uri: str) -> str:
            if not ax_ns:
                return ""
            prefix = "openid." + ax_ns + ".type."
            ax_name = None
            for name in handler.request.arguments.keys():
                if handler.get_argument(name) == uri and name.startswith(prefix):
                    part = name[len(prefix) :]
                    ax_name = "openid." + ax_ns + ".value." + part
                    break
            if not ax_name:
                return ""
            return handler.get_argument(ax_name, "")

        email = get_ax_arg("http://axschema.org/contact/email")
        name = get_ax_arg("http://axschema.org/namePerson")
        first_name = get_ax_arg("http://axschema.org/namePerson/first")
        last_name = get_ax_arg("http://axschema.org/namePerson/last")
        username = get_ax_arg("http://axschema.org/namePerson/friendly")
        locale = get_ax_arg("http://axschema.org/pref/language").lower()
        user = dict()
        name_parts = []
        if first_name:
            user["first_name"] = first_name
            name_parts.append(first_name)
        if last_name:
            user["last_name"] = last_name
            name_parts.append(last_name)
        if name:
            user["name"] = name
        elif name_parts:
            user["name"] = " ".join(name_parts)
        elif email:
            user["name"] = email.split("@")[0]
        if email:
            user["email"] = email
        if locale:
            user["locale"] = locale
        if username:
            user["username"] = username
        claimed_id = handler.get_argument("openid.claimed_id", None)
        if claimed_id:
            user["claimed_id"] = claimed_id
        return user

    def get_auth_http_client(self) -> httpclient.AsyncHTTPClient:
        """Returns the `.AsyncHTTPClient` instance to be used for auth requests.

        May be overridden by subclasses to use an HTTP client other than
        the default.
        """
        return httpclient.AsyncHTTPClient()


class OAuthMixin:
    """Abstract implementation of OAuth 1.0 and 1.0a.

    See `TwitterMixin` below for an example implementation.

    Class attributes:

    * ``_OAUTH_AUTHORIZE_URL``: The service's OAuth authorization url.
    * ``_OAUTH_ACCESS_TOKEN_URL``: The service's OAuth access token url.
    * ``_OAUTH_VERSION``: May be either "1.0" or "1.0a".
    * ``_OAUTH_NO_CALLBACKS``: Set this to True if the service requires
      advance registration of callbacks.

    Subclasses must also override the `_oauth_get_user_future` and
    `_oauth_consumer_token` methods.
    """

    async def authorize_redirect(
        self,
        callback_uri: str | None = None,
        extra_params: dict[str, Any] | None = None,
        http_client: httpclient.AsyncHTTPClient | None = None,
    ) -> None:
        """Redirects the user to obtain OAuth authorization for this service.

        The ``callback_uri`` may be omitted if you have previously
        registered a callback URI with the third-party service. For
        some services, you must use a previously-registered callback
        URI and cannot specify a callback via this method.

        This method sets a cookie called ``_oauth_request_token`` which is
        subsequently used (and cleared) in `get_authenticated_user` for
        security purposes.

        This method is asynchronous and must be called with ``await``
        or ``yield`` (This is different from other ``auth*_redirect``
        methods defined in this module). It calls
        `.RequestHandler.finish` for you so you should not write any
        other response after it returns.

        .. versionchanged:: 3.1
           Now returns a `.Future` and takes an optional callback, for
           compatibility with `.gen.coroutine`.

        .. versionchanged:: 6.0

           The ``callback`` argument was removed. Use the returned
           awaitable object instead.

        """
        if callback_uri and getattr(self, "_OAUTH_NO_CALLBACKS", False):
            raise Exception("This service does not support oauth_callback")
        if http_client is None:
            http_client = self.get_auth_http_client()
        assert http_client is not None
        if getattr(self, "_OAUTH_VERSION", "1.0a") == "1.0a":
            response = await http_client.fetch(
                self._oauth_request_token_url(
                    callback_uri=callback_uri, extra_params=extra_params
                )
            )
        else:
            response = await http_client.fetch(self._oauth_request_token_url())
        url = self._OAUTH_AUTHORIZE_URL  # type: ignore
        self._on_request_token(url, callback_uri, response)

    async def get_authenticated_user(
        self, http_client: httpclient.AsyncHTTPClient | None = None
    ) -> dict[str, Any]:
        """Gets the OAuth authorized user and access token.

        This method should be called from the handler for your
        OAuth callback URL to complete the registration process. We run the
        callback with the authenticated user dictionary.  This dictionary
        will contain an ``access_key`` which can be used to make authorized
        requests to this service on behalf of the user.  The dictionary will
        also contain other fields such as ``name``, depending on the service
        used.

        .. versionchanged:: 6.0

           The ``callback`` argument was removed. Use the returned
           awaitable object instead.
        """
        handler = cast(RequestHandler, self)
        request_key = escape.utf8(handler.get_argument("oauth_token"))
        oauth_verifier = handler.get_argument("oauth_verifier", None)
        request_cookie = handler.get_cookie("_oauth_request_token")
        if not request_cookie:
            raise AuthError("Missing OAuth request token cookie")
        handler.clear_cookie("_oauth_request_token")
        cookie_key, cookie_secret = (
            base64.b64decode(escape.utf8(i)) for i in request_cookie.split("|")
        )
        if cookie_key != request_key:
            raise AuthError("Request token does not match cookie")
        token: dict[str, str | bytes] = dict(key=cookie_key, secret=cookie_secret)
        if oauth_verifier:
            token["verifier"] = oauth_verifier
        if http_client is None:
            http_client = self.get_auth_http_client()
        assert http_client is not None
        response = await http_client.fetch(self._oauth_access_token_url(token))
        access_token = _oauth_parse_response(response.body)
        user = await self._oauth_get_user_future(access_token)
        if not user:
            raise AuthError("Error getting user")
        user["access_token"] = access_token
        return user

    def _oauth_request_token_url(
        self,
        callback_uri: str | None = None,
        extra_params: dict[str, Any] | None = None,
    ) -> str:
        handler = cast(RequestHandler, self)
        consumer_token = self._oauth_consumer_token()
        url = self._OAUTH_REQUEST_TOKEN_URL  # type: ignore
        args = dict(
            oauth_consumer_key=escape.to_basestring(consumer_token["key"]),
            oauth_signature_method="HMAC-SHA1",
            oauth_timestamp=str(int(time.time())),
            oauth_nonce=escape.to_basestring(binascii.b2a_hex(uuid.uuid4().bytes)),
            oauth_version="1.0",
        )
        if getattr(self, "_OAUTH_VERSION", "1.0a") == "1.0a":
            if callback_uri == "oob":
                args["oauth_callback"] = "oob"
            elif callback_uri:
                args["oauth_callback"] = urllib.parse.urljoin(
                    handler.request.full_url(), callback_uri
                )
            if extra_params:
                args.update(extra_params)
            signature = _oauth10a_signature(consumer_token, "GET", url, args)
        else:
            signature = _oauth_signature(consumer_token, "GET", url, args)

        args["oauth_signature"] = signature
        return url + "?" + urllib.parse.urlencode(args)

    def _on_request_token(
        self,
        authorize_url: str,
        callback_uri: str | None,
        response: httpclient.HTTPResponse,
    ) -> None:
        handler = cast(RequestHandler, self)
        request_token = _oauth_parse_response(response.body)
        data = (
            base64.b64encode(escape.utf8(request_token["key"]))
            + b"|"
            + base64.b64encode(escape.utf8(request_token["secret"]))
        )
        handler.set_cookie("_oauth_request_token", data)
        args = dict(oauth_token=request_token["key"])
        if callback_uri == "oob":
            handler.finish(authorize_url + "?" + urllib.parse.urlencode(args))
            return
        elif callback_uri:
            args["oauth_callback"] = urllib.parse.urljoin(
                handler.request.full_url(), callback_uri
            )
        handler.redirect(authorize_url + "?" + urllib.parse.urlencode(args))

    def _oauth_access_token_url(self, request_token: dict[str, Any]) -> str:
        consumer_token = self._oauth_consumer_token()
        url = self._OAUTH_ACCESS_TOKEN_URL  # type: ignore
        args = dict(
            oauth_consumer_key=escape.to_basestring(consumer_token["key"]),
            oauth_token=escape.to_basestring(request_token["key"]),
            oauth_signature_method="HMAC-SHA1",
            oauth_timestamp=str(int(time.time())),
            oauth_nonce=escape.to_basestring(binascii.b2a_hex(uuid.uuid4().bytes)),
            oauth_version="1.0",
        )
        if "verifier" in request_token:
            args["oauth_verifier"] = request_token["verifier"]

        if getattr(self, "_OAUTH_VERSION", "1.0a") == "1.0a":
            signature = _oauth10a_signature(
                consumer_token, "GET", url, args, request_token
            )
        else:
            signature = _oauth_signature(
                consumer_token, "GET", url, args, request_token
            )

        args["oauth_signature"] = signature
        return url + "?" + urllib.parse.urlencode(args)

    def _oauth_consumer_token(self) -> dict[str, Any]:
        """Subclasses must override this to return their OAuth consumer keys.

        The return value should be a `dict` with keys ``key`` and ``secret``.
        """
        raise NotImplementedError()

    async def _oauth_get_user_future(
        self, access_token: dict[str, Any]
    ) -> dict[str, Any]:
        """Subclasses must override this to get basic information about the
        user.

        Should be a coroutine whose result is a dictionary
        containing information about the user, which may have been
        retrieved by using ``access_token`` to make a request to the
        service.

        The access token will be added to the returned dictionary to make
        the result of `get_authenticated_user`.

        .. versionchanged:: 5.1

           Subclasses may also define this method with ``async def``.

        .. versionchanged:: 6.0

           A synchronous fallback to ``_oauth_get_user`` was removed.
        """
        raise NotImplementedError()

    def _oauth_request_parameters(
        self,
        url: str,
        access_token: dict[str, Any],
        parameters: dict[str, Any] = {},
        method: str = "GET",
    ) -> dict[str, Any]:
        """Returns the OAuth parameters as a dict for the given request.

        parameters should include all POST arguments and query string arguments
        that will be sent with the request.
        """
        consumer_token = self._oauth_consumer_token()
        base_args = dict(
            oauth_consumer_key=escape.to_basestring(consumer_token["key"]),
            oauth_token=escape.to_basestring(access_token["key"]),
            oauth_signature_method="HMAC-SHA1",
            oauth_timestamp=str(int(time.time())),
            oauth_nonce=escape.to_basestring(binascii.b2a_hex(uuid.uuid4().bytes)),
            oauth_version="1.0",
        )
        args = {}
        args.update(base_args)
        args.update(parameters)
        if getattr(self, "_OAUTH_VERSION", "1.0a") == "1.0a":
            signature = _oauth10a_signature(
                consumer_token, method, url, args, access_token
            )
        else:
            signature = _oauth_signature(
                consumer_token, method, url, args, access_token
            )
        base_args["oauth_signature"] = escape.to_basestring(signature)
        return base_args

    def get_auth_http_client(self) -> httpclient.AsyncHTTPClient:
        """Returns the `.AsyncHTTPClient` instance to be used for auth requests.

        May be overridden by subclasses to use an HTTP client other than
        the default.
        """
        return httpclient.AsyncHTTPClient()


class OAuth2Mixin:
    """Abstract implementation of OAuth 2.0.

    See `FacebookGraphMixin` or `GoogleOAuth2Mixin` below for example
    implementations.

    The PKCE helpers keep the code verifier and redirect URI on the server.
    One handler can both start a login and receive its callback:

        class LoginHandler(tornado.web.RequestHandler,
                          tornado.auth.OAuth2Mixin):
            async def get(self):
                try:
                    token = await self.oauth2_pkce_login()
                except tornado.auth.OAuth2PKCEError as error:
                    self.send_oauth2_pkce_error(error)
                    return
                if token is not None:
                    # Persist the application session, then redirect.
                    self.redirect("/")

    Configure client_id, redirect_uri, authorize_url, and token_url under the
    oauth2_pkce application setting. Set state_store to an
    OAuth2PKCEStateStore implementation for shared or persistent deployments.
    InMemoryOAuth2PKCEStateStore is provided for local single-process apps.

    Class attributes:

    * ``_OAUTH_AUTHORIZE_URL``: The service's authorization url.
    * ``_OAUTH_ACCESS_TOKEN_URL``:  The service's access token url.
    """

    def authorize_redirect(
        self,
        redirect_uri: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        extra_params: dict[str, Any] | None = None,
        scope: list[str] | None = None,
        response_type: str = "code",
    ) -> None:
        """Redirects the user to obtain OAuth authorization for this service.

        Some providers require that you register a redirect URL with
        your application instead of passing one via this method. You
        should call this method to log the user in, and then call
        ``get_authenticated_user`` in the handler for your
        redirect URL to complete the authorization process.

        .. versionchanged:: 6.0

           The ``callback`` argument and returned awaitable were removed;
           this is now an ordinary synchronous function.

        .. deprecated:: 6.4
           The ``client_secret`` argument (which has never had any effect)
           is deprecated and will be removed in Tornado 7.0.
        """
        if client_secret is not None:
            warnings.warn("client_secret argument is deprecated", DeprecationWarning)
        handler = cast(RequestHandler, self)
        args = {"response_type": response_type}
        if redirect_uri is not None:
            args["redirect_uri"] = redirect_uri
        if client_id is not None:
            args["client_id"] = client_id
        if extra_params:
            args.update(extra_params)
        if scope:
            args["scope"] = " ".join(scope)
        url = self._OAUTH_AUTHORIZE_URL  # type: ignore
        handler.redirect(url_concat(url, args))

    _OAUTH_PKCE_SETTINGS_KEY = "oauth2_pkce"
    _OAUTH_PKCE_COOKIE_PREFIX = "oauth2_pkce_state_"
    _OAUTH_PKCE_STATE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
    _OAUTH_PKCE_PROVIDER_ERRORS = frozenset(
        {
            "access_denied",
            "invalid_request",
            "invalid_scope",
            "server_error",
            "temporarily_unavailable",
            "unauthorized_client",
            "unsupported_response_type",
        }
    )

    async def authorize_pkce_redirect(
        self,
        *,
        redirect_uri: str | None = None,
        client_id: str | None = None,
        scope: list[str] | str | None = None,
        extra_params: dict[str, Any] | None = None,
        state_ttl_seconds: float | None = None,
        authorize_url: str | None = None,
    ) -> None:
        """Create S256 PKCE state and redirect to the authorization endpoint.

        .. versionadded:: 6.6
        """
        handler = cast(RequestHandler, self)
        redirect_uri = self._oauth2_pkce_setting(
            "redirect_uri", redirect_uri, required=True
        )
        redirect_uri, cookie_path, redirect_scheme = self._oauth2_pkce_redirect_uri(
            redirect_uri
        )
        client_id = self._oauth2_pkce_setting("client_id", client_id, required=True)
        authorize_url = self._oauth2_pkce_setting(
            "authorize_url",
            authorize_url,
            getattr(self, "_OAUTH_AUTHORIZE_URL", None),
            required=True,
        )
        ttl = self._oauth2_pkce_ttl(state_ttl_seconds)

        if isinstance(scope, list):
            scope_value = " ".join(scope)
        else:
            scope_value = scope

        reserved_params = {
            "response_type",
            "client_id",
            "redirect_uri",
            "state",
            "code_challenge",
            "code_challenge_method",
            "scope",
        }
        if extra_params and reserved_params.intersection(extra_params):
            raise OAuth2PKCEError("invalid_request")

        code_verifier = secrets.token_urlsafe(32)
        digest = hashlib.sha256(escape.utf8(code_verifier)).digest()
        code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        state = secrets.token_urlsafe(32)
        initiator = secrets.token_urlsafe(32)

        entry = OAuth2PKCEState(
            code_verifier=code_verifier,
            redirect_uri=redirect_uri,
            client_id=client_id,
            initiator=initiator,
            scope=scope_value,
            extra_params=dict(extra_params) if extra_params is not None else None,
        )
        await self._oauth2_pkce_state_store().save(state, entry, ttl)

        cookie_secure = self._oauth2_pkce_cookie_secure(redirect_scheme)
        handler.set_signed_cookie(
            self._oauth2_pkce_cookie_name(state),
            initiator,
            expires_days=ttl / 86400,
            httponly=True,
            secure=cookie_secure,
            samesite=self._oauth2_pkce_setting("cookie_samesite", None, "Lax"),
            path=cookie_path,
        )

        args: dict[str, Any] = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        if scope_value is not None:
            args["scope"] = scope_value
        if extra_params:
            args.update(extra_params)
        handler.redirect(url_concat(authorize_url, args))

    async def get_pkce_authenticated_user(
        self,
        *,
        client_secret: str | None = None,
        extra_params: dict[str, str] | None = None,
        token_url: str | None = None,
        http_client: httpclient.AsyncHTTPClient | None = None,
    ) -> dict[str, Any]:
        """Validate a callback and exchange its code with the stored verifier.

        .. versionadded:: 6.6
        """
        provider_error = self._oauth2_pkce_callback_provider_error()
        if provider_error is not None:
            await self._consume_oauth2_pkce_state(provider_error)
            if provider_error == "access_denied":
                raise OAuth2PKCEError("access_denied", 403, "Login was denied")
            raise OAuth2PKCEError(
                provider_error,
                400,
                "The identity provider returned an error",
            )

        code = self._oauth2_pkce_single_argument("code")
        if code is None:
            raise OAuth2PKCEError("invalid_request", 400, "Missing authorization code")
        state = await self._consume_oauth2_pkce_state()

        token_url = self._oauth2_pkce_setting(
            "token_url",
            token_url,
            getattr(self, "_OAUTH_ACCESS_TOKEN_URL", None),
            required=True,
        )
        body_args: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": state.redirect_uri,
            "client_id": state.client_id,
            "code_verifier": state.code_verifier,
        }
        if client_secret is not None:
            body_args["client_secret"] = client_secret
        if extra_params:
            reserved = set(body_args)
            if reserved.intersection(extra_params):
                raise OAuth2PKCEError("invalid_request")
            body_args.update(extra_params)

        if http_client is None:
            http_client = self.get_auth_http_client()
        try:
            response = await http_client.fetch(
                token_url,
                method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body=urllib.parse.urlencode(body_args),
            )
        except httpclient.HTTPClientError:
            auth_log.warning("OAuth2 PKCE token request failed")
            raise OAuth2PKCEError(
                "token_request_failed", 502, "Could not complete login"
            )

        try:
            return escape.json_decode(response.body)
        except ValueError:
            auth_log.warning("OAuth2 PKCE token response was invalid")
            raise OAuth2PKCEError(
                "invalid_token_response", 502, "Could not complete login"
            )

    async def oauth2_pkce_login(self, **kwargs: Any) -> dict[str, Any] | None:
        """Start or finish a PKCE login from one callback handler.

        Returns the token response on a callback and otherwise redirects to
        the authorization endpoint and returns None.

        .. versionadded:: 6.6
        """
        handler = cast(RequestHandler, self)
        query = handler.request.query_arguments
        if "code" in query or "error" in query:
            return await self.get_pkce_authenticated_user(
                client_secret=kwargs.pop("client_secret", None),
                extra_params=kwargs.pop("token_extra_params", None),
                token_url=kwargs.pop("token_url", None),
                http_client=kwargs.pop("http_client", None),
            )
        await self.authorize_pkce_redirect(
            redirect_uri=kwargs.pop("redirect_uri", None),
            client_id=kwargs.pop("client_id", None),
            scope=kwargs.pop("scope", None),
            extra_params=kwargs.pop("extra_params", None),
            state_ttl_seconds=kwargs.pop("state_ttl_seconds", None),
            authorize_url=kwargs.pop("authorize_url", None),
        )
        return None

    def send_oauth2_pkce_error(self, error: OAuth2PKCEError) -> None:
        """Render a stable failure response without PKCE or token secrets.

        .. versionadded:: 6.6
        """
        handler = cast(RequestHandler, self)
        messages = {
            "access_denied": "Login was denied.",
            "invalid_request": "The login request was invalid.",
            "invalid_scope": "The requested login scope was invalid.",
            "invalid_state": "This login link has expired or already been used.",
            "initiator_mismatch": "This login link belongs to another browser.",
            "provider_error": "The identity provider returned an error.",
            "server_error": "The identity provider was temporarily unavailable.",
            "temporarily_unavailable": "The identity provider was temporarily unavailable.",
            "token_request_failed": "Could not complete login.",
            "unauthorized_client": "The login client was not authorized.",
            "unsupported_response_type": "The identity provider rejected this login.",
        }
        message = messages.get(error.error_code, "Could not complete login.")
        handler.set_status(error.status_code)
        handler.set_header("Content-Type", "text/plain; charset=UTF-8")
        handler.write(message)

    def _oauth2_pkce_setting(
        self,
        key: str,
        value: Any = None,
        default: Any = None,
        *,
        required: bool = False,
    ) -> Any:
        if value is not None:
            return value
        handler = cast(RequestHandler, self)
        settings = handler.settings.get(self._OAUTH_PKCE_SETTINGS_KEY, {})
        if key in settings:
            return settings[key]
        if default is not None:
            return default
        if required:
            raise OAuth2PKCEError("invalid_configuration", 500)
        return None

    def _oauth2_pkce_state_store(self) -> OAuth2PKCEStateStore:
        store = self._oauth2_pkce_setting(
            "state_store", default=_DEFAULT_OAUTH2_PKCE_STATE_STORE
        )
        if not isinstance(store, OAuth2PKCEStateStore):
            raise OAuth2PKCEError("invalid_configuration", 500)
        return store

    def _oauth2_pkce_ttl(self, value: float | None) -> float:
        ttl = self._oauth2_pkce_setting("state_ttl_seconds", value, 600)
        try:
            ttl = float(ttl)
        except (TypeError, ValueError):
            raise OAuth2PKCEError("invalid_configuration", 500)
        if ttl <= 0 or ttl > 86400:
            raise OAuth2PKCEError("invalid_configuration", 500)
        return ttl

    def _oauth2_pkce_redirect_uri(self, redirect_uri: str) -> tuple[str, str, str]:
        parsed = urllib.parse.urlparse(redirect_uri)
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.netloc
            or not parsed.path
            or parsed.fragment
        ):
            raise OAuth2PKCEError("invalid_configuration", 500)
        secure = self._oauth2_pkce_cookie_secure(parsed.scheme)
        if secure and parsed.scheme != "https":
            raise OAuth2PKCEError("invalid_configuration", 500)
        return redirect_uri, parsed.path, parsed.scheme

    def _oauth2_pkce_cookie_secure(self, scheme: str) -> bool:
        secure = self._oauth2_pkce_setting("cookie_secure", None, scheme == "https")
        if not isinstance(secure, bool):
            raise OAuth2PKCEError("invalid_configuration", 500)
        return secure

    def _oauth2_pkce_cookie_name(self, state: str) -> str:
        return self._OAUTH_PKCE_COOKIE_PREFIX + state

    def _oauth2_pkce_single_argument(self, name: str) -> str | None:
        handler = cast(RequestHandler, self)
        values = handler.request.query_arguments.get(name)
        if values is None:
            return None
        if len(values) != 1:
            raise OAuth2PKCEError("invalid_provider_response", 502)
        return values[0].decode("utf-8", errors="strict")

    def _oauth2_pkce_callback_provider_error(self) -> str | None:
        handler = cast(RequestHandler, self)
        query = handler.request.query_arguments
        if "redirect_uri" in query:
            raise OAuth2PKCEError("invalid_request")
        if "error" not in query:
            return None
        if len(query["error"]) != 1 or "code" in query:
            raise OAuth2PKCEError("invalid_provider_response", 502)
        error = query["error"][0].decode("utf-8", errors="strict")
        if not re.fullmatch(r"[a-z_]{3,40}", error):
            raise OAuth2PKCEError("invalid_provider_response", 502)
        if error not in self._OAUTH_PKCE_PROVIDER_ERRORS:
            return "provider_error"
        return error

    async def _consume_oauth2_pkce_state(
        self, provider_error: str | None = None
    ) -> OAuth2PKCEState:
        handler = cast(RequestHandler, self)
        state = self._oauth2_pkce_single_argument("state")
        if state is None or not self._OAUTH_PKCE_STATE_PATTERN.fullmatch(state):
            raise OAuth2PKCEError("invalid_state", 400)

        cookie_name = self._oauth2_pkce_cookie_name(state)
        cookie_value = handler.get_signed_cookie(
            cookie_name,
            max_age_days=self._oauth2_pkce_ttl(None) / 86400,
        )
        if cookie_value is None:
            raise OAuth2PKCEError("invalid_state", 400)

        result = await self._oauth2_pkce_state_store().consume(
            state, cookie_value.decode("ascii", errors="strict")
        )
        if result.entry is not None and not result.initiator_mismatch:
            parsed = urllib.parse.urlparse(result.entry.redirect_uri)
            handler.clear_cookie(
                cookie_name,
                path=parsed.path or "/",
                secure=self._oauth2_pkce_cookie_secure(parsed.scheme),
                samesite=self._oauth2_pkce_setting("cookie_samesite", None, "Lax"),
            )
        if result.initiator_mismatch:
            raise OAuth2PKCEError("initiator_mismatch", 403)
        if result.entry is None:
            if provider_error == "access_denied":
                raise OAuth2PKCEError("access_denied", 403, "Login was denied")
            raise OAuth2PKCEError("invalid_state", 400)
        return result.entry

    def _oauth_request_token_url(
        self,
        redirect_uri: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        code: str | None = None,
        extra_params: dict[str, Any] | None = None,
    ) -> str:
        url = self._OAUTH_ACCESS_TOKEN_URL  # type: ignore
        args: dict[str, str] = {}
        if redirect_uri is not None:
            args["redirect_uri"] = redirect_uri
        if code is not None:
            args["code"] = code
        if client_id is not None:
            args["client_id"] = client_id
        if client_secret is not None:
            args["client_secret"] = client_secret
        if extra_params:
            args.update(extra_params)
        return url_concat(url, args)

    async def oauth2_request(
        self,
        url: str,
        access_token: str | None = None,
        post_args: dict[str, Any] | None = None,
        **args: Any,
    ) -> Any:
        """Fetches the given URL auth an OAuth2 access token.

        If the request is a POST, ``post_args`` should be provided. Query
        string arguments should be given as keyword arguments.

        Example usage:

        ..testcode::

            class MainHandler(tornado.web.RequestHandler,
                              tornado.auth.FacebookGraphMixin):
                @tornado.web.authenticated
                async def get(self):
                    new_entry = await self.oauth2_request(
                        "https://graph.facebook.com/me/feed",
                        post_args={"message": "I am posting from my Tornado application!"},
                        access_token=self.current_user["access_token"])

                    if not new_entry:
                        # Call failed; perhaps missing permission?
                        self.authorize_redirect()
                        return
                    self.finish("Posted a message!")

        .. versionadded:: 4.3

        .. versionchanged::: 6.0

           The ``callback`` argument was removed. Use the returned awaitable object instead.
        """
        all_args = {}
        if access_token:
            all_args["access_token"] = access_token
            all_args.update(args)

        if all_args:
            url += "?" + urllib.parse.urlencode(all_args)
        http = self.get_auth_http_client()
        if post_args is not None:
            response = await http.fetch(
                url, method="POST", body=urllib.parse.urlencode(post_args)
            )
        else:
            response = await http.fetch(url)
        return escape.json_decode(response.body)

    def get_auth_http_client(self) -> httpclient.AsyncHTTPClient:
        """Returns the `.AsyncHTTPClient` instance to be used for auth requests.

        May be overridden by subclasses to use an HTTP client other than
        the default.

        .. versionadded:: 4.3
        """
        return httpclient.AsyncHTTPClient()


class TwitterMixin(OAuthMixin):
    """Twitter OAuth authentication.

    To authenticate with Twitter, register your application with
    Twitter at http://twitter.com/apps. Then copy your Consumer Key
    and Consumer Secret to the application
    `~tornado.web.Application.settings` ``twitter_consumer_key`` and
    ``twitter_consumer_secret``. Use this mixin on the handler for the
    URL you registered as your application's callback URL.

    When your application is set up, you can use this mixin like this
    to authenticate the user with Twitter and get access to their stream:

    .. testcode::

        class TwitterLoginHandler(tornado.web.RequestHandler,
                                  tornado.auth.TwitterMixin):
            async def get(self):
                if self.get_argument("oauth_token", None):
                    user = await self.get_authenticated_user()
                    # Save the user using e.g. set_signed_cookie()
                else:
                    await self.authorize_redirect()

    The user object returned by `~OAuthMixin.get_authenticated_user`
    includes the attributes ``username``, ``name``, ``access_token``,
    and all of the custom Twitter user attributes described at
    https://dev.twitter.com/docs/api/1.1/get/users/show

    .. deprecated:: 6.3
       This class refers to version 1.1 of the Twitter API, which has been
       deprecated by Twitter. Since Twitter has begun to limit access to its
       API, this class will no longer be updated and will be removed in the
       future.
    """

    _OAUTH_REQUEST_TOKEN_URL = "https://api.twitter.com/oauth/request_token"
    _OAUTH_ACCESS_TOKEN_URL = "https://api.twitter.com/oauth/access_token"
    _OAUTH_AUTHORIZE_URL = "https://api.twitter.com/oauth/authorize"
    _OAUTH_AUTHENTICATE_URL = "https://api.twitter.com/oauth/authenticate"
    _OAUTH_NO_CALLBACKS = False
    _TWITTER_BASE_URL = "https://api.twitter.com/1.1"

    async def authenticate_redirect(self, callback_uri: str | None = None) -> None:
        """Just like `~OAuthMixin.authorize_redirect`, but
        auto-redirects if authorized.

        This is generally the right interface to use if you are using
        Twitter for single-sign on.

        .. versionchanged:: 3.1
           Now returns a `.Future` and takes an optional callback, for
           compatibility with `.gen.coroutine`.

        .. versionchanged:: 6.0

           The ``callback`` argument was removed. Use the returned
           awaitable object instead.
        """
        http = self.get_auth_http_client()
        response = await http.fetch(
            self._oauth_request_token_url(callback_uri=callback_uri)
        )
        self._on_request_token(self._OAUTH_AUTHENTICATE_URL, None, response)

    async def twitter_request(
        self,
        path: str,
        access_token: dict[str, Any],
        post_args: dict[str, Any] | None = None,
        **args: Any,
    ) -> Any:
        """Fetches the given API path, e.g., ``statuses/user_timeline/btaylor``

        The path should not include the format or API version number.
        (we automatically use JSON format and API version 1).

        If the request is a POST, ``post_args`` should be provided. Query
        string arguments should be given as keyword arguments.

        All the Twitter methods are documented at http://dev.twitter.com/

        Many methods require an OAuth access token which you can
        obtain through `~OAuthMixin.authorize_redirect` and
        `~OAuthMixin.get_authenticated_user`. The user returned through that
        process includes an 'access_token' attribute that can be used
        to make authenticated requests via this method. Example
        usage:

        .. testcode::

            class MainHandler(tornado.web.RequestHandler,
                              tornado.auth.TwitterMixin):
                @tornado.web.authenticated
                async def get(self):
                    new_entry = await self.twitter_request(
                        "/statuses/update",
                        post_args={"status": "Testing Tornado Web Server"},
                        access_token=self.current_user["access_token"])
                    if not new_entry:
                        # Call failed; perhaps missing permission?
                        await self.authorize_redirect()
                        return
                    self.finish("Posted a message!")

        .. versionchanged:: 6.0

           The ``callback`` argument was removed. Use the returned
           awaitable object instead.
        """
        if path.startswith("http:") or path.startswith("https:"):
            # Raw urls are useful for e.g. search which doesn't follow the
            # usual pattern: http://search.twitter.com/search.json
            url = path
        else:
            url = self._TWITTER_BASE_URL + path + ".json"
        # Add the OAuth resource request signature if we have credentials
        if access_token:
            all_args = {}
            all_args.update(args)
            all_args.update(post_args or {})
            method = "POST" if post_args is not None else "GET"
            oauth = self._oauth_request_parameters(
                url, access_token, all_args, method=method
            )
            args.update(oauth)
        if args:
            url += "?" + urllib.parse.urlencode(args)
        http = self.get_auth_http_client()
        if post_args is not None:
            response = await http.fetch(
                url, method="POST", body=urllib.parse.urlencode(post_args)
            )
        else:
            response = await http.fetch(url)
        return escape.json_decode(response.body)

    def _oauth_consumer_token(self) -> dict[str, Any]:
        handler = cast(RequestHandler, self)
        handler.require_setting("twitter_consumer_key", "Twitter OAuth")
        handler.require_setting("twitter_consumer_secret", "Twitter OAuth")
        return dict(
            key=handler.settings["twitter_consumer_key"],
            secret=handler.settings["twitter_consumer_secret"],
        )

    async def _oauth_get_user_future(
        self, access_token: dict[str, Any]
    ) -> dict[str, Any]:
        user = await self.twitter_request(
            "/account/verify_credentials", access_token=access_token
        )
        if user:
            user["username"] = user["screen_name"]
        return user


class GoogleOAuth2Mixin(OAuth2Mixin):
    """Google authentication using OAuth2.

    In order to use, register your application with Google and copy the
    relevant parameters to your application settings.

    * Go to the Google Dev Console at http://console.developers.google.com
    * Select a project, or create a new one.
    * Depending on permissions required, you may need to set your app to
      "testing" mode and add your account as a test user, or go through
      a verification process. You may also need to use the "Enable
      APIs and Services" command to enable specific services.
    * In the sidebar on the left, select Credentials.
    * Click CREATE CREDENTIALS and click OAuth client ID.
    * Under Application type, select Web application.
    * Name OAuth 2.0 client and click Create.
    * Copy the "Client secret" and "Client ID" to the application settings as
      ``{"google_oauth": {"key": CLIENT_ID, "secret": CLIENT_SECRET}}``
    * You must register the ``redirect_uri`` you plan to use with this class
      on the Credentials page.

    .. versionadded:: 3.2
    """

    _OAUTH_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    _OAUTH_ACCESS_TOKEN_URL = "https://www.googleapis.com/oauth2/v4/token"
    _OAUTH_USERINFO_URL = "https://www.googleapis.com/oauth2/v1/userinfo"
    _OAUTH_NO_CALLBACKS = False
    _OAUTH_SETTINGS_KEY = "google_oauth"

    def get_google_oauth_settings(self) -> dict[str, str]:
        """Return the Google OAuth 2.0 credentials that you created with
        [Google Cloud
        Platform](https://console.cloud.google.com/apis/credentials). The dict
        format is::

            {
                "key": "your_client_id", "secret": "your_client_secret"
            }

        If your credentials are stored differently (e.g. in a db) you can
        override this method for custom provision.
        """
        handler = cast(RequestHandler, self)
        return handler.settings[self._OAUTH_SETTINGS_KEY]

    async def get_authenticated_user(
        self,
        redirect_uri: str,
        code: str,
        client_id: str | None = None,
        client_secret: str | None = None,
    ) -> dict[str, Any]:
        """Handles the login for the Google user, returning an access token.

        The result is a dictionary containing an ``access_token`` field
        ([among others](https://developers.google.com/identity/protocols/OAuth2WebServer#handlingtheresponse)).
        Unlike other ``get_authenticated_user`` methods in this package,
        this method does not return any additional information about the user.
        The returned access token can be used with `OAuth2Mixin.oauth2_request`
        to request additional information (perhaps from
        ``https://www.googleapis.com/oauth2/v2/userinfo``)

        Example usage:

        .. testsetup::

            import urllib

        .. testcode::

            class GoogleOAuth2LoginHandler(tornado.web.RequestHandler,
                                           tornado.auth.GoogleOAuth2Mixin):
                async def get(self):
                    # Google requires an exact match for redirect_uri, so it's
                    # best to get it from your app configuration instead of from
                    # self.request.full_uri().
                    redirect_uri = urllib.parse.urljoin(self.application.settings['redirect_base_uri'],
                        self.reverse_url('google_oauth'))
                    async def get(self):
                        if self.get_argument('code', False):
                            access = await self.get_authenticated_user(
                                redirect_uri=redirect_uri,
                                code=self.get_argument('code'))
                            user = await self.oauth2_request(
                                "https://www.googleapis.com/oauth2/v1/userinfo",
                                access_token=access["access_token"])
                            # Save the user and access token. For example:
                            user_cookie = dict(id=user["id"], access_token=access["access_token"])
                            self.set_signed_cookie("user", json.dumps(user_cookie))
                            self.redirect("/")
                        else:
                            self.authorize_redirect(
                                redirect_uri=redirect_uri,
                                client_id=self.get_google_oauth_settings()['key'],
                                scope=['profile', 'email'],
                                response_type='code',
                                extra_params={'approval_prompt': 'auto'})

        .. versionchanged:: 6.0

           The ``callback`` argument was removed. Use the returned awaitable object instead.
        """  # noqa: E501

        if client_id is None or client_secret is None:
            settings = self.get_google_oauth_settings()
            if client_id is None:
                client_id = settings["key"]
            if client_secret is None:
                client_secret = settings["secret"]
        http = self.get_auth_http_client()
        body = urllib.parse.urlencode(
            {
                "redirect_uri": redirect_uri,
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "grant_type": "authorization_code",
            }
        )

        response = await http.fetch(
            self._OAUTH_ACCESS_TOKEN_URL,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=body,
        )
        return escape.json_decode(response.body)


class FacebookGraphMixin(OAuth2Mixin):
    """Facebook authentication using the new Graph API and OAuth2."""

    _OAUTH_ACCESS_TOKEN_URL = "https://graph.facebook.com/oauth/access_token?"
    _OAUTH_AUTHORIZE_URL = "https://www.facebook.com/dialog/oauth?"
    _OAUTH_NO_CALLBACKS = False
    _FACEBOOK_BASE_URL = "https://graph.facebook.com"

    async def get_authenticated_user(
        self,
        redirect_uri: str,
        client_id: str,
        client_secret: str,
        code: str,
        extra_fields: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Handles the login for the Facebook user, returning a user object.

        Example usage:

        .. testcode::

            class FacebookGraphLoginHandler(tornado.web.RequestHandler,
                                            tornado.auth.FacebookGraphMixin):
              async def get(self):
                redirect_uri = urllib.parse.urljoin(
                    self.application.settings['redirect_base_uri'],
                    self.reverse_url('facebook_oauth'))
                if self.get_argument("code", False):
                    user = await self.get_authenticated_user(
                        redirect_uri=redirect_uri,
                        client_id=self.settings["facebook_api_key"],
                        client_secret=self.settings["facebook_secret"],
                        code=self.get_argument("code"))
                    # Save the user with e.g. set_signed_cookie
                else:
                    self.authorize_redirect(
                        redirect_uri=redirect_uri,
                        client_id=self.settings["facebook_api_key"],
                        extra_params={"scope": "user_posts"})

        This method returns a dictionary which may contain the following fields:

        * ``access_token``, a string which may be passed to `facebook_request`
        * ``session_expires``, an integer encoded as a string representing
          the time until the access token expires in seconds. This field should
          be used like ``int(user['session_expires'])``; in a future version of
          Tornado it will change from a string to an integer.
        * ``id``, ``name``, ``first_name``, ``last_name``, ``locale``, ``picture``,
          ``link``, plus any fields named in the ``extra_fields`` argument. These
          fields are copied from the Facebook graph API
          `user object <https://developers.facebook.com/docs/graph-api/reference/user>`_

        .. versionchanged:: 4.5
           The ``session_expires`` field was updated to support changes made to the
           Facebook API in March 2017.

        .. versionchanged:: 6.0

           The ``callback`` argument was removed. Use the returned awaitable object instead.
        """
        http = self.get_auth_http_client()
        args = {
            "redirect_uri": redirect_uri,
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
        }

        fields = {"id", "name", "first_name", "last_name", "locale", "picture", "link"}
        if extra_fields:
            fields.update(extra_fields)

        response = await http.fetch(
            self._oauth_request_token_url(**args)  # type: ignore
        )
        args = escape.json_decode(response.body)
        session = {
            "access_token": args.get("access_token"),
            "expires_in": args.get("expires_in"),
        }
        assert session["access_token"] is not None

        user = await self.facebook_request(
            path="/me",
            access_token=session["access_token"],
            appsecret_proof=hmac.new(
                key=client_secret.encode("utf8"),
                msg=session["access_token"].encode("utf8"),
                digestmod=hashlib.sha256,
            ).hexdigest(),
            fields=",".join(fields),
        )

        if user is None:
            return None

        fieldmap = {}
        for field in fields:
            fieldmap[field] = user.get(field)

        # session_expires is converted to str for compatibility with
        # older versions in which the server used url-encoding and
        # this code simply returned the string verbatim.
        # This should change in Tornado 5.0.
        fieldmap.update(
            {
                "access_token": session["access_token"],
                "session_expires": str(session.get("expires_in")),
            }
        )
        return fieldmap

    async def facebook_request(
        self,
        path: str,
        access_token: str | None = None,
        post_args: dict[str, Any] | None = None,
        **args: Any,
    ) -> Any:
        """Fetches the given relative API path, e.g., "/btaylor/picture"

        If the request is a POST, ``post_args`` should be provided. Query
        string arguments should be given as keyword arguments.

        An introduction to the Facebook Graph API can be found at
        http://developers.facebook.com/docs/api

        Many methods require an OAuth access token which you can
        obtain through `~OAuth2Mixin.authorize_redirect` and
        `get_authenticated_user`. The user returned through that
        process includes an ``access_token`` attribute that can be
        used to make authenticated requests via this method.

        Example usage:

        .. testcode::

            class MainHandler(tornado.web.RequestHandler,
                              tornado.auth.FacebookGraphMixin):
                @tornado.web.authenticated
                async def get(self):
                    new_entry = await self.facebook_request(
                        "/me/feed",
                        post_args={"message": "I am posting from my Tornado application!"},
                        access_token=self.current_user["access_token"])

                    if not new_entry:
                        # Call failed; perhaps missing permission?
                        self.authorize_redirect()
                        return
                    self.finish("Posted a message!")

        The given path is relative to ``self._FACEBOOK_BASE_URL``,
        by default "https://graph.facebook.com".

        This method is a wrapper around `OAuth2Mixin.oauth2_request`;
        the only difference is that this method takes a relative path,
        while ``oauth2_request`` takes a complete url.

        .. versionchanged:: 3.1
           Added the ability to override ``self._FACEBOOK_BASE_URL``.

        .. versionchanged:: 6.0

           The ``callback`` argument was removed. Use the returned awaitable object instead.
        """
        url = self._FACEBOOK_BASE_URL + path
        return await self.oauth2_request(
            url, access_token=access_token, post_args=post_args, **args
        )


def _oauth_signature(
    consumer_token: dict[str, Any],
    method: str,
    url: str,
    parameters: dict[str, Any] = {},
    token: dict[str, Any] | None = None,
) -> bytes:
    """Calculates the HMAC-SHA1 OAuth signature for the given request.

    See http://oauth.net/core/1.0/#signing_process
    """
    parts = urllib.parse.urlparse(url)
    scheme, netloc, path = parts[:3]
    normalized_url = scheme.lower() + "://" + netloc.lower() + path

    base_elems = []
    base_elems.append(method.upper())
    base_elems.append(normalized_url)
    base_elems.append(
        "&".join(f"{k}={_oauth_escape(str(v))}" for k, v in sorted(parameters.items()))
    )
    base_string = "&".join(_oauth_escape(e) for e in base_elems)

    key_elems = [escape.utf8(consumer_token["secret"])]
    key_elems.append(escape.utf8(token["secret"] if token else ""))
    key = b"&".join(key_elems)

    hash = hmac.new(key, escape.utf8(base_string), hashlib.sha1)
    return binascii.b2a_base64(hash.digest())[:-1]


def _oauth10a_signature(
    consumer_token: dict[str, Any],
    method: str,
    url: str,
    parameters: dict[str, Any] = {},
    token: dict[str, Any] | None = None,
) -> bytes:
    """Calculates the HMAC-SHA1 OAuth 1.0a signature for the given request.

    See http://oauth.net/core/1.0a/#signing_process
    """
    parts = urllib.parse.urlparse(url)
    scheme, netloc, path = parts[:3]
    normalized_url = scheme.lower() + "://" + netloc.lower() + path

    base_elems = []
    base_elems.append(method.upper())
    base_elems.append(normalized_url)
    base_elems.append(
        "&".join(f"{k}={_oauth_escape(str(v))}" for k, v in sorted(parameters.items()))
    )

    base_string = "&".join(_oauth_escape(e) for e in base_elems)
    key_elems = [escape.utf8(urllib.parse.quote(consumer_token["secret"], safe="~"))]
    key_elems.append(
        escape.utf8(urllib.parse.quote(token["secret"], safe="~") if token else "")
    )
    key = b"&".join(key_elems)

    hash = hmac.new(key, escape.utf8(base_string), hashlib.sha1)
    return binascii.b2a_base64(hash.digest())[:-1]


def _oauth_escape(val: str | bytes) -> str:
    if isinstance(val, unicode_type):
        val = val.encode("utf-8")
    return urllib.parse.quote(val, safe="~")


def _oauth_parse_response(body: bytes) -> dict[str, Any]:
    # I can't find an officially-defined encoding for oauth responses and
    # have never seen anyone use non-ascii.  Leave the response in a byte
    # string for python 2, and use utf8 on python 3.
    body_str = escape.native_str(body)
    p = urllib.parse.parse_qs(body_str, keep_blank_values=False)
    token = dict(key=p["oauth_token"][0], secret=p["oauth_token_secret"][0])

    # Add the extra parameters the Provider included to the token
    special = ("oauth_token", "oauth_token_secret")
    token.update((k, p[k][0]) for k in p if k not in special)
    return token
