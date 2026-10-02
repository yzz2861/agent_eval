# ruff: noqa: I001
# The import order below is intentional: httpx compatibility must be loaded
# before anyio so import errors refer to httpx.
import typing
from contextlib import asynccontextmanager

from ._compat import httpx2
from anyio import Lock  # Import after httpx so import errors refer to httpx
from anyio import sleep as anyio_sleep

from authlib.common.errors import AuthlibBaseError
from authlib.common.urls import url_decode
from authlib.oauth2.auth import ClientAuth
from authlib.oauth2.auth import TokenAuth
from authlib.oauth2.client import DEFAULT_HEADERS
from authlib.oauth2.client import OAuth2Client as _OAuth2Client
from authlib.oauth2.rfc6749.parameters import prepare_token_request
from authlib.oauth2.rfc8628.client import DEVICE_CODE_GRANT_TYPE

from ..base_client import InvalidTokenError
from ..base_client import MissingTokenError
from ..base_client import OAuthError
from ..base_client import UnsupportedTokenTypeError
from .utils import HTTPX_CLIENT_KWARGS
from .utils import build_request

USE_CLIENT_DEFAULT = httpx2.USE_CLIENT_DEFAULT
Auth = httpx2.Auth
Request = httpx2.Request
Response = httpx2.Response

__all__ = [
    "OAuth2Auth",
    "OAuth2ClientAuth",
    "AsyncOAuth2Client",
    "OAuth2Client",
]


class OAuth2Auth(Auth, TokenAuth):
    """Sign requests for OAuth 2.0, currently only bearer token is supported."""

    requires_request_body = True

    def auth_flow(self, request: Request) -> typing.Generator[Request, Response, None]:
        try:
            url, headers, body = self.prepare(
                str(request.url), request.headers, request.content
            )
            headers["Content-Length"] = str(len(body))
            yield build_request(
                url=url, headers=headers, body=body, initial_request=request
            )
        except KeyError as error:
            description = f"Unsupported token_type: {str(error)}"
            raise UnsupportedTokenTypeError(description=description) from error


class OAuth2ClientAuth(Auth, ClientAuth):
    requires_request_body = True

    def auth_flow(self, request: Request) -> typing.Generator[Request, Response, None]:
        url, headers, body = self.prepare(
            request.method, str(request.url), request.headers, request.content
        )
        headers["Content-Length"] = str(len(body))
        yield build_request(
            url=url, headers=headers, body=body, initial_request=request
        )


class AsyncOAuth2Client(_OAuth2Client, httpx2.AsyncClient):
    SESSION_REQUEST_PARAMS = HTTPX_CLIENT_KWARGS

    client_auth_class = OAuth2ClientAuth
    token_auth_class = OAuth2Auth
    oauth_error_class = OAuthError
    network_timeout_exceptions = (httpx2.TimeoutException,)

    def __init__(
        self,
        client_id=None,
        client_secret=None,
        token_endpoint_auth_method=None,
        revocation_endpoint_auth_method=None,
        scope=None,
        redirect_uri=None,
        token=None,
        token_placement="header",
        update_token=None,
        leeway=60,
        **kwargs,
    ):
        # extract httpx2.Client kwargs
        client_kwargs = self._extract_session_request_params(kwargs)
        httpx2.AsyncClient.__init__(self, **client_kwargs)

        # We use a Lock to synchronize coroutines to prevent
        # multiple concurrent attempts to refresh the same token
        self._token_refresh_lock = Lock()

        _OAuth2Client.__init__(
            self,
            session=None,
            client_id=client_id,
            client_secret=client_secret,
            token_endpoint_auth_method=token_endpoint_auth_method,
            revocation_endpoint_auth_method=revocation_endpoint_auth_method,
            scope=scope,
            redirect_uri=redirect_uri,
            token=token,
            token_placement=token_placement,
            update_token=update_token,
            leeway=leeway,
            **kwargs,
        )

    async def request(
        self, method, url, withhold_token=False, auth=USE_CLIENT_DEFAULT, **kwargs
    ):
        if not withhold_token and auth is USE_CLIENT_DEFAULT:
            if not self.token:
                raise MissingTokenError()

            await self.ensure_active_token(self.token)

            auth = self.token_auth

        return await super().request(method, url, auth=auth, **kwargs)

    @asynccontextmanager
    async def stream(
        self, method, url, withhold_token=False, auth=USE_CLIENT_DEFAULT, **kwargs
    ):
        if not withhold_token and auth is USE_CLIENT_DEFAULT:
            if not self.token:
                raise MissingTokenError()

            await self.ensure_active_token(self.token)

            auth = self.token_auth

        async with super().stream(method, url, auth=auth, **kwargs) as resp:
            yield resp

    async def ensure_active_token(self, token):
        async with self._token_refresh_lock:
            if self.token.is_expired(leeway=self.leeway):
                refresh_token = token.get("refresh_token")
                url = self.metadata.get("token_endpoint")
                if refresh_token and url:
                    await self.refresh_token(url, refresh_token=refresh_token)
                elif self.metadata.get("grant_type") == "client_credentials":
                    access_token = token["access_token"]
                    new_token = await self.fetch_token(
                        url, grant_type="client_credentials"
                    )
                    if self.update_token:
                        await self.update_token(new_token, access_token=access_token)
                else:
                    raise InvalidTokenError()

    async def fetch_device_authorization(self, url=None, **kwargs):
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
        resp = await self._http_post(url, body, auth=auth, headers=DEFAULT_HEADERS)
        return self._parse_device_authorization_response(resp)

    async def poll_device_token(
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

        The loop runs in the caller's task: when this coroutine returns,
        raises or is cancelled, no further request for this device code
        is made.

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
        :param sleep: An awaitable callable used to wait between
            requests, defaults to ``anyio.sleep``.
        :param kwargs: Extra parameters passed to the HTTP session.
        :return: A :class:`OAuth2Token` object (a dict too).

        .. _`RFC 8628`: https://www.rfc-editor.org/rfc/rfc8628
        """
        device_code, url, state = self._prepare_device_token_poll(
            device_authorization, device_code, url, interval, expires_in, clock
        )
        if sleep is None:
            sleep = anyio_sleep

        while not state.expired:
            await sleep(state.next_delay())
            if state.expired:
                break
            try:
                return await self._fetch_device_token(url, device_code, **kwargs)
            except self.network_timeout_exceptions:
                state.handle_network_timeout()
            except AuthlibBaseError as error:
                if not state.handle_error(error.error):
                    raise

        raise self.oauth_error_class(
            error="expired_token",
            description="The device code expired before the user completed authorization.",
        )

    async def _fetch_device_token(self, url, device_code, **kwargs):
        body = prepare_token_request(
            DEVICE_CODE_GRANT_TYPE, "", device_code=device_code
        )
        auth = self.client_auth(self.token_endpoint_auth_method)
        return await self._fetch_token(
            url, body=body, auth=auth, headers=DEFAULT_HEADERS, **kwargs
        )

    async def _fetch_token(
        self,
        url,
        body="",
        headers=None,
        auth=USE_CLIENT_DEFAULT,
        method="POST",
        **kwargs,
    ):
        if method.upper() == "POST":
            resp = await self.post(
                url, data=dict(url_decode(body)), headers=headers, auth=auth, **kwargs
            )
        else:
            if "?" in url:
                url = "&".join([url, body])
            else:
                url = "?".join([url, body])
            resp = await self.get(url, headers=headers, auth=auth, **kwargs)

        for hook in self.compliance_hook["access_token_response"]:
            resp = hook(resp)

        return self.parse_response_token(resp)

    async def _refresh_token(
        self,
        url,
        refresh_token=None,
        body="",
        headers=None,
        auth=USE_CLIENT_DEFAULT,
        **kwargs,
    ):
        resp = await self.post(
            url, data=dict(url_decode(body)), headers=headers, auth=auth, **kwargs
        )

        for hook in self.compliance_hook["refresh_token_response"]:
            resp = hook(resp)

        token = self.parse_response_token(resp)
        if "refresh_token" not in token:
            self.token["refresh_token"] = refresh_token

        if self.update_token:
            await self.update_token(self.token, refresh_token=refresh_token)

        return self.token

    def _http_post(
        self, url, body=None, auth=USE_CLIENT_DEFAULT, headers=None, **kwargs
    ):
        return self.post(
            url, data=dict(url_decode(body)), headers=headers, auth=auth, **kwargs
        )


class OAuth2Client(_OAuth2Client, httpx2.Client):
    SESSION_REQUEST_PARAMS = HTTPX_CLIENT_KWARGS

    client_auth_class = OAuth2ClientAuth
    token_auth_class = OAuth2Auth
    oauth_error_class = OAuthError
    network_timeout_exceptions = (httpx2.TimeoutException,)

    def __init__(
        self,
        client_id=None,
        client_secret=None,
        token_endpoint_auth_method=None,
        revocation_endpoint_auth_method=None,
        scope=None,
        redirect_uri=None,
        token=None,
        token_placement="header",
        update_token=None,
        **kwargs,
    ):
        # extract httpx2.Client kwargs
        client_kwargs = self._extract_session_request_params(kwargs)
        httpx2.Client.__init__(self, **client_kwargs)

        _OAuth2Client.__init__(
            self,
            session=self,
            client_id=client_id,
            client_secret=client_secret,
            token_endpoint_auth_method=token_endpoint_auth_method,
            revocation_endpoint_auth_method=revocation_endpoint_auth_method,
            scope=scope,
            redirect_uri=redirect_uri,
            token=token,
            token_placement=token_placement,
            update_token=update_token,
            **kwargs,
        )

    @staticmethod
    def handle_error(error_type, error_description):
        raise OAuthError(error_type, error_description)

    def request(
        self, method, url, withhold_token=False, auth=USE_CLIENT_DEFAULT, **kwargs
    ):
        if not withhold_token and auth is USE_CLIENT_DEFAULT:
            if not self.token:
                raise MissingTokenError()

            if not self.ensure_active_token(self.token):
                raise InvalidTokenError()

            auth = self.token_auth

        return super().request(method, url, auth=auth, **kwargs)

    def stream(
        self, method, url, withhold_token=False, auth=USE_CLIENT_DEFAULT, **kwargs
    ):
        if not withhold_token and auth is USE_CLIENT_DEFAULT:
            if not self.token:
                raise MissingTokenError()

            if not self.ensure_active_token(self.token):
                raise InvalidTokenError()

            auth = self.token_auth

        return super().stream(method, url, auth=auth, **kwargs)
