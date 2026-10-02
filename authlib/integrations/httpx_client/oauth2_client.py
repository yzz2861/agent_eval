# ruff: noqa: I001
# The import order below is intentional: httpx compatibility must be loaded
# before anyio so import errors refer to httpx.
import asyncio
import time
import typing
from contextlib import asynccontextmanager

from ._compat import httpx2
from anyio import Lock  # Import after httpx so import errors refer to httpx

from authlib.common.urls import url_decode
from authlib.oauth2.auth import ClientAuth
from authlib.oauth2.auth import TokenAuth
from authlib.oauth2.client import OAuth2Client as _OAuth2Client
from authlib.oauth2.client import DEFAULT_DEVICE_POLL_INTERVAL
from authlib.oauth2.client import DEVICE_POLL_MAX_TIMEOUT_BACKOFF
from authlib.oauth2.rfc8628 import DEVICE_CODE_GRANT_TYPE
from authlib.oauth2.rfc8628 import ExpiredTokenError

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
    network_timeout_errors = (TimeoutError, httpx2.TimeoutException)

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

    async def _fetch_device_authorization(self, url, body, auth, headers, **kwargs):
        resp = await self.post(
            url, data=dict(url_decode(body)), auth=auth, headers=headers, **kwargs
        )
        return self._parse_device_authorization_response(resp)

    async def poll_device_token(
        self,
        device_info,
        url=None,
        *,
        clock=None,
        sleep=None,
        cancel_event=None,
        **kwargs,
    ):
        """Async variant of the device token polling defined in RFC8628
        Section 3.3 and 3.5. See the sync client documentation for details.

        :param device_info: The device authorization response returned by
            ``fetch_device_authorization``, or a ``device_code`` string.
        :param url: Token endpoint URL. If not given, the ``token_endpoint``
            metadata value is used.
        :param clock: A callable returning the current time in seconds.
            Defaults to ``time.monotonic``.
        :param sleep: An awaitable callable used to wait between polling
            requests. Defaults to ``asyncio.sleep``.
        :param cancel_event: An optional event-like object with an
            ``is_set()`` method (e.g. ``asyncio.Event``). Once set,
            polling stops and no further request is sent.
        :return: A :class:`OAuth2Token` object, or ``None`` if
            ``cancel_event`` was set.

        Polling happens in the calling task: when this coroutine returns,
        the device code is not polled anymore in the background.
        """
        if isinstance(device_info, str):
            device_info = {"device_code": device_info}

        device_code = device_info["device_code"]
        interval = device_info.get("interval") or DEFAULT_DEVICE_POLL_INTERVAL

        if clock is None:
            clock = time.monotonic
        if sleep is None:
            sleep = asyncio.sleep
        if url is None:
            url = self.metadata.get("token_endpoint")

        expires_in = device_info.get("expires_in")
        deadline = None
        if expires_in is not None:
            deadline = clock() + expires_in

        timeout_backoff = None
        while True:
            if cancel_event is not None and cancel_event.is_set():
                return None
            if deadline is not None and clock() >= deadline:
                raise ExpiredTokenError()

            try:
                return await self.fetch_token(
                    url,
                    grant_type=DEVICE_CODE_GRANT_TYPE,
                    device_code=device_code,
                    **kwargs,
                )
            except self.network_timeout_errors:
                # network timeout: back off independently of the
                # protocol polling interval
                if timeout_backoff is None:
                    timeout_backoff = 1
                else:
                    timeout_backoff = min(
                        timeout_backoff * 2, DEVICE_POLL_MAX_TIMEOUT_BACKOFF
                    )
                wait = timeout_backoff
            except self.oauth_error_class as error:
                # the server answered: reset the network timeout backoff
                timeout_backoff = None
                if error.error == "authorization_pending":
                    wait = interval
                elif error.error == "slow_down":
                    interval += 5
                    wait = interval
                else:
                    raise

            await sleep(wait)


class OAuth2Client(_OAuth2Client, httpx2.Client):
    SESSION_REQUEST_PARAMS = HTTPX_CLIENT_KWARGS

    client_auth_class = OAuth2ClientAuth
    token_auth_class = OAuth2Auth
    oauth_error_class = OAuthError
    network_timeout_errors = (TimeoutError, httpx2.TimeoutException)

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
