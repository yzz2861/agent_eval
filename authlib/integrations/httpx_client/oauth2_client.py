# ruff: noqa: I001
# The import order below is intentional: httpx compatibility must be loaded
# before anyio so import errors refer to httpx.
import typing
from contextlib import asynccontextmanager

from ._compat import httpx2
from anyio import Lock  # Import after httpx so import errors refer to httpx

from authlib.common.urls import url_decode
from authlib.common.urls import url_encode
from authlib.oauth2.auth import ClientAuth
from authlib.oauth2.auth import TokenAuth
from authlib.oauth2.client import OAuth2Client as _OAuth2Client
from authlib.oauth2.token_store import DEFAULT_LEASE_TTL
from authlib.oauth2.token_store import DEFAULT_WAIT_TIMEOUT
from authlib.oauth2.token_store import async_coordinated_token_refresh

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
        token_store=None,
        token_store_lease_ttl=DEFAULT_LEASE_TTL,
        token_store_wait_timeout=DEFAULT_WAIT_TIMEOUT,
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
            token_store=token_store,
            token_store_lease_ttl=token_store_lease_ttl,
            token_store_wait_timeout=token_store_wait_timeout,
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
        if self.token_store is not None:
            return await self._refresh_token_with_store(
                url,
                refresh_token=refresh_token,
                body=body,
                headers=headers,
                auth=auth,
                **kwargs,
            )

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

    async def _refresh_token_with_store(
        self,
        url,
        refresh_token=None,
        body="",
        headers=None,
        auth=USE_CLIENT_DEFAULT,
        **kwargs,
    ):
        previous_refresh_token = self.token.get("refresh_token") if self.token else None

        async def do_refresh(fresh_refresh_token):
            actual_body = body
            if fresh_refresh_token != refresh_token:
                # The store knows a fresher refresh token than the one this
                # instance was about to use; rebuild the request body with
                # it so the stale one is never sent.
                params = dict(url_decode(body))
                params["refresh_token"] = fresh_refresh_token
                actual_body = url_encode(params.items())

            resp = await self.post(
                url,
                data=dict(url_decode(actual_body)),
                headers=headers,
                auth=auth,
                **kwargs,
            )

            for hook in self.compliance_hook["refresh_token_response"]:
                resp = hook(resp)

            token = self.parse_response_token(resp)
            if "refresh_token" not in token:
                token["refresh_token"] = fresh_refresh_token
            return token

        token = await async_coordinated_token_refresh(
            self.token_store,
            self.token,
            self.leeway,
            do_refresh,
            lease_ttl=self.token_store_lease_ttl,
            wait_timeout=self.token_store_wait_timeout,
        )
        self.token = token

        if self.update_token:
            await self.update_token(self.token, refresh_token=previous_refresh_token)

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
        token_store=None,
        token_store_lease_ttl=DEFAULT_LEASE_TTL,
        token_store_wait_timeout=DEFAULT_WAIT_TIMEOUT,
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
            token_store=token_store,
            token_store_lease_ttl=token_store_lease_ttl,
            token_store_wait_timeout=token_store_wait_timeout,
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
