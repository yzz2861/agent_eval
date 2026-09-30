from __future__ import annotations

import asyncio
import contextlib
import http.client
import json
import math
import threading
import time
import urllib.request
from collections import OrderedDict, namedtuple
from collections.abc import Awaitable, Callable
from email.message import Message
from functools import lru_cache
from ssl import SSLContext
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, urlsplit

from .api_jwk import PyJWK, PyJWKSet
from .api_jwt import decode_complete as decode_token
from .exceptions import PyJWKClientConnectionError, PyJWKClientError
from .jwk_set_cache import JWKSetCache


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        return None


class AsyncJWKSTransport(Protocol):
    async def fetch_data(
        self,
        uri: str,
        headers: dict[str, Any],
        timeout: float,
        ssl_context: SSLContext | None,
    ) -> dict[str, Any]: ...

    async def aclose(self) -> None: ...


class AsyncIOJWKSTransport:
    """Default non-blocking JWKS transport based on :mod:`asyncio` streams."""

    async def fetch_data(
        self,
        uri: str,
        headers: dict[str, Any],
        timeout: float,
        ssl_context: SSLContext | None,
    ) -> dict[str, Any]:
        parsed = urlsplit(uri)
        host = parsed.hostname
        if host is None:
            raise PyJWKClientConnectionError("Invalid JWKS URI: missing host")

        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80

        request_target = parsed.path or "/"
        if parsed.query:
            request_target = f"{request_target}?{parsed.query}"

        try:
            host.encode("ascii")
        except UnicodeEncodeError:
            host = host.encode("idna").decode("ascii")

        connection_kwargs: dict[str, Any] = {"host": host, "port": port}
        if parsed.scheme == "https":
            connection_kwargs["ssl"] = ssl_context

        body = b""
        writer: asyncio.StreamWriter | None = None
        try:
            reader, stream_writer = await asyncio.wait_for(
                asyncio.open_connection(**connection_kwargs), timeout
            )
            writer = stream_writer

            request_headers = (
                f"GET {request_target} HTTP/1.1\r\n"
                f"Host: {parsed.netloc.rsplit('@', 1)[-1]}\r\n"
                "Accept: application/json\r\n"
                "Connection: close\r\n"
            )
            for name, value in headers.items():
                request_headers += f"{name}: {value}\r\n"
            request_headers += "\r\n"

            writer.write(request_headers.encode("iso-8859-1"))
            await asyncio.wait_for(writer.drain(), timeout)

            status_line = await asyncio.wait_for(reader.readline(), timeout)
            try:
                status_parts = (
                    status_line.decode("iso-8859-1").rstrip("\r\n").split(" ", 2)
                )
                if len(status_parts) < 2:
                    raise ValueError("Malformed HTTP status line")
                http_version, status_text = status_parts[:2]
                status_code = int(status_text)
            except (ValueError, UnicodeError) as error:
                raise http.client.HTTPException("Malformed HTTP status line") from error

            if not http_version.startswith("HTTP/"):
                raise http.client.HTTPException("Malformed HTTP response")
            if 300 <= status_code < 400:
                raise PyJWKClientConnectionError("Redirects are not followed")
            if not 200 <= status_code < 300:
                raise PyJWKClientConnectionError(
                    f"JWKS endpoint returned HTTP {status_code}"
                )

            response_headers = Message()
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout)
                if line in (b"\r\n", b"\n", b""):
                    break
                name, _, value = line.decode("iso-8859-1").rstrip("\r\n").partition(":")
                if not _:
                    raise http.client.HTTPException("Malformed HTTP response header")
                response_headers[name.strip()] = value.strip()

            body = await self._read_body(reader, response_headers, timeout)
        except (OSError, TimeoutError, http.client.HTTPException) as error:
            raise PyJWKClientConnectionError(
                f'Fail to fetch data from the url, err: "{error}"'
            ) from error
        finally:
            if writer is not None:
                writer.close()
                with contextlib.suppress(Exception, OSError):
                    await writer.wait_closed()

        charset = response_headers.get_content_charset() or "utf-8"
        try:
            return json.loads(body.decode(charset))
        except (LookupError, UnicodeError, json.JSONDecodeError) as error:
            raise PyJWKClientConnectionError(
                f'Fail to decode JWKS response, err: "{error}"'
            ) from error

    @staticmethod
    async def _read_body(
        reader: asyncio.StreamReader,
        headers: Message,
        timeout: float,
    ) -> bytes:
        transfer_encoding = headers.get("Transfer-Encoding", "").lower()
        if "chunked" in transfer_encoding:
            chunks: list[bytes] = []
            while True:
                size_line = await asyncio.wait_for(reader.readline(), timeout)
                try:
                    chunk_size = int(size_line.split(b";", 1)[0].strip(), 16)
                except ValueError as error:
                    raise http.client.HTTPException("Malformed chunk size") from error
                if chunk_size == 0:
                    while True:
                        trailer = await asyncio.wait_for(reader.readline(), timeout)
                        if trailer in (b"\r\n", b"\n", b""):
                            break
                    break
                chunks.append(
                    await asyncio.wait_for(reader.readexactly(chunk_size), timeout)
                )
                await asyncio.wait_for(reader.readexactly(2), timeout)
            return b"".join(chunks)

        content_length = headers.get("Content-Length")
        if content_length is not None:
            try:
                length = int(content_length)
            except ValueError as error:
                raise http.client.HTTPException("Malformed Content-Length") from error
            if length < 0:
                raise http.client.HTTPException("Malformed Content-Length")
            return await asyncio.wait_for(reader.readexactly(length), timeout)

        return await asyncio.wait_for(reader.read(), timeout)

    async def aclose(self) -> None:
        return None

    close = aclose


_JWKSFetchResult = namedtuple("_JWKSFetchResult", ["payload", "jwk_set"])


class PyJWKClient:
    def __init__(
        self,
        uri: str,
        cache_keys: bool = False,
        max_cached_keys: int = 16,
        cache_jwk_set: bool = True,
        lifespan: float = 300,
        headers: dict[str, Any] | None = None,
        timeout: float = 30,
        ssl_context: SSLContext | None = None,
        cooldown_duration: float = 30,
    ):
        """A client for retrieving signing keys from a JWKS endpoint.

        ``PyJWKClient`` uses a two-tier caching system to avoid unnecessary
        network requests:

        **Tier 1 — JWK Set cache** (enabled by default):
        Caches the entire JSON Web Key Set response from the endpoint.
        Controlled by:

        - ``cache_jwk_set``: Set to ``True`` (the default) to enable this
          cache. When enabled, the JWK Set is fetched from the network only
          when the cache is empty or expired.
        - ``lifespan``: Time in seconds before the cached JWK Set expires.
          Defaults to ``300`` (5 minutes). Must be greater than 0.

        Unknown key IDs can trigger one forced refresh after the cooldown
        period configured by ``cooldown_duration``. Every successful fetch
        starts this cooldown, including the initial fetch and cache-expiry
        fetches. A newly rotated key may therefore wait for the cooldown
        period before it is fetched; set ``cooldown_duration`` to ``0`` to
        disable this behavior. The cooldown is bypassed when
        ``cache_jwk_set`` is ``False``.

        **Tier 2 — Signing key cache** (disabled by default):
        Caches individual signing keys (looked up by ``kid``) using an LRU
        cache with **no time-based expiration**. Keys are evicted only when
        the cache reaches its maximum size. Controlled by:

        - ``cache_keys``: Set to ``True`` to enable this cache.
          Defaults to ``False``.
        - ``max_cached_keys``: Maximum number of signing keys to keep in
          the LRU cache. Defaults to ``16``.

        :param uri: The URL of the JWKS endpoint.
        :type uri: str
        :param cache_keys: Enable the per-key LRU cache (Tier 2).
        :type cache_keys: bool
        :param max_cached_keys: Max entries in the signing key LRU cache.
        :type max_cached_keys: int
        :param cache_jwk_set: Enable the JWK Set response cache (Tier 1).
        :type cache_jwk_set: bool
        :param lifespan: TTL in seconds for the JWK Set cache.
        :type lifespan: float
        :param headers: Optional HTTP headers to include in requests.
        :type headers: dict or None
        :param timeout: HTTP request timeout in seconds.
        :type timeout: float
        :param ssl_context: Optional SSL context for the request.
        :type ssl_context: ssl.SSLContext or None
        :param cooldown_duration: Minimum time in seconds between forced
            refreshes after an unknown key ID. Defaults to ``30``.
        :type cooldown_duration: float
        """
        if headers is None:
            headers = {}
        # urllib's default OpenerDirector also handles file://, ftp://, and
        # data: URIs. Reject anything that isn't http(s) eagerly so a caller
        # passing an attacker-influenced URL (e.g. taken from a `jku` token
        # header) can't read local files or reach other unintended schemes.
        scheme = urlparse(uri).scheme.lower()
        if scheme not in ("http", "https"):
            raise PyJWKClientError(
                f"Invalid JWKS URI scheme {scheme!r}: only 'http' and 'https' "
                f"are supported."
            )
        self.uri = uri
        self.jwk_set_cache: JWKSetCache | None = None
        self.headers = headers
        self.timeout = timeout
        self.ssl_context = ssl_context
        if cooldown_duration < 0:
            raise PyJWKClientError(
                "Cooldown duration must be greater than or equal to 0, "
                f'the input is "{cooldown_duration}"'
            )
        if not math.isfinite(cooldown_duration):
            raise PyJWKClientError(
                f'Cooldown duration must be finite, the input is "{cooldown_duration}"'
            )
        self.cooldown_duration = cooldown_duration
        self._last_successful_fetch: float | None = None
        self._client_lock = threading.RLock()

        if cache_jwk_set:
            # Init jwt set cache with default or given lifespan.
            # Default lifespan is 300 seconds (5 minutes).
            if lifespan <= 0:
                raise PyJWKClientError(
                    f'Lifespan must be greater than 0, the input is "{lifespan}"'
                )
            self.jwk_set_cache = JWKSetCache(lifespan)
        else:
            self.jwk_set_cache = None

        if cache_keys:
            # Cache signing keys
            get_signing_key = lru_cache(maxsize=max_cached_keys)(self.get_signing_key)
            # Ignore mypy (https://github.com/python/mypy/issues/2427)
            self.get_signing_key = get_signing_key  # type: ignore[method-assign]

    def fetch_data(self) -> Any:
        """Fetch the JWK Set from the JWKS endpoint.

        Makes an HTTP request to the configured ``uri`` and returns the
        parsed JSON response. If the JWK Set cache is enabled, the
        response is stored in the cache.

        :returns: The parsed JWK Set as a dictionary.
        :raises PyJWKClientConnectionError: If the HTTP request fails.
        :raises PyJWKClientError: If the endpoint does not return a JSON
            object.
        :raises PyJWKSetError: If the JWK Set cache is enabled and the
            response contains no usable keys.
        """
        try:
            r = urllib.request.Request(url=self.uri, headers=self.headers)
            handlers: list[Any] = [_NoRedirectHandler()]
            if self.ssl_context is not None:
                handlers.append(urllib.request.HTTPSHandler(context=self.ssl_context))
            opener = urllib.request.build_opener(*handlers)
            with opener.open(r, timeout=self.timeout) as response:
                jwk_set = json.load(response)
        except (URLError, TimeoutError, http.client.HTTPException) as e:
            if isinstance(e, HTTPError):
                e.close()
            raise PyJWKClientConnectionError(
                f'Fail to fetch data from the url, err: "{e}"'
            ) from e

        # Validate the payload before it reaches the cache, so an endpoint
        # returning something that isn't a JSON object is reported as such
        # rather than as a malformed JWK Set.
        jwk_set = self._as_jwk_set_payload(jwk_set)

        # Only update the cache on a successful fetch. Writing in a
        # `finally` block with `jwk_set=None` on error clears any
        # previously-cached JWKS, turning a transient outage into a cache
        # wipe that breaks legitimate auth.
        if self.jwk_set_cache is not None:
            self.jwk_set_cache.put(jwk_set)
        self._last_successful_fetch = time.monotonic()
        return jwk_set

    def get_jwk_set(self, refresh: bool = False) -> PyJWKSet:
        """Return the JWK Set, using the cache when available.

        :param refresh: Force a fresh fetch from the endpoint, bypassing
            the cache.
        :type refresh: bool
        :returns: The JWK Set.
        :rtype: PyJWKSet
        :raises PyJWKClientError: If the endpoint does not return a JSON
            object.
        """
        data = None
        fetched = False
        if self.jwk_set_cache is not None and not refresh:
            data = self.jwk_set_cache.get()

        if data is None:
            data = self.fetch_data()
            fetched = True

        # A cache hit is already parsed, so serve it as-is. Only a fresh
        # fetch reaches the check below, which still matters because
        # `fetch_data()` may be overridden by a subclass.
        if isinstance(data, PyJWKSet):
            jwk_set = data
        else:
            jwk_set = PyJWKSet.from_dict(self._as_jwk_set_payload(data))

        # `fetch_data()` caches the payload it received from the endpoint,
        # but a subclass may filter or transform it before returning. Cache
        # the value actually being returned, so later cache hits serve the
        # same key set as this call rather than the pre-transform one.
        if fetched and self.jwk_set_cache is not None:
            self.jwk_set_cache.put(jwk_set)

        return jwk_set

    @staticmethod
    def _as_jwk_set_payload(data: Any) -> dict[str, Any]:
        if not isinstance(data, dict):
            raise PyJWKClientError("The JWKS endpoint did not return a JSON object")

        return data

    def get_signing_keys(self, refresh: bool = False) -> list[PyJWK]:
        """Return all signing keys from the JWK Set.

        Filters the JWK Set to keys whose ``use`` is ``"sig"`` (or
        unspecified) and that have a ``kid``.

        :param refresh: Force a fresh fetch from the endpoint, bypassing
            the cache.
        :type refresh: bool
        :returns: A list of signing keys.
        :rtype: list[PyJWK]
        :raises PyJWKClientError: If no signing keys are found.
        """
        jwk_set = self.get_jwk_set(refresh)
        return self._get_signing_keys_from_jwk_set(jwk_set)

    @staticmethod
    def _get_signing_keys_from_jwk_set(jwk_set: PyJWKSet) -> list[PyJWK]:
        signing_keys = [
            jwk_set_key
            for jwk_set_key in jwk_set.keys
            if jwk_set_key.public_key_use in ["sig", None] and jwk_set_key.key_id
        ]

        if not signing_keys:
            raise PyJWKClientError("The JWKS endpoint did not contain any signing keys")

        return signing_keys

    def get_signing_key(self, kid: str) -> PyJWK:
        """Return the signing key matching the given ``kid``.

        If no match is found in the current JWK Set, the set is refreshed
        from the endpoint and the lookup is retried once when the refresh
        cooldown permits it.

        :param kid: The key ID to look up.
        :type kid: str
        :returns: The matching signing key.
        :rtype: PyJWK
        :raises PyJWKClientError: If no matching key is found after
            refreshing.
        """
        with self._client_lock:
            signing_keys = self.get_signing_keys()
            signing_key = self.match_kid(signing_keys, kid)

            if not signing_key:
                cooling_down = (
                    self.jwk_set_cache is not None
                    and self._last_successful_fetch is not None
                    and time.monotonic() - self._last_successful_fetch
                    < self.cooldown_duration
                )
                if not cooling_down:
                    signing_keys = self.get_signing_keys(refresh=True)
                    self._last_successful_fetch = time.monotonic()
                    signing_key = self.match_kid(signing_keys, kid)

                if not signing_key:
                    raise PyJWKClientError(
                        f'Unable to find a signing key that matches: "{kid}"'
                    )

            return signing_key

    def get_signing_key_from_jwt(self, token: str | bytes) -> PyJWK:
        """Return the signing key for a JWT by reading its ``kid`` header.

        Extracts the ``kid`` from the token's unverified header and
        delegates to :meth:`get_signing_key`.

        :param token: The encoded JWT.
        :type token: str or bytes
        :returns: The matching signing key.
        :rtype: PyJWK
        """
        unverified = decode_token(token, options={"verify_signature": False})
        header = unverified["header"]
        return self.get_signing_key(header.get("kid"))

    @staticmethod
    def match_kid(signing_keys: list[PyJWK], kid: str) -> PyJWK | None:
        """Find a key in *signing_keys* that matches *kid*.

        :param signing_keys: The list of keys to search.
        :type signing_keys: list[PyJWK]
        :param kid: The key ID to match.
        :type kid: str
        :returns: The matching key, or ``None`` if not found.
        :rtype: PyJWK or None
        """
        signing_key = None

        for key in signing_keys:
            if key.key_id == kid:
                signing_key = key
                break

        return signing_key


class AsyncPyJWKClient:
    def __init__(
        self,
        uri: str,
        cache_keys: bool = False,
        max_cached_keys: int = 16,
        cache_jwk_set: bool = True,
        lifespan: float = 300,
        headers: dict[str, Any] | None = None,
        timeout: float = 30,
        ssl_context: SSLContext | None = None,
        cooldown_duration: float = 30,
        transport: AsyncJWKSTransport | None = None,
    ):
        """Asynchronous equivalent of :class:`PyJWKClient`.

        The constructor arguments and lookup methods mirror
        :class:`PyJWKClient`. ``transport`` can provide an asynchronous HTTP
        implementation, for example one backed by a preferred HTTP client.
        When omitted, the client creates and owns a transport built on
        :mod:`asyncio` streams. Closing the client closes only a transport
        that it created; caller-provided transports remain the caller's
        responsibility.
        """
        if headers is None:
            headers = {}

        scheme = urlparse(uri).scheme.lower()
        if scheme not in ("http", "https"):
            raise PyJWKClientError(
                f"Invalid JWKS URI scheme {scheme!r}: only 'http' and 'https' "
                f"are supported."
            )
        if cooldown_duration < 0:
            raise PyJWKClientError(
                "Cooldown duration must be greater than or equal to 0, "
                f'the input is "{cooldown_duration}"'
            )
        if not math.isfinite(cooldown_duration):
            raise PyJWKClientError(
                f'Cooldown duration must be finite, the input is "{cooldown_duration}"'
            )
        if cache_jwk_set and lifespan <= 0:
            raise PyJWKClientError(
                f'Lifespan must be greater than 0, the input is "{lifespan}"'
            )
        if timeout < 0 or not math.isfinite(timeout):
            raise PyJWKClientError(
                f'Timeout must be a finite number greater than or equal to 0, the input is "{timeout}"'
            )
        self.uri = uri
        self.headers = headers
        self.timeout = timeout
        self.ssl_context = ssl_context
        self.cooldown_duration = cooldown_duration
        self.jwk_set_cache: JWKSetCache | None = (
            JWKSetCache(lifespan) if cache_jwk_set else None
        )
        self._owns_transport = transport is None
        self.transport: AsyncJWKSTransport | None = transport or AsyncIOJWKSTransport()
        self._closed = False
        self._inflight_fetch: asyncio.Task[Any] | None = None
        self._inflight_waiters: set[asyncio.Task[Any]] = set()
        self._last_successful_fetch: float | None = None
        self._key_cache: OrderedDict[str, PyJWK] | None = (
            OrderedDict() if cache_keys and max_cached_keys > 0 else None
        )
        self._max_cached_keys = max_cached_keys

    def _ensure_open(self) -> None:
        if self._closed:
            raise PyJWKClientError("Cannot use a closed AsyncPyJWKClient")

    def _closed_error(self) -> PyJWKClientError:
        return PyJWKClientError("Cannot use a closed AsyncPyJWKClient")

    async def fetch_data(self) -> dict[str, Any]:
        """Fetch and cache the JWK Set from the asynchronous transport."""
        self._ensure_open()
        if self._inflight_fetch is asyncio.current_task():
            return (await self._fetch_result_once()).payload

        result = await self._coalesce_fetch(self._fetch_result_task)
        return result.payload

    async def _fetch_result_once(self) -> _JWKSFetchResult:
        data = self._as_jwk_set_payload(await self._transport_fetch_data())
        jwk_set = PyJWKSet.from_dict(data)
        if self.jwk_set_cache is not None:
            self.jwk_set_cache.put(jwk_set)
        self._last_successful_fetch = time.monotonic()
        return _JWKSFetchResult(data, jwk_set)

    async def _transport_fetch_data(self) -> dict[str, Any]:
        assert self.transport is not None
        return await self.transport.fetch_data(
            self.uri,
            self.headers,
            self.timeout,
            self.ssl_context,
        )

    async def _coalesce_fetch(
        self,
        fetcher: Callable[..., Awaitable[Any]],
        refresh: bool = False,
    ) -> Any:
        self._ensure_open()
        if self._inflight_fetch is asyncio.current_task():
            return await fetcher(refresh=refresh)

        if self._inflight_fetch is None:
            self._inflight_fetch = asyncio.create_task(fetcher(refresh))
            self._inflight_fetch.add_done_callback(self._fetch_finished)

        fetch = self._inflight_fetch
        waiter = asyncio.current_task()
        if waiter is not None:
            self._inflight_waiters.add(waiter)
        try:
            return await asyncio.shield(fetch)
        except asyncio.CancelledError:
            if self._closed:
                raise self._closed_error() from None
            raise
        finally:
            if waiter is not None:
                self._inflight_waiters.discard(waiter)

    def _fetch_finished(
        self,
        future: asyncio.Task[Any],
    ) -> None:
        if self._inflight_fetch is future:
            self._inflight_fetch = None

    async def get_jwk_set(self, refresh: bool = False) -> PyJWKSet:
        """Return the JWK Set, coalescing concurrent fetches."""
        self._ensure_open()
        if self._inflight_fetch is asyncio.current_task():
            result = await self._load_jwk_set(refresh)
        else:
            result = await self._coalesce_fetch(self.get_jwk_set, refresh=refresh)

        if isinstance(result, _JWKSFetchResult):
            return result.jwk_set
        return result

    async def _load_jwk_set(self, refresh: bool) -> PyJWKSet:
        data: PyJWKSet | dict[str, Any] | None = None

        if self.jwk_set_cache is not None and not refresh:
            data = self.jwk_set_cache.get()

        if data is None:
            result = await self._coalesce_fetch(self._fetch_result_task)
            return result.jwk_set

        if isinstance(data, PyJWKSet):
            return data

        return PyJWKSet.from_dict(self._as_jwk_set_payload(data))

    async def _fetch_result_task(self, refresh: bool = False) -> _JWKSFetchResult:
        return await self._fetch_result_once()

    @staticmethod
    def _as_jwk_set_payload(data: Any) -> dict[str, Any]:
        if not isinstance(data, dict):
            raise PyJWKClientError("The JWKS endpoint did not return a JSON object")

        return data

    async def get_signing_keys(self, refresh: bool = False) -> list[PyJWK]:
        """Return all signing keys from the JWK Set."""
        jwk_set = await self.get_jwk_set(refresh)
        return self._get_signing_keys_from_jwk_set(jwk_set)

    @staticmethod
    def _get_signing_keys_from_jwk_set(jwk_set: PyJWKSet) -> list[PyJWK]:
        signing_keys = [
            jwk_set_key
            for jwk_set_key in jwk_set.keys
            if jwk_set_key.public_key_use in ["sig", None] and jwk_set_key.key_id
        ]

        if not signing_keys:
            raise PyJWKClientError("The JWKS endpoint did not contain any signing keys")

        return signing_keys

    async def get_signing_key(self, kid: str) -> PyJWK:
        """Return the signing key matching the given ``kid``."""
        if self._key_cache is not None:
            cached_key = self._key_cache.get(kid)
            if cached_key is not None:
                self._key_cache.move_to_end(kid)
                return cached_key

        signing_keys = await self.get_signing_keys()
        signing_key = self.match_kid(signing_keys, kid)

        if not signing_key:
            cooling_down = (
                self.jwk_set_cache is not None
                and self._last_successful_fetch is not None
                and time.monotonic() - self._last_successful_fetch
                < self.cooldown_duration
            )
            if not cooling_down:
                result = await self._coalesce_fetch(self._fetch_result_task)
                jwk_set = result.jwk_set
                signing_keys = self._get_signing_keys_from_jwk_set(jwk_set)
                self._last_successful_fetch = time.monotonic()
                signing_key = self.match_kid(signing_keys, kid)

            if not signing_key:
                raise PyJWKClientError(
                    f'Unable to find a signing key that matches: "{kid}"'
                )

        if self._key_cache is not None:
            self._key_cache[kid] = signing_key
            self._key_cache.move_to_end(kid)
            while len(self._key_cache) > self._max_cached_keys:
                self._key_cache.popitem(last=False)

        return signing_key

    async def get_signing_key_from_jwt(self, token: str | bytes) -> PyJWK:
        """Return the signing key for a JWT by reading its ``kid`` header."""
        unverified = decode_token(token, options={"verify_signature": False})
        header = unverified["header"]
        return await self.get_signing_key(header.get("kid"))

    @staticmethod
    def match_kid(signing_keys: list[PyJWK], kid: str) -> PyJWK | None:
        signing_key = None

        for key in signing_keys:
            if key.key_id == kid:
                signing_key = key
                break

        return signing_key

    async def aclose(self) -> None:
        """Close the client and release a transport that it created."""
        if self._closed:
            return

        self._closed = True
        waiters = self._inflight_waiters.copy()
        self._inflight_waiters.clear()
        for waiter in waiters:
            if not waiter.done():
                waiter.cancel()

        fetch = self._inflight_fetch
        if fetch is not None and not fetch.done():
            fetch.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await asyncio.shield(fetch)

        transport = self.transport
        self.transport = None
        if transport is not None and self._owns_transport:
            close = getattr(transport, "aclose", None) or getattr(
                transport, "close", None
            )
            result = close()
            if asyncio.iscoroutine(result):
                await result

    close = aclose

    async def __aenter__(self) -> AsyncPyJWKClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> None:
        await self.aclose()
