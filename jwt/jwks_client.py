from __future__ import annotations

import asyncio
import contextlib
import http.client
import io
import json
import math
import ssl
import threading
import time
import urllib.request
from collections import OrderedDict
from functools import lru_cache
from typing import Any, Protocol, runtime_checkable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, urlsplit

from .api_jwk import PyJWK, PyJWKSet
from .api_jwt import decode_complete as decode_token
from .exceptions import PyJWKClientConnectionError, PyJWKClientError
from .jwk_set_cache import JWKSetCache


@runtime_checkable
class AsyncHTTPTransport(Protocol):
    """Asynchronous HTTP transport used by :class:`AsyncPyJWKClient`."""

    async def request(
        self,
        uri: str,
        headers: dict[str, Any],
        timeout: float,
        ssl_context: ssl.SSLContext | None,
    ) -> bytes:
        """Return the raw JWKS response body for the configured request."""
        ...


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


class _DefaultAsyncHTTPTransport:
    def __init__(self) -> None:
        self._ssl_context: ssl.SSLContext | None = None

    async def request(
        self,
        uri: str,
        headers: dict[str, Any],
        timeout: float,
        ssl_context: ssl.SSLContext | None,
    ) -> bytes:
        parsed = urlsplit(uri)
        scheme = parsed.scheme.lower()
        host = parsed.hostname
        if host is None:
            raise PyJWKClientConnectionError(
                f'Fail to fetch data from the url, err: "Missing host in {uri!r}"'
            )

        try:
            port = parsed.port
        except ValueError as error:
            raise PyJWKClientConnectionError(
                f'Fail to fetch data from the url, err: "{error}"'
            ) from error
        if port is None:
            port = 443 if scheme == "https" else 80
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        if "\r" in path or "\n" in path:
            raise PyJWKClientConnectionError(
                'Fail to fetch data from the url, err: "Invalid request target"'
            )

        request_headers = dict(headers)
        host_header = f"[{host}]" if ":" in host else host
        if not any(key.lower() == "host" for key in request_headers):
            request_headers["Host"] = host_header
        if not any(key.lower() == "connection" for key in request_headers):
            request_headers["Connection"] = "close"
        if any(
            "\r" in str(key)
            or "\n" in str(key)
            or "\r" in str(value)
            or "\n" in str(value)
            for key, value in request_headers.items()
        ):
            raise PyJWKClientConnectionError(
                'Fail to fetch data from the url, err: "Invalid HTTP header"'
            )

        request_lines = [f"GET {path} HTTP/1.1\r\n"]
        request_lines.extend(
            f"{key}: {value}\r\n" for key, value in request_headers.items()
        )
        request_lines.append("\r\n")
        try:
            request_data = "".join(request_lines).encode("latin-1")
        except UnicodeEncodeError as error:
            raise PyJWKClientConnectionError(
                f'Fail to fetch data from the url, err: "{error}"'
            ) from error

        is_https = scheme == "https"
        if is_https and ssl_context is None and self._ssl_context is None:
            self._ssl_context = ssl.create_default_context()
        context = ssl_context if is_https else None
        server_hostname = host if is_https else None

        reader: asyncio.StreamReader | None = None
        writer: asyncio.StreamWriter | None = None
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        try:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        host, port, ssl=context, server_hostname=server_hostname
                    ),
                    timeout=max(0.0, deadline - loop.time()),
                )
                writer.write(request_data)
                await asyncio.wait_for(
                    writer.drain(), timeout=max(0.0, deadline - loop.time())
                )
                header_data = await asyncio.wait_for(
                    reader.readuntil(b"\r\n\r\n"),
                    timeout=max(0.0, deadline - loop.time()),
                )
                status_end = header_data.find(b"\r\n")
                if status_end < 0:
                    raise http.client.HTTPException("Invalid HTTP response")
                status_line = header_data[:status_end].decode("latin-1")
                status_parts = status_line.split(" ", 2)
                if len(status_parts) < 2 or not status_parts[0].startswith("HTTP/"):
                    raise http.client.HTTPException(
                        f"Invalid status line {status_line!r}"
                    )
                status_code = int(status_parts[1])
                message = http.client.parse_headers(
                    io.BytesIO(header_data[status_end + 2 :])
                )
            except (
                OSError,
                TimeoutError,
                ValueError,
                asyncio.LimitOverrunError,
                http.client.HTTPException,
            ) as error:
                raise PyJWKClientConnectionError(
                    f'Fail to fetch data from the url, err: "{error}"'
                ) from error

            if not 200 <= status_code < 300:
                raise PyJWKClientConnectionError(
                    f'Fail to fetch data from the url, err: "HTTP {status_code}"'
                )

            async def read_body() -> bytes:
                assert reader is not None
                if message.get("Transfer-Encoding", "").lower() == "chunked":
                    chunks: list[bytes] = []
                    while True:
                        size_line = await reader.readline()
                        if not size_line:
                            raise http.client.IncompleteRead(b"")
                        size_part = size_line.split(b";", 1)[0].strip()
                        try:
                            chunk_size = int(size_part, 16)
                        except ValueError as error:
                            raise http.client.HTTPException(
                                "Invalid chunk size"
                            ) from error
                        if chunk_size == 0:
                            while await reader.readline() not in (b"\r\n", b""):
                                pass
                            break
                        chunks.append(await reader.readexactly(chunk_size))
                        await reader.readexactly(2)
                    return b"".join(chunks)

                content_length = message.get("Content-Length")
                if content_length is not None:
                    return await reader.readexactly(int(content_length))
                return await reader.read(-1)

            try:
                return await asyncio.wait_for(
                    read_body(), timeout=max(0.0, deadline - loop.time())
                )
            except (
                OSError,
                TimeoutError,
                ValueError,
                http.client.HTTPException,
            ) as error:
                raise PyJWKClientConnectionError(
                    f'Fail to fetch data from the url, err: "{error}"'
                ) from error
        finally:
            if writer is not None:
                writer.close()
                with contextlib.suppress(Exception):
                    await asyncio.shield(writer.wait_closed())

    async def aclose(self) -> None:
        return None


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
        ssl_context: ssl.SSLContext | None = None,
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
        ssl_context: ssl.SSLContext | None = None,
        cooldown_duration: float = 30,
        transport: AsyncHTTPTransport | None = None,
    ):
        """Asynchronous client for retrieving signing keys from JWKS.

        Caching and key lookup behavior mirrors :class:`PyJWKClient`. JWKS
        requests are made through the supplied asynchronous transport, while
        the default transport uses asyncio streams instead of running blocking
        urllib calls in a thread.

        Concurrent cache misses and allowed unknown-kid refreshes share one
        in-flight request. Cancelling one waiter does not cancel that request,
        and failed responses are not cached. Close the client when finished;
        a created transport is closed, while an injected transport is retained.
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

        self.uri = uri
        self.headers = headers
        self.timeout = timeout
        self.ssl_context = ssl_context
        self.cooldown_duration = cooldown_duration
        self._transport = (
            transport if transport is not None else _DefaultAsyncHTTPTransport()
        )
        self._owns_transport = transport is None
        self._last_successful_fetch: float | None = None
        self.jwk_set_cache: JWKSetCache | None = None
        self._fetch_lock: asyncio.Lock | None = None
        self._refresh_lock: asyncio.Lock | None = None
        self._key_cache_lock: asyncio.Lock | None = None
        self._fetch_future: asyncio.Future[dict[str, Any]] | None = None
        self._fetch_task: asyncio.Task[None] | None = None
        self._close_task: asyncio.Task[None] | None = None
        self._closed = False
        self._cached_signing_keys: OrderedDict[str, PyJWK] = OrderedDict()
        self._max_cached_keys = max_cached_keys

        if cache_jwk_set:
            if lifespan <= 0:
                raise PyJWKClientError(
                    f'Lifespan must be greater than 0, the input is "{lifespan}"'
                )
            self.jwk_set_cache = JWKSetCache(lifespan)

        if cache_keys:
            self.get_signing_key = self._get_cached_signing_key  # type: ignore[method-assign]

    def _ensure_open(self) -> None:
        if self._closed:
            raise PyJWKClientError("The JWK client is closed")

    def _get_fetch_lock(self) -> asyncio.Lock:
        lock = self._fetch_lock
        if lock is None:
            lock = asyncio.Lock()
            self._fetch_lock = lock
        return lock

    def _get_refresh_lock(self) -> asyncio.Lock:
        lock = self._refresh_lock
        if lock is None:
            lock = asyncio.Lock()
            self._refresh_lock = lock
        return lock

    def _get_key_cache_lock(self) -> asyncio.Lock:
        lock = self._key_cache_lock
        if lock is None:
            lock = asyncio.Lock()
            self._key_cache_lock = lock
        return lock

    async def fetch_data(self) -> Any:
        """Fetch and validate the JWK Set through the async transport."""
        self._ensure_open()
        return await self._fetch_data()

    async def _fetch_data(self) -> dict[str, Any]:
        async with self._get_fetch_lock():
            self._ensure_open()
            future = self._fetch_future
            if future is None or future.done():
                future = asyncio.get_running_loop().create_future()
                self._fetch_future = future
                self._fetch_task = asyncio.create_task(self._perform_fetch(future))
                self._fetch_task.add_done_callback(
                    lambda task: self._fetch_task_done(task, future)
                )

        return await asyncio.shield(future)

    @staticmethod
    def _fetch_task_done(
        task: asyncio.Task[None], future: asyncio.Future[dict[str, Any]]
    ) -> None:
        if task.cancelled():
            return
        task.exception()
        if not future.done() or future.cancelled():
            return
        future.exception()

    async def _perform_fetch(self, future: asyncio.Future[dict[str, Any]]) -> None:
        try:
            try:
                response = await self._transport.request(
                    self.uri, self.headers, self.timeout, self.ssl_context
                )
            except asyncio.CancelledError:
                raise
            except PyJWKClientError:
                raise
            except Exception as error:
                raise PyJWKClientConnectionError(
                    f'Fail to fetch data from the url, err: "{error}"'
                ) from error

            if isinstance(response, dict):
                jwk_set = response
            else:
                try:
                    jwk_set = json.loads(response)
                except (TypeError, ValueError) as error:
                    raise PyJWKClientError(
                        "The JWKS endpoint did not return valid JSON"
                    ) from error

            jwk_set = self._as_jwk_set_payload(jwk_set)
            if self.jwk_set_cache is not None:
                self.jwk_set_cache.put(jwk_set)
            self._last_successful_fetch = time.monotonic()
            if not future.done():
                future.set_result(jwk_set)
        except asyncio.CancelledError:
            if not future.done():
                future.set_exception(PyJWKClientError("The JWK client is closed"))
            raise
        except BaseException as error:
            if not future.done():
                future.set_exception(error)

    async def get_jwk_set(self, refresh: bool = False) -> PyJWKSet:
        """Return the JWK Set, using the cache unless refresh is requested."""
        self._ensure_open()
        data = None
        fetched = False
        if self.jwk_set_cache is not None and not refresh:
            data = self.jwk_set_cache.get()

        if data is None:
            data = await self.fetch_data()
            fetched = True

        self._ensure_open()
        if isinstance(data, PyJWKSet):
            jwk_set = data
        else:
            jwk_set = PyJWKSet.from_dict(self._as_jwk_set_payload(data))

        if fetched and self.jwk_set_cache is not None:
            self.jwk_set_cache.put(jwk_set)

        return jwk_set

    @staticmethod
    def _as_jwk_set_payload(data: Any) -> dict[str, Any]:
        if not isinstance(data, dict):
            raise PyJWKClientError("The JWKS endpoint did not return a JSON object")
        return data

    async def get_signing_keys(self, refresh: bool = False) -> list[PyJWK]:
        """Return all usable signing keys in the current JWK Set."""
        self._ensure_open()
        jwk_set = await self.get_jwk_set(refresh)
        return PyJWKClient._get_signing_keys_from_jwk_set(jwk_set)

    async def get_signing_key(self, kid: str) -> PyJWK:
        """Return the signing key matching kid, with cooldown refresh."""
        return await self._get_uncached_signing_key(kid)

    async def _get_uncached_signing_key(self, kid: str) -> PyJWK:
        async with self._get_refresh_lock():
            self._ensure_open()
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
                    signing_keys = await self.get_signing_keys(refresh=True)
                    signing_key = self.match_kid(signing_keys, kid)

                if not signing_key:
                    raise PyJWKClientError(
                        f'Unable to find a signing key that matches: "{kid}"'
                    )

            return signing_key

    async def _get_cached_signing_key(self, kid: str) -> PyJWK:
        self._ensure_open()
        lock = self._get_key_cache_lock()
        async with lock:
            try:
                signing_key = self._cached_signing_keys[kid]
                self._cached_signing_keys.move_to_end(kid)
                return signing_key
            except KeyError:
                pass

        signing_key = await self._get_uncached_signing_key(kid)

        max_cached_keys = self._max_cached_keys
        async with lock:
            self._cached_signing_keys[kid] = signing_key
            self._cached_signing_keys.move_to_end(kid)
            if (
                max_cached_keys is not None
                and max_cached_keys >= 0
                and len(self._cached_signing_keys) > max_cached_keys
            ):
                self._cached_signing_keys.popitem(last=False)

        return signing_key

    async def get_signing_key_from_jwt(self, token: str | bytes) -> PyJWK:
        """Read a JWT kid header and return its signing key."""
        self._ensure_open()
        unverified = decode_token(token, options={"verify_signature": False})
        header = unverified["header"]
        return await self.get_signing_key(header.get("kid"))

    @staticmethod
    def match_kid(signing_keys: list[PyJWK], kid: str) -> PyJWK | None:
        return PyJWKClient.match_kid(signing_keys, kid)

    async def close(self) -> None:
        """Close the client and release a client-owned transport."""
        if self._close_task is None:
            self._close_task = asyncio.create_task(self._close())
        await self._close_task

    async def _close(self) -> None:
        self._closed = True
        async with self._get_fetch_lock():
            task = self._fetch_task
            if task is not None and not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

        if self._owns_transport:
            aclose = getattr(self._transport, "aclose", None)
            if aclose is not None:
                await aclose()

    async def aclose(self) -> None:
        await self.close()

    async def __aenter__(self) -> AsyncPyJWKClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: Any,
    ) -> None:
        await self.close()
