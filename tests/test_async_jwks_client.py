from __future__ import annotations

import asyncio
import copy
import json
from base64 import urlsafe_b64encode
from collections.abc import Awaitable, Callable
from ssl import SSLContext
from typing import Any

import pytest

from jwt import AsyncIOJWKSTransport, AsyncPyJWKClient
from jwt.api_jwk import PyJWKSet
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError, PyJWKSetError

URL = "https://example.test/.well-known/jwks.json"


def hmac_key(kid: str) -> dict[str, Any]:
    return {
        "kty": "oct",
        "kid": kid,
        "use": "sig",
        "alg": "HS256",
        "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg",
    }


KEY_SET_ONE = {"keys": [hmac_key("key-one")]}
KEY_SET_TWO = {"keys": [hmac_key("key-one"), hmac_key("key-two")]}
NO_MATCHING_KEY_SET = {"keys": [hmac_key("other-key")]}


class ScriptedAsyncTransport:
    def __init__(
        self,
        payloads: list[dict[str, Any]] | None = None,
        failure: BaseException | None = None,
    ) -> None:
        self.payloads = payloads or []
        self.failure = failure
        self.calls: list[tuple[str, dict[str, Any], float, SSLContext | None]] = []
        self.closed = 0

    async def fetch_data(
        self,
        uri: str,
        headers: dict[str, Any],
        timeout: float,
        ssl_context: SSLContext | None,
    ) -> dict[str, Any]:
        self.calls.append((uri, headers, timeout, ssl_context))
        if self.failure is not None:
            raise self.failure
        return self.payloads.pop(0)

    async def aclose(self) -> None:
        self.closed += 1


class GatedRefreshTransport(ScriptedAsyncTransport):
    def __init__(
        self,
        first_payload: dict[str, Any],
        refresh_payload: dict[str, Any] | None = None,
        failure: BaseException | None = None,
    ) -> None:
        super().__init__([first_payload], failure)
        self.refresh_payload = refresh_payload or copy.deepcopy(first_payload)
        self.refresh_failure = failure
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def fetch_data(
        self,
        uri: str,
        headers: dict[str, Any],
        timeout: float,
        ssl_context: SSLContext | None,
    ) -> dict[str, Any]:
        self.calls.append((uri, headers, timeout, ssl_context))
        if len(self.calls) == 1:
            return self.payloads.pop(0)

        self.started.set()
        await self.release.wait()
        if self.refresh_failure is not None:
            raise self.refresh_failure
        return self.refresh_payload


class TrackingDefaultTransport(AsyncIOJWKSTransport):
    def __init__(self) -> None:
        self.closed = 0

    async def aclose(self) -> None:
        self.closed += 1


def run(coro: Awaitable[Any]) -> Any:
    return asyncio.run(coro)


def token_with_kid(kid: str) -> str:
    def encode(payload: dict[str, Any]) -> str:
        raw = json.dumps(payload, separators=(",", ":")).encode()
        return urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{encode({'alg': 'HS256', 'kid': kid})}.{encode({})}."


async def fetch_jwk_set() -> None:
    transport = ScriptedAsyncTransport([copy.deepcopy(KEY_SET_ONE)])
    client = AsyncPyJWKClient(
        URL,
        headers={"Authorization": "Bearer token"},
        timeout=7,
        transport=transport,  # type: ignore[arg-type]
    )

    jwk_set = await client.get_jwk_set()

    assert len(jwk_set.keys) == 1
    assert transport.calls == [(URL, {"Authorization": "Bearer token"}, 7, None)]


def test_async_fetch_jwk_set() -> None:
    run(fetch_jwk_set())


async def signing_key_from_jwt() -> None:
    transport = ScriptedAsyncTransport([copy.deepcopy(KEY_SET_ONE)])
    client = AsyncPyJWKClient(URL, transport=transport)  # type: ignore[arg-type]

    key = await client.get_signing_key_from_jwt(token_with_kid("key-one"))

    assert key.key_id == "key-one"


def test_async_signing_key_from_jwt() -> None:
    run(signing_key_from_jwt())


async def signing_key_cache_avoids_fetch() -> None:
    transport = ScriptedAsyncTransport(
        [copy.deepcopy(KEY_SET_TWO), copy.deepcopy(KEY_SET_TWO)]
    )
    client = AsyncPyJWKClient(
        URL,
        cache_keys=True,
        transport=transport,  # type: ignore[arg-type]
    )

    first = await client.get_signing_key("key-two")
    second = await client.get_signing_key("key-two")

    assert first is second
    assert len(transport.calls) == 1


def test_async_signing_key_cache_avoids_fetch() -> None:
    run(signing_key_cache_avoids_fetch())


async def concurrent_misses_share_refresh() -> None:
    transport = GatedRefreshTransport(
        copy.deepcopy(NO_MATCHING_KEY_SET), copy.deepcopy(KEY_SET_ONE)
    )
    client = AsyncPyJWKClient(URL, transport=transport)  # type: ignore[arg-type]
    await client.get_jwk_set()
    client._last_successful_fetch = -100

    tasks = [asyncio.ensure_future(client.get_signing_key("key-one")) for _ in range(3)]
    await transport.started.wait()
    await asyncio.sleep(0)
    transport.release.set()
    keys = await asyncio.gather(*tasks)

    assert [key.key_id for key in keys] == ["key-one"] * 3
    assert len(transport.calls) == 2


def test_async_concurrent_misses_share_refresh() -> None:
    run(concurrent_misses_share_refresh())


async def concurrent_initial_fetch_is_shared() -> None:
    transport = ScriptedAsyncTransport([copy.deepcopy(KEY_SET_ONE)])
    client = AsyncPyJWKClient(URL, transport=transport)  # type: ignore[arg-type]

    payload, jwk_set = await asyncio.gather(client.fetch_data(), client.get_jwk_set())

    assert payload == copy.deepcopy(KEY_SET_ONE)
    assert len(jwk_set.keys) == 1
    assert len(transport.calls) == 1


def test_async_concurrent_initial_fetch_is_shared() -> None:
    run(concurrent_initial_fetch_is_shared())


async def cancelling_one_waiter_keeps_refresh_running() -> None:
    transport = GatedRefreshTransport(
        copy.deepcopy(NO_MATCHING_KEY_SET), copy.deepcopy(KEY_SET_ONE)
    )
    client = AsyncPyJWKClient(URL, transport=transport)  # type: ignore[arg-type]
    await client.get_jwk_set()
    client._last_successful_fetch = -100

    cancelled = asyncio.ensure_future(client.get_signing_key("key-one"))
    await transport.started.wait()
    waiter = asyncio.ensure_future(client.get_signing_key("key-one"))
    await asyncio.sleep(0)

    cancelled.cancel()
    with pytest.raises(asyncio.CancelledError):
        await cancelled
    assert not waiter.done()

    transport.release.set()
    key = await waiter

    assert key.key_id == "key-one"
    assert len(transport.calls) == 2


def test_async_cancelling_one_waiter_keeps_refresh_running() -> None:
    run(cancelling_one_waiter_keeps_refresh_running())


async def failed_refresh_is_shared_and_preserves_cache() -> None:
    failure = PyJWKClientConnectionError("network unavailable")
    transport = GatedRefreshTransport(
        copy.deepcopy(NO_MATCHING_KEY_SET), failure=failure
    )
    client = AsyncPyJWKClient(URL, transport=transport)  # type: ignore[arg-type]
    cached = await client.get_jwk_set()
    client._last_successful_fetch = -100

    tasks = [asyncio.ensure_future(client.get_signing_key("missing")) for _ in range(2)]
    await transport.started.wait()
    await asyncio.sleep(0)
    transport.release.set()
    results = await asyncio.gather(*tasks, return_exceptions=True)

    assert results == [failure, failure]
    assert client.jwk_set_cache is not None
    assert client.jwk_set_cache.get() is cached
    assert client._inflight_fetch is None
    assert len(transport.calls) == 2


def test_async_failed_refresh_is_shared_and_preserves_cache() -> None:
    run(failed_refresh_is_shared_and_preserves_cache())


async def invalid_payload_is_not_cached() -> None:
    transport = ScriptedAsyncTransport()
    transport.payloads = [{"keys": []}]  # type: ignore[assignment]
    client = AsyncPyJWKClient(URL, transport=transport)  # type: ignore[arg-type]

    with pytest.raises(PyJWKSetError):
        await client.get_jwk_set()

    assert client.jwk_set_cache is not None
    assert client.jwk_set_cache.get() is None


def test_async_invalid_payload_is_not_cached() -> None:
    run(invalid_payload_is_not_cached())


async def fetch_data_rejects_non_object() -> None:
    transport = ScriptedAsyncTransport()
    transport.payloads = [["not-object"]]  # type: ignore[assignment]
    client = AsyncPyJWKClient(URL, transport=transport)  # type: ignore[arg-type]

    with pytest.raises(PyJWKClientError, match="JSON object"):
        await client.fetch_data()


def test_async_fetch_data_rejects_non_object() -> None:
    run(fetch_data_rejects_non_object())


async def unknown_kid_respects_cooldown() -> None:
    transport = ScriptedAsyncTransport([copy.deepcopy(NO_MATCHING_KEY_SET)])
    client = AsyncPyJWKClient(URL, transport=transport)  # type: ignore[arg-type]

    for _ in range(2):
        with pytest.raises(PyJWKClientError, match="matches"):
            await client.get_signing_key("missing")

    assert len(transport.calls) == 1

    client._last_successful_fetch = -100
    transport.payloads.append(copy.deepcopy(KEY_SET_ONE))
    key = await client.get_signing_key("key-one")

    assert key.key_id == "key-one"
    assert len(transport.calls) == 2


def test_async_unknown_kid_respects_cooldown() -> None:
    run(unknown_kid_respects_cooldown())


async def cache_disabled_bypasses_cooldown() -> None:
    transport = ScriptedAsyncTransport(
        [copy.deepcopy(NO_MATCHING_KEY_SET) for _ in range(4)]
    )
    client = AsyncPyJWKClient(
        URL,
        cache_jwk_set=False,
        transport=transport,  # type: ignore[arg-type]
    )

    for _ in range(2):
        with pytest.raises(PyJWKClientError, match="matches"):
            await client.get_signing_key("missing")

    assert len(transport.calls) == 4


def test_async_cache_disabled_bypasses_cooldown() -> None:
    run(cache_disabled_bypasses_cooldown())


async def closing_rejects_new_requests_and_preserves_external_transport() -> None:
    transport = ScriptedAsyncTransport([copy.deepcopy(KEY_SET_ONE)])
    client = AsyncPyJWKClient(URL, transport=transport)  # type: ignore[arg-type]
    await client.get_jwk_set()

    await client.aclose()
    await client.aclose()

    with pytest.raises(PyJWKClientError, match="closed"):
        await client.get_jwk_set()
    assert transport.closed == 0


def test_async_closing_rejects_new_requests_and_preserves_external_transport() -> None:
    run(closing_rejects_new_requests_and_preserves_external_transport())


async def closing_owned_transport_and_ending_waiters() -> None:
    transport = GatedRefreshTransport(
        copy.deepcopy(NO_MATCHING_KEY_SET), copy.deepcopy(KEY_SET_ONE)
    )
    client = AsyncPyJWKClient(URL)
    client.transport = transport  # type: ignore[assignment]
    client._owns_transport = True
    try:
        await client.get_jwk_set()
        client._last_successful_fetch = -100

        waiters = [
            asyncio.ensure_future(client.get_signing_key("key-one")) for _ in range(2)
        ]
        await transport.started.wait()
        await asyncio.sleep(0)
        await client.aclose()
        results = await asyncio.gather(*waiters, return_exceptions=True)

        assert all(isinstance(result, PyJWKClientError) for result in results)
        assert all("closed" in str(result) for result in results)
        assert transport.closed == 1
        assert client.transport is None
    finally:
        transport.release.set()


def test_async_closing_owned_transport_and_ending_waiters() -> None:
    run(closing_owned_transport_and_ending_waiters())


async def context_manager_closes_owned_transport() -> None:
    transport = TrackingDefaultTransport()
    client = AsyncPyJWKClient(URL)
    client.transport = transport  # type: ignore[assignment]

    async with client:
        jwk_set = PyJWKSet.from_dict(copy.deepcopy(KEY_SET_ONE))
        assert client.jwk_set_cache is not None
        client.jwk_set_cache.put(jwk_set)
        assert await client.get_jwk_set() is jwk_set

    assert transport.closed == 1
    with pytest.raises(PyJWKClientError, match="closed"):
        await client.get_jwk_set()


def test_async_context_manager_closes_owned_transport() -> None:
    run(context_manager_closes_owned_transport())


def test_invalid_uri_scheme() -> None:
    with pytest.raises(PyJWKClientError, match="Invalid JWKS URI scheme"):
        AsyncPyJWKClient("file:///etc/passwd")


def test_invalid_timeout() -> None:
    with pytest.raises(PyJWKClientError, match="Timeout must be"):
        AsyncPyJWKClient(URL, timeout=-1)


def test_default_transport_is_async_transport() -> None:
    transport = AsyncIOJWKSTransport()
    close: Callable[[], Awaitable[None]] = transport.aclose
    assert asyncio.iscoroutinefunction(close)
