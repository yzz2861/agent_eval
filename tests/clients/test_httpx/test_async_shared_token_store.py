import asyncio
import time
from unittest import mock

import pytest

from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.integrations.httpx_client._compat import httpx2
from authlib.oauth2.token_store import SQLiteSharedTokenStore
from authlib.oauth2.token_store import TokenPersistenceError

TOKEN_ENDPOINT = "https://provider.test/token"


@pytest.fixture
def expired_token():
    return {
        "token_type": "Bearer",
        "access_token": "old-access",
        "refresh_token": "refresh-1",
        "expires_at": int(time.time()) - 10,
    }


@pytest.fixture
def fresh_token():
    return {
        "token_type": "Bearer",
        "access_token": "new-access",
        "refresh_token": "refresh-2",
        "expires_at": int(time.time()) + 3600,
    }


@pytest.fixture
def store(tmp_path, expired_token):
    store = SQLiteSharedTokenStore(str(tmp_path / "tokens.db"))
    store.initialize(expired_token)
    yield store
    store.close()


def refresh_handler(payload, calls, delay=0):
    async def handler(request):
        calls.append(1)
        if delay:
            await asyncio.sleep(delay)
        return httpx2.Response(200, json=payload)

    return handler


def make_client(store, token, handler, **kwargs):
    kwargs.setdefault("token_store_poll_interval", 0.05)
    return AsyncOAuth2Client(
        "foo",
        token=dict(token),
        token_endpoint=TOKEN_ENDPOINT,
        token_store=store,
        transport=httpx2.MockTransport(handler),
        **kwargs,
    )


async def test_two_async_clients_share_single_refresh(
    store, expired_token, fresh_token
):
    calls = []
    handler = refresh_handler(fresh_token, calls, delay=0.2)
    client1 = make_client(store, expired_token, handler)
    client2 = make_client(store, expired_token, handler)

    async with client1, client2:
        await asyncio.gather(
            client1.ensure_active_token(client1.token),
            client2.ensure_active_token(client2.token),
        )

    # exactly one instance performed the HTTP refresh
    assert len(calls) == 1
    # both instances converge on the new token
    assert client1.token["access_token"] == "new-access"
    assert client2.token["access_token"] == "new-access"
    record = store.read()
    assert record.version == 2
    assert record.token["refresh_token"] == "refresh-2"


async def test_stale_async_instance_adopts_store_token(
    store, expired_token, fresh_token
):
    lease = store.acquire_refresh_lease(1, ttl=5)
    assert store.save_token(fresh_token, expected_version=1, lease=lease)

    async def fail_handler(request):  # pragma: no cover
        raise AssertionError("stale instance must not refresh")

    client = make_client(store, expired_token, fail_handler)
    async with client:
        await client.ensure_active_token(client.token)
    assert client.token["access_token"] == "new-access"
    assert client.token["refresh_token"] == "refresh-2"


async def test_save_conflict_after_refresh_raises_uncertain(
    store, expired_token, fresh_token
):
    calls = []
    handler = refresh_handler(fresh_token, calls)
    client = make_client(store, expired_token, handler)

    async with client:
        with mock.patch.object(store, "save_token", return_value=False):
            with pytest.raises(TokenPersistenceError):
                await client.ensure_active_token(client.token)

    # the refresh request succeeded once and was not retried
    assert len(calls) == 1


async def test_async_coordinator_crash_lease_takeover(
    store, expired_token, fresh_token
):
    # a coordinator acquired the lease and crashed without saving
    lease = store.acquire_refresh_lease(1, ttl=0.2)
    assert lease is not None

    calls = []
    handler = refresh_handler(fresh_token, calls)
    client = make_client(store, expired_token, handler)
    async with client:
        await client.ensure_active_token(client.token)

    assert len(calls) == 1
    assert client.token["access_token"] == "new-access"
    assert store.read().version == 2
