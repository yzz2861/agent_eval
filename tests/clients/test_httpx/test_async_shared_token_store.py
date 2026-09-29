import asyncio
import json
import time
import uuid

import pytest

from authlib.common.urls import url_decode
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.integrations.httpx_client._compat import httpx2
from authlib.oauth2.token_store import AsyncSharedTokenStore
from authlib.oauth2.token_store import StoredToken
from authlib.oauth2.token_store import TokenPersistenceUncertainError


class AsyncMemoryTokenStore(AsyncSharedTokenStore):
    def __init__(self):
        self._stored = None
        self._lease = None  # (lease_id, owner, expires_at)

    async def read(self):
        return self._stored

    async def acquire_lease(self, owner, ttl):
        now = time.monotonic()
        if self._lease is not None and self._lease[2] > now:
            return None
        lease_id = uuid.uuid4().hex
        self._lease = (lease_id, owner, now + ttl)
        return lease_id

    async def release_lease(self, lease_id):
        if self._lease is not None and self._lease[0] == lease_id:
            self._lease = None

    async def wait_for_update(self, version, timeout):
        deadline = time.monotonic() + timeout
        while True:
            current = self._stored.version if self._stored else None
            if current != version:
                return self._stored
            if time.monotonic() >= deadline:
                return None
            await asyncio.sleep(0.01)

    async def save(self, token, expected_version):
        current = self._stored.version if self._stored else None
        if current != expected_version:
            return False
        self._stored = StoredToken(dict(token), (current or 0) + 1)
        return True


class RotatingTokenApp:
    """ASGI token endpoint: rotates the refresh token on every refresh."""

    def __init__(self):
        self.refresh_count = 0
        self.current_refresh_token = "rt-0"
        self.received_refresh_tokens = []

    async def __call__(self, scope, receive, send):
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        params = dict(url_decode(body.decode()))
        self.received_refresh_tokens.append(params.get("refresh_token"))
        if params.get("refresh_token") == self.current_refresh_token:
            self.refresh_count += 1
            count = self.refresh_count
            self.current_refresh_token = f"rt-{count}"
            payload = {
                "access_token": f"at-{count}",
                "refresh_token": f"rt-{count}",
                "token_type": "Bearer",
                "expires_in": 3600,
            }
            status = 200
        else:
            payload = {"error": "invalid_grant"}
            status = 400
        data = json.dumps(payload).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(data)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": data})


@pytest.fixture
def expired_token():
    return {
        "token_type": "Bearer",
        "access_token": "at-0",
        "refresh_token": "rt-0",
        "expires_at": 100,
    }


@pytest.fixture
def store(expired_token):
    store = AsyncMemoryTokenStore()
    assert store._sync_save(expired_token, None)
    return store


@pytest.fixture
def app():
    return RotatingTokenApp()


def _sync_save(self, token, expected_version):
    current = self._stored.version if self._stored else None
    if current != expected_version:
        return False
    self._stored = StoredToken(dict(token), (current or 0) + 1)
    return True


AsyncMemoryTokenStore._sync_save = _sync_save


def make_client(store, app, token, **kwargs):
    return AsyncOAuth2Client(
        "foo",
        token=dict(token),
        token_endpoint="https://provider.test/token",
        token_store=store,
        transport=httpx2.ASGITransport(app),
        **kwargs,
    )


async def test_two_clients_share_one_refresh(store, app, expired_token):
    async with (
        make_client(store, app, expired_token) as client1,
        make_client(store, app, expired_token) as client2,
    ):
        await asyncio.gather(
            client1.ensure_active_token(client1.token),
            client2.ensure_active_token(client2.token),
        )

    assert app.refresh_count == 1
    assert app.received_refresh_tokens == ["rt-0"]
    for client in (client1, client2):
        assert client.token["access_token"] == "at-1"
        assert client.token["refresh_token"] == "rt-1"
    stored = await store.read()
    assert stored.token["access_token"] == "at-1"
    assert stored.version == 2


async def test_lagging_client_adopts_stored_token(store, app, expired_token):
    fresh_token = {
        "token_type": "Bearer",
        "access_token": "at-9",
        "refresh_token": "rt-9",
        "expires_at": int(time.time()) + 3600,
    }
    assert await store.save(fresh_token, 1)

    async with make_client(store, app, expired_token) as client:
        await client.ensure_active_token(client.token)

    assert app.refresh_count == 0
    assert app.received_refresh_tokens == []
    assert client.token["access_token"] == "at-9"
    assert client.token["refresh_token"] == "rt-9"


async def test_update_token_called_with_store(store, app, expired_token):
    calls = []

    async def update_token(token, refresh_token=None, **kwargs):
        calls.append((token, refresh_token))

    async with make_client(
        store, app, expired_token, update_token=update_token
    ) as client:
        await client.ensure_active_token(client.token)

    assert len(calls) == 1
    assert calls[0][0]["access_token"] == "at-1"
    # same contract as the legacy flow: the previous refresh token
    assert calls[0][1] == "rt-0"


async def test_persistence_failure_reports_uncertain_state(store, app, expired_token):
    class FailingStore(AsyncMemoryTokenStore):
        async def save(self, token, expected_version):
            raise OSError("disk full")

    failing_store = FailingStore()
    assert failing_store._sync_save(expired_token, None)

    async with make_client(failing_store, app, expired_token) as client:
        with pytest.raises(TokenPersistenceUncertainError) as exc_info:
            await client.ensure_active_token(client.token)

    # the refresh succeeded exactly once and was not retried
    assert app.refresh_count == 1
    assert app.received_refresh_tokens == ["rt-0"]
    # the new token is available for manual recovery
    assert exc_info.value.token["access_token"] == "at-1"
    assert exc_info.value.expected_version == 1
    assert client.token["access_token"] == "at-1"


async def test_cas_conflict_adopts_winner_token(store, app, expired_token):
    winner_token = {
        "token_type": "Bearer",
        "access_token": "at-winner",
        "refresh_token": "rt-winner",
        "expires_at": int(time.time()) + 3600,
    }

    class LosingStore(AsyncMemoryTokenStore):
        async def save(self, token, expected_version):
            # another instance won the race and persisted first
            self._stored = StoredToken(dict(winner_token), expected_version + 1)
            return False

    losing_store = LosingStore()
    assert losing_store._sync_save(expired_token, None)

    async with make_client(losing_store, app, expired_token) as client:
        await client.ensure_active_token(client.token)

    assert app.refresh_count == 1
    assert client.token["access_token"] == "at-winner"
    assert client.token["refresh_token"] == "rt-winner"


async def test_lease_expiry_recovers_from_crashed_coordinator(
    store, app, expired_token
):
    # a crashed coordinator never releases its lease
    assert await store.acquire_lease("crashed-coordinator", ttl=0.1) is not None

    async with make_client(
        store,
        app,
        expired_token,
        token_store_lease_ttl=0.1,
        token_store_wait_timeout=0.2,
    ) as client:
        await client.ensure_active_token(client.token)

    assert app.refresh_count == 1
    assert client.token["access_token"] == "at-1"
    stored = await store.read()
    assert stored.token["access_token"] == "at-1"


async def test_store_uses_freshest_refresh_token(store, app, expired_token):
    # the client's own token is older than the store's: the request must
    # use the store's refresh token, not the stale local one
    stale_token = dict(expired_token, refresh_token="rt-stale")
    async with make_client(store, app, stale_token) as client:
        await client.ensure_active_token(client.token)

    assert app.received_refresh_tokens == ["rt-0"]
    assert client.token["refresh_token"] == "rt-1"
