import asyncio

import pytest

try:
    import httpx2
except ImportError:  # pragma: no cover
    import httpx as httpx2

from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.integrations.httpx_client import OAuthError

DEVICE_AUTHORIZATION = {
    "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
    "user_code": "WDJB-MJHT",
    "verification_uri": "https://provider.test/device",
    "verification_uri_complete": "https://provider.test/device?user_code=WDJB-MJHT",
    "expires_in": 1800,
    "interval": 5,
}

TOKEN = {
    "token_type": "Bearer",
    "access_token": "a",
    "refresh_token": "b",
    "expires_in": 3600,
}

DEVICE_AUTHORIZATION_URL = "https://provider.test/device_authorization"
TOKEN_URL = "https://provider.test/token"


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def __call__(self):
        return self.now

    async def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def make_client(queue, **kwargs):
    requests_made = []

    def handler(request):
        requests_made.append(request)
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        status_code, payload = item
        return httpx2.Response(status_code, json=payload)

    transport = httpx2.MockTransport(handler)
    client = AsyncOAuth2Client("foo", transport=transport, **kwargs)
    return client, requests_made


def pending():
    return 400, {"error": "authorization_pending"}


@pytest.mark.asyncio
async def test_fetch_device_authorization():
    client, made = make_client([(200, DEVICE_AUTHORIZATION)], scope="profile")
    async with client:
        data = await client.fetch_device_authorization(DEVICE_AUTHORIZATION_URL)
    assert data["device_code"] == DEVICE_AUTHORIZATION["device_code"]
    assert data["user_code"] == "WDJB-MJHT"
    assert data["verification_uri"] == "https://provider.test/device"
    assert len(made) == 1
    body = made[0].content.decode()
    assert "client_id=foo" in body
    assert "scope=profile" in body


@pytest.mark.asyncio
async def test_poll_device_token_success():
    client, made = make_client([pending(), pending(), (200, TOKEN)])
    clock = FakeClock()
    async with client:
        token = await client.poll_device_token(
            DEVICE_AUTHORIZATION, url=TOKEN_URL, clock=clock, sleep=clock.sleep
        )
    assert token["access_token"] == "a"
    assert client.token["access_token"] == "a"
    assert clock.sleeps == [5, 5, 5]
    assert len(made) == 3
    body = made[0].content.decode()
    assert "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code" in body
    assert "device_code=" in body


@pytest.mark.asyncio
async def test_poll_device_token_slow_down():
    client, made = make_client([(400, {"error": "slow_down"}), pending(), (200, TOKEN)])
    clock = FakeClock()
    async with client:
        await client.poll_device_token(
            DEVICE_AUTHORIZATION, url=TOKEN_URL, clock=clock, sleep=clock.sleep
        )
    assert clock.sleeps == [5, 10, 10]
    assert len(made) == 3


@pytest.mark.asyncio
async def test_poll_device_token_access_denied():
    client, made = make_client([pending(), (400, {"error": "access_denied"})])
    clock = FakeClock()
    async with client:
        with pytest.raises(OAuthError) as exc_info:
            await client.poll_device_token(
                DEVICE_AUTHORIZATION, url=TOKEN_URL, clock=clock, sleep=clock.sleep
            )
    assert exc_info.value.error == "access_denied"
    assert len(made) == 2


@pytest.mark.asyncio
async def test_poll_device_token_expired_token_from_server():
    client, made = make_client([(400, {"error": "expired_token"})])
    clock = FakeClock()
    async with client:
        with pytest.raises(OAuthError) as exc_info:
            await client.poll_device_token(
                DEVICE_AUTHORIZATION, url=TOKEN_URL, clock=clock, sleep=clock.sleep
            )
    assert exc_info.value.error == "expired_token"
    assert len(made) == 1


@pytest.mark.asyncio
async def test_poll_device_token_expires_locally():
    device_authorization = dict(DEVICE_AUTHORIZATION, expires_in=12)
    client, made = make_client([pending(), pending(), pending()])
    clock = FakeClock()
    async with client:
        with pytest.raises(OAuthError) as exc_info:
            await client.poll_device_token(
                device_authorization, url=TOKEN_URL, clock=clock, sleep=clock.sleep
            )
    assert exc_info.value.error == "expired_token"
    assert clock.sleeps == [5, 5, 2]
    assert len(made) == 2


@pytest.mark.asyncio
async def test_poll_device_token_network_timeout_backoff():
    timeout = httpx2.ConnectTimeout("timeout")
    client, made = make_client([timeout, timeout, (200, TOKEN)])
    clock = FakeClock()
    async with client:
        token = await client.poll_device_token(
            DEVICE_AUTHORIZATION, url=TOKEN_URL, clock=clock, sleep=clock.sleep
        )
    assert token["access_token"] == "a"
    assert clock.sleeps == [5, 1.0, 2.0]
    assert len(made) == 3


@pytest.mark.asyncio
async def test_poll_device_token_cancellation_stops_polling():
    client, made = make_client([(200, TOKEN)])
    started = asyncio.Event()

    async def sleep(seconds):
        started.set()
        await asyncio.sleep(10)

    async with client:
        task = asyncio.create_task(
            client.poll_device_token(DEVICE_AUTHORIZATION, url=TOKEN_URL, sleep=sleep)
        )
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    # no request is sent after the wait was cancelled
    assert len(made) == 0
