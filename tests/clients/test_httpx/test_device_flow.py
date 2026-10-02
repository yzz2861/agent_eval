import asyncio
import json

import pytest

from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.integrations.httpx_client import OAuthError
from authlib.integrations.httpx_client._compat import httpx2
from authlib.oauth2.rfc8628 import DEVICE_CODE_GRANT_TYPE
from authlib.oauth2.rfc8628 import ExpiredTokenError

DEVICE_INFO = {
    "device_code": "GmRhmhcxhwAzkoEqiMEg",
    "user_code": "WDJB-MJHT",
    "verification_uri": "https://provider.test/activate",
    "expires_in": 1800,
    "interval": 5,
}

TOKEN = {
    "token_type": "Bearer",
    "access_token": "a",
    "expires_in": 3600,
}

TOKEN_URL = "https://provider.test/token"


def make_app(payloads, calls):
    # A minimal ASGI app returning the given JSON payloads in order.
    # The last payload is repeated when the sequence is exhausted.
    # An exception payload is raised to simulate a transport error.
    async def app(scope, receive, send):
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        calls.append(body.decode())
        payload = payloads[min(len(calls), len(payloads)) - 1]
        if isinstance(payload, Exception):
            raise payload
        data = json.dumps(payload).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": data})

    return app


def make_client(payloads, calls=None, **kwargs):
    if calls is None:
        calls = []
    transport = httpx2.ASGITransport(make_app(payloads, calls))
    client = AsyncOAuth2Client("foo", transport=transport, **kwargs)
    return client, calls


class SleepRecorder:
    def __init__(self):
        self.waits = []

    async def __call__(self, seconds):
        self.waits.append(seconds)


@pytest.mark.asyncio
async def test_fetch_device_authorization():
    client, calls = make_client([DEVICE_INFO], scope="profile")
    async with client:
        data = await client.fetch_device_authorization("https://provider.test/device")
    assert data["device_code"] == DEVICE_INFO["device_code"]
    assert data["user_code"] == "WDJB-MJHT"
    assert data["verification_uri"] == "https://provider.test/activate"
    assert "client_id=foo" in calls[0]
    assert "scope=profile" in calls[0]


@pytest.mark.asyncio
async def test_fetch_device_authorization_error():
    client, _ = make_client([{"error": "invalid_client"}])
    async with client:
        with pytest.raises(OAuthError) as exc_info:
            await client.fetch_device_authorization("https://provider.test/device")
    assert exc_info.value.error == "invalid_client"


@pytest.mark.asyncio
async def test_poll_device_token_pending_then_success():
    client, calls = make_client(
        [
            {"error": "authorization_pending"},
            {"error": "authorization_pending"},
            TOKEN,
        ]
    )
    sleep = SleepRecorder()
    async with client:
        token = await client.poll_device_token(DEVICE_INFO, TOKEN_URL, sleep=sleep)
    assert token["access_token"] == "a"
    assert client.token["access_token"] == "a"
    assert sleep.waits == [5, 5]
    assert len(calls) == 3
    assert "device_code=GmRhmhcxhwAzkoEqiMEg" in calls[0]
    assert DEVICE_CODE_GRANT_TYPE.replace(":", "%3A") in calls[0]


@pytest.mark.asyncio
async def test_poll_device_token_slow_down():
    client, _ = make_client(
        [
            {"error": "authorization_pending"},
            {"error": "slow_down"},
            {"error": "slow_down"},
            TOKEN,
        ]
    )
    sleep = SleepRecorder()
    async with client:
        await client.poll_device_token(DEVICE_INFO, TOKEN_URL, sleep=sleep)
    # slow_down increases the interval by 5 seconds for all
    # subsequent requests
    assert sleep.waits == [5, 10, 15]


@pytest.mark.asyncio
async def test_poll_device_token_access_denied():
    client, calls = make_client([{"error": "access_denied"}])
    async with client:
        with pytest.raises(OAuthError) as exc_info:
            await client.poll_device_token(
                DEVICE_INFO, TOKEN_URL, sleep=SleepRecorder()
            )
    assert exc_info.value.error == "access_denied"
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_poll_device_token_expired_token():
    client, calls = make_client([{"error": "expired_token"}])
    async with client:
        with pytest.raises(OAuthError) as exc_info:
            await client.poll_device_token(
                DEVICE_INFO, TOKEN_URL, sleep=SleepRecorder()
            )
    assert exc_info.value.error == "expired_token"
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_poll_device_token_device_code_expires():
    client, calls = make_client([{"error": "authorization_pending"}])

    now = [0.0]

    def clock():
        return now[0]

    class Sleep:
        async def __call__(self, seconds):
            now[0] += seconds

    info = dict(DEVICE_INFO, expires_in=10, interval=5)
    async with client:
        with pytest.raises(ExpiredTokenError):
            await client.poll_device_token(info, TOKEN_URL, clock=clock, sleep=Sleep())
    # polled at t=0 and t=5, then the device code expired at t=10
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_poll_device_token_network_timeout_backoff():
    client, _ = make_client(
        [
            httpx2.ConnectTimeout("boom"),
            {"error": "authorization_pending"},
            TOKEN,
        ]
    )
    sleep = SleepRecorder()
    async with client:
        token = await client.poll_device_token(DEVICE_INFO, TOKEN_URL, sleep=sleep)
    assert token["access_token"] == "a"
    # the network timeout backoff (1s) is tracked separately from the
    # protocol polling interval (5s)
    assert sleep.waits == [1, 5]


@pytest.mark.asyncio
async def test_poll_device_token_cancel_stops_requests():
    client, calls = make_client([{"error": "authorization_pending"}])
    event = asyncio.Event()

    class Sleep:
        async def __call__(self, seconds):
            event.set()

    async with client:
        result = await client.poll_device_token(
            DEVICE_INFO, TOKEN_URL, sleep=Sleep(), cancel_event=event
        )
    assert result is None
    # no further request is sent once cancelled
    assert len(calls) == 1
