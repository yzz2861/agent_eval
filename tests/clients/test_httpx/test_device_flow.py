import pytest

try:
    import httpx2
except ImportError:  # pragma: no cover
    import httpx as httpx2

from authlib.integrations.httpx_client import OAuth2Client
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

TOKEN_URL = "https://provider.test/token"


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
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
    client = OAuth2Client("foo", transport=transport, **kwargs)
    return client, requests_made


def test_fetch_device_authorization():
    client, made = make_client([(200, DEVICE_AUTHORIZATION)])
    with client:
        data = client.fetch_device_authorization(
            "https://provider.test/device_authorization"
        )
    assert data["user_code"] == "WDJB-MJHT"
    assert data["verification_uri"] == "https://provider.test/device"
    assert "client_id=foo" in made[0].content.decode()


def test_poll_device_token_success_and_slow_down():
    client, made = make_client(
        [
            (400, {"error": "slow_down"}),
            (400, {"error": "authorization_pending"}),
            (200, TOKEN),
        ]
    )
    clock = FakeClock()
    with client:
        token = client.poll_device_token(
            DEVICE_AUTHORIZATION, url=TOKEN_URL, clock=clock, sleep=clock.sleep
        )
    assert token["access_token"] == "a"
    assert clock.sleeps == [5, 10, 10]
    assert len(made) == 3


def test_poll_device_token_access_denied():
    client, made = make_client([(400, {"error": "access_denied"})])
    clock = FakeClock()
    with client:
        with pytest.raises(OAuthError) as exc_info:
            client.poll_device_token(
                DEVICE_AUTHORIZATION, url=TOKEN_URL, clock=clock, sleep=clock.sleep
            )
    assert exc_info.value.error == "access_denied"
    assert len(made) == 1
