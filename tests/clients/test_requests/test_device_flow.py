import threading
from unittest import mock

import pytest
import requests

from authlib.integrations.requests_client import OAuth2Session
from authlib.integrations.requests_client import OAuthError
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


def json_response(payload):
    resp = mock.MagicMock()
    resp.status_code = 200
    resp.json = lambda: payload
    return resp


def mock_sequence(payloads):
    # A fake "send" returning the given JSON payloads in order. The
    # last payload is repeated when the sequence is exhausted.
    calls = []

    def fake_send(r, **kwargs):
        calls.append(r)
        payload = payloads[min(len(calls), len(payloads)) - 1]
        return json_response(payload)

    return fake_send, calls


def test_fetch_device_authorization():
    session = OAuth2Session("foo", scope="profile")

    def fake_send(r, **kwargs):
        assert "client_id=foo" in r.body
        assert "scope=profile" in r.body
        return json_response(DEVICE_INFO)

    session.send = fake_send
    data = session.fetch_device_authorization("https://provider.test/device")
    assert data["device_code"] == DEVICE_INFO["device_code"]
    assert data["user_code"] == "WDJB-MJHT"
    assert data["verification_uri"] == "https://provider.test/activate"


def test_fetch_device_authorization_with_metadata_url():
    session = OAuth2Session(
        "foo", device_authorization_endpoint="https://provider.test/device"
    )
    session.send, calls = mock_sequence([DEVICE_INFO])
    data = session.fetch_device_authorization()
    assert data["user_code"] == "WDJB-MJHT"
    assert str(calls[0].url) == "https://provider.test/device"


def test_fetch_device_authorization_error():
    session = OAuth2Session("foo")
    session.send, _ = mock_sequence([{"error": "invalid_client"}])
    with pytest.raises(OAuthError) as exc_info:
        session.fetch_device_authorization("https://provider.test/device")
    assert exc_info.value.error == "invalid_client"


def test_poll_device_token_pending_then_success():
    session = OAuth2Session("foo")
    session.send, calls = mock_sequence(
        [
            {"error": "authorization_pending"},
            {"error": "authorization_pending"},
            TOKEN,
        ]
    )
    waits = []
    token = session.poll_device_token(DEVICE_INFO, TOKEN_URL, sleep=waits.append)
    assert token["access_token"] == "a"
    assert session.token["access_token"] == "a"
    assert waits == [5, 5]
    assert len(calls) == 3
    body = calls[0].body
    assert "device_code=GmRhmhcxhwAzkoEqiMEg" in body
    assert DEVICE_CODE_GRANT_TYPE.replace(":", "%3A") in body


def test_poll_device_token_accepts_device_code_string():
    session = OAuth2Session("foo")
    session.send, calls = mock_sequence([TOKEN])
    token = session.poll_device_token("GmRhmhcxhwAzkoEqiMEg", TOKEN_URL)
    assert token["access_token"] == "a"
    assert len(calls) == 1


def test_poll_device_token_slow_down():
    session = OAuth2Session("foo")
    session.send, _ = mock_sequence(
        [
            {"error": "authorization_pending"},
            {"error": "slow_down"},
            {"error": "slow_down"},
            TOKEN,
        ]
    )
    waits = []
    session.poll_device_token(DEVICE_INFO, TOKEN_URL, sleep=waits.append)
    # slow_down increases the interval by 5 seconds for all
    # subsequent requests
    assert waits == [5, 10, 15]


def test_poll_device_token_access_denied():
    session = OAuth2Session("foo")
    session.send, calls = mock_sequence([{"error": "access_denied"}])
    with pytest.raises(OAuthError) as exc_info:
        session.poll_device_token(DEVICE_INFO, TOKEN_URL, sleep=lambda s: None)
    assert exc_info.value.error == "access_denied"
    assert len(calls) == 1


def test_poll_device_token_expired_token():
    session = OAuth2Session("foo")
    session.send, calls = mock_sequence([{"error": "expired_token"}])
    with pytest.raises(OAuthError) as exc_info:
        session.poll_device_token(DEVICE_INFO, TOKEN_URL, sleep=lambda s: None)
    assert exc_info.value.error == "expired_token"
    assert len(calls) == 1


def test_poll_device_token_device_code_expires():
    session = OAuth2Session("foo")
    session.send, calls = mock_sequence([{"error": "authorization_pending"}])

    now = [0.0]

    def clock():
        return now[0]

    def sleep(seconds):
        now[0] += seconds

    info = dict(DEVICE_INFO, expires_in=10, interval=5)
    with pytest.raises(ExpiredTokenError):
        session.poll_device_token(info, TOKEN_URL, clock=clock, sleep=sleep)
    # polled at t=0 and t=5, then the device code expired at t=10
    assert len(calls) == 2


def test_poll_device_token_network_timeout_backoff():
    session = OAuth2Session("foo")
    calls = []

    def fake_send(r, **kwargs):
        calls.append(r)
        if len(calls) == 1:
            raise requests.exceptions.ConnectTimeout("boom")
        if len(calls) == 2:
            return json_response({"error": "authorization_pending"})
        return json_response(TOKEN)

    session.send = fake_send
    waits = []
    token = session.poll_device_token(DEVICE_INFO, TOKEN_URL, sleep=waits.append)
    assert token["access_token"] == "a"
    # the network timeout backoff (1s) is tracked separately from the
    # protocol polling interval (5s)
    assert waits == [1, 5]


def test_poll_device_token_consecutive_timeouts():
    session = OAuth2Session("foo")
    calls = []

    def fake_send(r, **kwargs):
        calls.append(r)
        if len(calls) <= 3:
            raise requests.exceptions.ReadTimeout("boom")
        return json_response(TOKEN)

    session.send = fake_send
    waits = []
    session.poll_device_token(DEVICE_INFO, TOKEN_URL, sleep=waits.append)
    # exponential backoff: 1, 2, 4
    assert waits == [1, 2, 4]


def test_poll_device_token_cancel_before_polling():
    session = OAuth2Session("foo")
    session.send, calls = mock_sequence([TOKEN])
    event = threading.Event()
    event.set()
    result = session.poll_device_token(
        DEVICE_INFO, TOKEN_URL, sleep=lambda s: None, cancel_event=event
    )
    assert result is None
    assert len(calls) == 0


def test_poll_device_token_cancel_stops_requests():
    session = OAuth2Session("foo")
    session.send, calls = mock_sequence([{"error": "authorization_pending"}])
    event = threading.Event()

    def sleep(seconds):
        event.set()

    result = session.poll_device_token(
        DEVICE_INFO, TOKEN_URL, sleep=sleep, cancel_event=event
    )
    assert result is None
    # no further request is sent once cancelled
    assert len(calls) == 1
