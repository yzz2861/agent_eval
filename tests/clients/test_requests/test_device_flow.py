from unittest import mock

import pytest
from requests.exceptions import Timeout

from authlib.integrations.requests_client import OAuth2Session
from authlib.integrations.requests_client import OAuthError

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

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def make_session(queue, **kwargs):
    sess = OAuth2Session(client_id="foo", **kwargs)
    requests_made = []

    def fake_send(r, **send_kwargs):
        requests_made.append(r)
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        status_code, payload = item
        resp = mock_response(status_code, payload)
        return resp

    sess.send = fake_send
    return sess, requests_made


def mock_response(status_code, payload):
    resp = mock.MagicMock()
    resp.status_code = status_code
    resp.json = lambda: payload
    return resp


def pending():
    return 400, {"error": "authorization_pending"}


def test_fetch_device_authorization():
    sess, made = make_session([(200, DEVICE_AUTHORIZATION)], scope="profile")
    data = sess.fetch_device_authorization(DEVICE_AUTHORIZATION_URL)
    assert data["device_code"] == DEVICE_AUTHORIZATION["device_code"]
    assert data["user_code"] == "WDJB-MJHT"
    assert data["verification_uri"] == "https://provider.test/device"
    assert len(made) == 1
    assert "client_id=foo" in made[0].body
    assert "scope=profile" in made[0].body


def test_fetch_device_authorization_from_metadata():
    sess, made = make_session(
        [(200, DEVICE_AUTHORIZATION)],
        device_authorization_endpoint=DEVICE_AUTHORIZATION_URL,
    )
    data = sess.fetch_device_authorization()
    assert data["user_code"] == "WDJB-MJHT"
    assert made[0].url == DEVICE_AUTHORIZATION_URL


def test_fetch_device_authorization_missing_url():
    sess, _ = make_session([])
    with pytest.raises(ValueError):
        sess.fetch_device_authorization()


def test_fetch_device_authorization_error():
    sess, _ = make_session([(400, {"error": "invalid_client"})])
    with pytest.raises(OAuthError) as exc_info:
        sess.fetch_device_authorization(DEVICE_AUTHORIZATION_URL)
    assert exc_info.value.error == "invalid_client"


def test_poll_device_token_success():
    sess, made = make_session([pending(), pending(), (200, TOKEN)])
    clock = FakeClock()
    token = sess.poll_device_token(
        DEVICE_AUTHORIZATION, url=TOKEN_URL, clock=clock, sleep=clock.sleep
    )
    assert token["access_token"] == "a"
    assert sess.token["access_token"] == "a"
    assert clock.sleeps == [5, 5, 5]
    assert len(made) == 3
    body = made[0].body
    assert "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code" in body
    assert "device_code=" in body


def test_poll_device_token_with_device_code_string():
    sess, made = make_session([(200, TOKEN)])
    clock = FakeClock()
    token = sess.poll_device_token(
        "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
        url=TOKEN_URL,
        interval=1,
        expires_in=10,
        clock=clock,
        sleep=clock.sleep,
    )
    assert token["access_token"] == "a"
    assert clock.sleeps == [1]
    assert len(made) == 1


def test_poll_device_token_slow_down():
    sess, made = make_session([(400, {"error": "slow_down"}), pending(), (200, TOKEN)])
    clock = FakeClock()
    sess.poll_device_token(
        DEVICE_AUTHORIZATION, url=TOKEN_URL, clock=clock, sleep=clock.sleep
    )
    # slow_down increases the interval by 5 seconds for all later polls
    assert clock.sleeps == [5, 10, 10]
    assert len(made) == 3


def test_poll_device_token_access_denied():
    sess, made = make_session([pending(), (400, {"error": "access_denied"})])
    clock = FakeClock()
    with pytest.raises(OAuthError) as exc_info:
        sess.poll_device_token(
            DEVICE_AUTHORIZATION, url=TOKEN_URL, clock=clock, sleep=clock.sleep
        )
    assert exc_info.value.error == "access_denied"
    assert len(made) == 2


def test_poll_device_token_expired_token_from_server():
    sess, made = make_session([pending(), (400, {"error": "expired_token"})])
    clock = FakeClock()
    with pytest.raises(OAuthError) as exc_info:
        sess.poll_device_token(
            DEVICE_AUTHORIZATION, url=TOKEN_URL, clock=clock, sleep=clock.sleep
        )
    assert exc_info.value.error == "expired_token"
    assert len(made) == 2


def test_poll_device_token_expires_locally():
    device_authorization = dict(DEVICE_AUTHORIZATION, expires_in=12)
    sess, made = make_session([pending(), pending(), pending()])
    clock = FakeClock()
    with pytest.raises(OAuthError) as exc_info:
        sess.poll_device_token(
            device_authorization, url=TOKEN_URL, clock=clock, sleep=clock.sleep
        )
    assert exc_info.value.error == "expired_token"
    # the last wait is capped by the device code deadline
    assert clock.sleeps == [5, 5, 2]
    # no request is sent once the device code expired
    assert len(made) == 2


def test_poll_device_token_network_timeout_backoff():
    sess, made = make_session([Timeout(), Timeout(), (200, TOKEN)])
    clock = FakeClock()
    token = sess.poll_device_token(
        DEVICE_AUTHORIZATION, url=TOKEN_URL, clock=clock, sleep=clock.sleep
    )
    assert token["access_token"] == "a"
    # network timeouts back off exponentially: 1, 2
    assert clock.sleeps == [5, 1.0, 2.0]
    assert len(made) == 3


def test_poll_device_token_timeout_backoff_separate_from_interval():
    sess, made = make_session([Timeout(), pending(), Timeout(), (200, TOKEN)])
    clock = FakeClock()
    sess.poll_device_token(
        DEVICE_AUTHORIZATION, url=TOKEN_URL, clock=clock, sleep=clock.sleep
    )
    # the protocol interval (5) is untouched by network timeouts, and
    # any server response resets the timeout backoff
    assert clock.sleeps == [5, 1.0, 5, 1.0]
    assert len(made) == 4


def test_poll_device_token_missing_device_code():
    sess, _ = make_session([])
    with pytest.raises(ValueError):
        sess.poll_device_token(url=TOKEN_URL)


def test_poll_device_token_interrupt_stops_polling():
    sess, made = make_session([(200, TOKEN)])

    def interrupting_sleep(seconds):
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        sess.poll_device_token(
            DEVICE_AUTHORIZATION, url=TOKEN_URL, sleep=interrupting_sleep
        )
    # no request is sent after the wait was interrupted
    assert len(made) == 0
