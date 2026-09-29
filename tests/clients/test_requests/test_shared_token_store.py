import sqlite3
import threading
import time
from unittest import mock

import pytest

from authlib.integrations.requests_client import OAuth2Session
from authlib.oauth2.token_store import RefreshCoordinationTimeout
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


def mock_refresh_endpoint(payload, calls, delay=0):
    def fake_send(request, **kwargs):
        calls.append(request.body)
        if delay:
            time.sleep(delay)
        resp = mock.MagicMock()
        resp.status_code = 200
        resp.json = lambda: dict(payload)
        return resp

    return fake_send


def make_session(store, token, send=None, **kwargs):
    kwargs.setdefault("token_store_poll_interval", 0.05)
    sess = OAuth2Session(
        "foo",
        token=dict(token),
        token_endpoint=TOKEN_ENDPOINT,
        token_store=store,
        **kwargs,
    )
    if send is not None:
        sess.send = send
    return sess


def test_two_clients_share_single_refresh(store, expired_token, fresh_token):
    calls = []
    send = mock_refresh_endpoint(fresh_token, calls, delay=0.2)
    sess1 = make_session(store, expired_token, send)
    sess2 = make_session(store, expired_token, send)

    errors = []

    def ensure(sess):
        try:
            sess.ensure_active_token()
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [
        threading.Thread(target=ensure, args=(sess1,)),
        threading.Thread(target=ensure, args=(sess2,)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    # exactly one instance performed the HTTP refresh
    assert len(calls) == 1
    # the coordinator refreshed with the store's refresh token
    assert "refresh_token=refresh-1" in calls[0]
    # both instances converge on the new token
    assert sess1.token["access_token"] == "new-access"
    assert sess2.token["access_token"] == "new-access"
    record = store.read()
    assert record.version == 2
    assert record.token["refresh_token"] == "refresh-2"


def test_stale_instance_adopts_store_token(store, expired_token, fresh_token):
    # another instance already published a fresh token
    lease = store.acquire_refresh_lease(1, ttl=5)
    assert store.save_token(fresh_token, expected_version=1, lease=lease)

    def fail_send(request, **kwargs):  # pragma: no cover
        raise AssertionError("stale instance must not refresh")

    sess = make_session(store, expired_token, fail_send)
    assert sess.ensure_active_token() is True
    assert sess.token["access_token"] == "new-access"
    assert sess.token["refresh_token"] == "refresh-2"


def test_save_conflict_after_refresh_raises_uncertain(
    store, expired_token, fresh_token
):
    calls = []
    send = mock_refresh_endpoint(fresh_token, calls)
    sess = make_session(store, expired_token, send)

    with mock.patch.object(store, "save_token", return_value=False):
        with pytest.raises(TokenPersistenceError):
            sess.ensure_active_token()

    # the refresh request succeeded once and was not retried
    assert len(calls) == 1


def test_save_error_after_refresh_raises_uncertain(store, expired_token, fresh_token):
    calls = []
    send = mock_refresh_endpoint(fresh_token, calls)
    sess = make_session(store, expired_token, send)

    with mock.patch.object(
        store, "save_token", side_effect=sqlite3.OperationalError("disk full")
    ):
        with pytest.raises(TokenPersistenceError):
            sess.ensure_active_token()

    assert len(calls) == 1


def test_waiter_adopts_coordinator_result(store, expired_token, fresh_token):
    # simulate another instance holding the lease and publishing later
    lease = store.acquire_refresh_lease(1, ttl=5)
    assert lease is not None

    def publish():
        time.sleep(0.3)
        store.save_token(fresh_token, expected_version=1, lease=lease)

    threading.Thread(target=publish).start()

    def fail_send(request, **kwargs):  # pragma: no cover
        raise AssertionError("waiting instance must not refresh")

    sess = make_session(store, expired_token, fail_send)
    assert sess.ensure_active_token() is True
    assert sess.token["access_token"] == "new-access"


def test_coordinator_crash_lease_takeover(store, expired_token, fresh_token):
    # a coordinator acquired the lease and crashed without saving
    lease = store.acquire_refresh_lease(1, ttl=0.2)
    assert lease is not None

    calls = []
    send = mock_refresh_endpoint(fresh_token, calls)
    sess = make_session(store, expired_token, send)
    assert sess.ensure_active_token() is True

    # after the abandoned lease expired, this instance took over and
    # refreshed exactly once
    assert len(calls) == 1
    assert sess.token["access_token"] == "new-access"
    assert store.read().version == 2


def test_wait_timeout_raises(store, expired_token):
    # a live lease is held but nobody publishes a fresh token
    lease = store.acquire_refresh_lease(1, ttl=30)
    assert lease is not None

    sess = make_session(store, expired_token, token_store_wait_timeout=0.3)
    with pytest.raises(RefreshCoordinationTimeout):
        sess.ensure_active_token()


def test_cas_semantics(store, fresh_token):
    lease = store.acquire_refresh_lease(1, ttl=5)
    assert lease is not None
    # a live lease blocks a second coordinator
    assert store.acquire_refresh_lease(1, ttl=5) is None
    # wrong expected version is rejected
    assert not store.save_token(fresh_token, expected_version=7, lease=lease)
    # wrong lease id is rejected
    assert not store.save_token(fresh_token, expected_version=1, lease="bogus")
    # correct compare-and-swap succeeds and consumes the lease
    assert store.save_token(fresh_token, expected_version=1, lease=lease)
    assert store.read().version == 2
    # the consumed lease cannot save again
    assert not store.save_token(fresh_token, expected_version=1, lease=lease)


def test_default_behavior_without_store(expired_token, fresh_token):
    calls = []
    send = mock_refresh_endpoint(fresh_token, calls)
    sess = OAuth2Session(
        "foo",
        token=dict(expired_token),
        token_endpoint=TOKEN_ENDPOINT,
    )
    sess.send = send
    assert sess.token_store is None
    assert sess.ensure_active_token() is True
    assert len(calls) == 1
    assert sess.token["access_token"] == "new-access"
