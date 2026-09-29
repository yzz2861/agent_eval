import threading
import time
import uuid
from unittest import mock

import pytest

from authlib.common.urls import url_decode
from authlib.integrations.requests_client import OAuth2Session
from authlib.oauth2.token_store import SharedTokenStore
from authlib.oauth2.token_store import StoredToken
from authlib.oauth2.token_store import TokenPersistenceUncertainError


class MemoryTokenStore(SharedTokenStore):
    def __init__(self):
        self._cond = threading.Condition()
        self._stored = None
        self._lease = None  # (lease_id, owner, expires_at)

    def read(self):
        with self._cond:
            return self._stored

    def acquire_lease(self, owner, ttl):
        with self._cond:
            now = time.monotonic()
            if self._lease is not None and self._lease[2] > now:
                return None
            lease_id = uuid.uuid4().hex
            self._lease = (lease_id, owner, now + ttl)
            return lease_id

    def release_lease(self, lease_id):
        with self._cond:
            if self._lease is not None and self._lease[0] == lease_id:
                self._lease = None
            self._cond.notify_all()

    def wait_for_update(self, version, timeout):
        deadline = time.monotonic() + timeout
        with self._cond:
            while True:
                current = self._stored.version if self._stored else None
                if current != version:
                    return self._stored
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._cond.wait(remaining)

    def save(self, token, expected_version):
        with self._cond:
            current = self._stored.version if self._stored else None
            if current != expected_version:
                return False
            self._stored = StoredToken(dict(token), (current or 0) + 1)
            self._cond.notify_all()
            return True


class RotatingTokenServer:
    """Fake token endpoint: rotates the refresh token on every refresh."""

    def __init__(self):
        self.refresh_count = 0
        self.current_refresh_token = "rt-0"
        self.received_refresh_tokens = []
        self._lock = threading.Lock()

    def fake_send(self, request, **kwargs):
        params = dict(url_decode(request.body))
        with self._lock:
            self.received_refresh_tokens.append(params.get("refresh_token"))
            if params.get("refresh_token") != self.current_refresh_token:
                payload = {"error": "invalid_grant"}
                status_code = 400
            else:
                self.refresh_count += 1
                count = self.refresh_count
                self.current_refresh_token = f"rt-{count}"
                payload = {
                    "access_token": f"at-{count}",
                    "refresh_token": f"rt-{count}",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                }
                status_code = 200
        resp = mock.MagicMock()
        resp.status_code = status_code
        resp.json = lambda: payload
        return resp


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
    store = MemoryTokenStore()
    assert store.save(expired_token, None)
    return store


@pytest.fixture
def server():
    return RotatingTokenServer()


def make_client(store, server, token, **kwargs):
    sess = OAuth2Session(
        "foo",
        token=dict(token),
        token_endpoint="https://provider.test/token",
        token_store=store,
        **kwargs,
    )
    sess.send = server.fake_send
    return sess


def test_two_clients_share_one_refresh(store, server, expired_token):
    clients = [
        make_client(store, server, expired_token),
        make_client(store, server, expired_token),
    ]
    threads = [threading.Thread(target=c.ensure_active_token) for c in clients]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert server.refresh_count == 1
    assert server.received_refresh_tokens == ["rt-0"]
    for client in clients:
        assert client.token["access_token"] == "at-1"
        assert client.token["refresh_token"] == "rt-1"
    assert store.read().token["access_token"] == "at-1"
    assert store.read().version == 2


def test_lagging_client_adopts_stored_token(store, server, expired_token):
    fresh_token = {
        "token_type": "Bearer",
        "access_token": "at-9",
        "refresh_token": "rt-9",
        "expires_at": int(time.time()) + 3600,
    }
    assert store.save(fresh_token, 1)

    client = make_client(store, server, expired_token)
    client.ensure_active_token()

    assert server.refresh_count == 0
    assert server.received_refresh_tokens == []
    assert client.token["access_token"] == "at-9"
    assert client.token["refresh_token"] == "rt-9"


def test_update_token_called_with_store(store, server, expired_token):
    update_token = mock.Mock()
    client = make_client(store, server, expired_token, update_token=update_token)
    client.ensure_active_token()
    assert update_token.called
    token = update_token.call_args[0][0]
    assert token["access_token"] == "at-1"
    # same contract as the legacy flow: the previous refresh token
    assert update_token.call_args[1]["refresh_token"] == "rt-0"


def test_persistence_failure_reports_uncertain_state(store, server, expired_token):
    class FailingStore(MemoryTokenStore):
        def save(self, token, expected_version):
            raise OSError("disk full")

    failing_store = FailingStore()
    assert MemoryTokenStore.save(failing_store, expired_token, None)

    client = make_client(failing_store, server, expired_token)
    with pytest.raises(TokenPersistenceUncertainError) as exc_info:
        client.ensure_active_token()

    # the refresh succeeded exactly once and was not retried
    assert server.refresh_count == 1
    assert server.received_refresh_tokens == ["rt-0"]
    # the new token is available for manual recovery
    assert exc_info.value.token["access_token"] == "at-1"
    assert exc_info.value.expected_version == 1
    assert client.token["access_token"] == "at-1"


def test_cas_conflict_adopts_winner_token(store, server, expired_token):
    winner_token = {
        "token_type": "Bearer",
        "access_token": "at-winner",
        "refresh_token": "rt-winner",
        "expires_at": int(time.time()) + 3600,
    }

    class LosingStore(MemoryTokenStore):
        def save(self, token, expected_version):
            # another instance won the race and persisted first
            self._stored = StoredToken(dict(winner_token), expected_version + 1)
            return False

    losing_store = LosingStore()
    assert MemoryTokenStore.save(losing_store, expired_token, None)

    client = make_client(losing_store, server, expired_token)
    client.ensure_active_token()

    assert server.refresh_count == 1
    assert client.token["access_token"] == "at-winner"
    assert client.token["refresh_token"] == "rt-winner"


def test_lease_expiry_recovers_from_crashed_coordinator(store, server, expired_token):
    # a crashed coordinator never releases its lease
    assert store.acquire_lease("crashed-coordinator", ttl=0.1) is not None

    client = make_client(
        store,
        server,
        expired_token,
        token_store_lease_ttl=0.1,
        token_store_wait_timeout=0.2,
    )
    client.ensure_active_token()

    assert server.refresh_count == 1
    assert client.token["access_token"] == "at-1"
    assert store.read().token["access_token"] == "at-1"


def test_store_uses_freshest_refresh_token(store, server, expired_token):
    # the client's own token is older than the store's: the request must
    # use the store's refresh token, not the stale local one
    stale_token = dict(expired_token, refresh_token="rt-stale")
    client = make_client(store, server, stale_token)
    client.ensure_active_token()

    assert server.received_refresh_tokens == ["rt-0"]
    assert client.token["refresh_token"] == "rt-1"


def test_refresh_without_store_keeps_legacy_behavior(server, expired_token):
    sess = OAuth2Session(
        "foo",
        token=dict(expired_token),
        token_endpoint="https://provider.test/token",
    )
    sess.send = server.fake_send
    sess.ensure_active_token()

    assert server.refresh_count == 1
    assert sess.token["access_token"] == "at-1"
