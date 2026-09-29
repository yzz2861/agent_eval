"""Demo: two OAuth2 clients sharing one rotating refresh token.

Uses an in-process authorization-server stub whose refresh tokens rotate on
every refresh (a stale refresh token is rejected with ``invalid_grant``),
then shows that two client instances coordinating through one local SQLite
store perform exactly one refresh and converge on the same token.

Run from the repository root:

    python examples/shared_token_store/demo_two_clients.py
"""

import asyncio
import json
import os
import sys
import tempfile
import threading
import time
import warnings
from urllib.parse import parse_qsl

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

with warnings.catch_warnings():
    # the repository venv ships legacy httpx instead of httpx2
    warnings.simplefilter("ignore")
    from authlib.integrations.httpx_client import AsyncOAuth2Client
    from authlib.integrations.httpx_client._compat import httpx2

import requests
from requests.adapters import BaseAdapter
from sqlite_token_store import AsyncSQLiteTokenStore
from sqlite_token_store import SQLiteTokenStore

from authlib.integrations.requests_client import OAuth2Session
from authlib.oauth2.token_store import TokenPersistenceUncertainError

TOKEN_ENDPOINT = "http://authserver.test/token"


class RotatingTokenServer:
    """In-process token endpoint with refresh-token rotation and a counter."""

    def __init__(self):
        self.refresh_count = 0
        self.current_refresh_token = "rt-0"
        self._lock = threading.Lock()

    def handle(self, params):
        with self._lock:
            if (
                params.get("grant_type") == "refresh_token"
                and params.get("refresh_token") == self.current_refresh_token
            ):
                self.refresh_count += 1
                count = self.refresh_count
                self.current_refresh_token = f"rt-{count}"
                return 200, {
                    "access_token": f"at-{count}",
                    "refresh_token": f"rt-{count}",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                }
            return 400, {"error": "invalid_grant"}

    def requests_adapter(self):
        server = self

        class Adapter(BaseAdapter):
            def send(self, request, **kwargs):
                params = dict(parse_qsl(request.body or ""))
                status, payload = server.handle(params)
                response = requests.Response()
                response.status_code = status
                response.url = request.url
                response.request = request
                response.headers["Content-Type"] = "application/json"
                response._content = json.dumps(payload).encode()
                return response

            def close(self):
                pass

        return Adapter()

    def httpx_transport(self):
        def handler(request):
            params = dict(parse_qsl(request.content.decode()))
            status, payload = self.handle(params)
            return httpx2.Response(status, json=payload)

        return httpx2.MockTransport(handler)


def expired(token):
    token = dict(token)
    token["expires_at"] = int(time.time()) - 10
    token.pop("expires_in", None)
    return token


def seed_store(store, token):
    stored = store.read()
    assert store.save(token, stored.version if stored else None)


def make_sync_client(server, db_path, **kwargs):
    store = SQLiteTokenStore(db_path) if db_path else None
    token = expired(store.read().token) if store else kwargs.pop("token")
    client = OAuth2Session(
        "client-id",
        "client-secret",
        token=token,
        token_endpoint=TOKEN_ENDPOINT,
        token_store=store,
        **kwargs,
    )
    client.mount("http://authserver.test", server.requests_adapter())
    return client


def check_converged(clients, stored, refreshes):
    tokens = {client.token["access_token"] for client in clients}
    assert refreshes == 1, f"expected 1 refresh, got {refreshes}"
    assert len(tokens) == 1, f"clients diverged: {tokens}"
    assert tokens == {stored.token["access_token"]}, "clients lag the store"


def run_sync_round(server, db_path):
    clients = [make_sync_client(server, db_path) for _ in range(2)]
    before = server.refresh_count
    threads = [
        threading.Thread(target=client.ensure_active_token) for client in clients
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    refreshes = server.refresh_count - before
    stored = SQLiteTokenStore(db_path).read()
    check_converged(clients, stored, refreshes)
    print(
        "[sync ] two clients, one SQLite store: "
        f"{refreshes} refresh, both clients hold {stored.token['access_token']}"
    )


async def run_async_round(server, db_path):
    stored_token = AsyncSQLiteTokenStore(db_path)._sync.read().token
    clients = [
        AsyncOAuth2Client(
            "client-id",
            "client-secret",
            token=expired(stored_token),
            token_endpoint=TOKEN_ENDPOINT,
            token_store=AsyncSQLiteTokenStore(db_path),
            transport=server.httpx_transport(),
        )
        for _ in range(2)
    ]
    before = server.refresh_count
    async with clients[0], clients[1]:
        await asyncio.gather(
            *(client.ensure_active_token(client.token) for client in clients)
        )
    refreshes = server.refresh_count - before
    stored = await AsyncSQLiteTokenStore(db_path).read()
    check_converged(clients, stored, refreshes)
    print(
        "[async] two clients, one SQLite store: "
        f"{refreshes} refresh, both clients hold {stored.token['access_token']}"
    )


def run_crash_recovery_round(server, db_path):
    # Simulate a coordinator that crashed while holding the lease: the lease
    # is never released. After its TTL expires, another instance must be
    # able to take over and refresh.
    store = SQLiteTokenStore(db_path)
    stuck_lease = store.acquire_lease("crashed-coordinator", ttl=0.3)
    assert stuck_lease is not None
    seed_store(store, expired(store.read().token))

    client = make_sync_client(
        server,
        db_path,
        token_store_lease_ttl=1.0,
        token_store_wait_timeout=0.5,
    )
    before = server.refresh_count
    started = time.monotonic()
    client.ensure_active_token()
    elapsed = time.monotonic() - started
    refreshes = server.refresh_count - before
    assert refreshes == 1, f"expected 1 refresh, got {refreshes}"
    assert client.token["access_token"] == store.read().token["access_token"]
    print(
        "[sync ] crashed coordinator: lease expired, recovered in "
        f"{elapsed:.1f}s with {refreshes} refresh"
    )


def run_uncertain_state_round(server, db_path):
    class FailingStore(SQLiteTokenStore):
        def save(self, token, expected_version):
            raise OSError("disk full")

    seed_store(
        SQLiteTokenStore(db_path), expired(SQLiteTokenStore(db_path).read().token)
    )
    store = FailingStore(db_path)
    client = OAuth2Session(
        "client-id",
        "client-secret",
        token=expired(store.read().token),
        token_endpoint=TOKEN_ENDPOINT,
        token_store=store,
    )
    client.mount("http://authserver.test", server.requests_adapter())
    before = server.refresh_count
    try:
        client.ensure_active_token()
    except TokenPersistenceUncertainError as exc:
        refreshes = server.refresh_count - before
        assert refreshes == 1, "refresh must not be retried automatically"
        assert exc.token["access_token"] == client.token["access_token"]
        print(
            "[sync ] persistence failure: TokenPersistenceUncertainError "
            "raised, new token kept on the error, no automatic retry"
        )
    else:
        raise AssertionError("expected TokenPersistenceUncertainError")


def run_default_compat_round(server):
    # Without a token_store the client behaves exactly as before.
    client = make_sync_client(
        server,
        None,
        token=expired(
            {
                "access_token": "at-old",
                "refresh_token": server.current_refresh_token,
                "token_type": "Bearer",
            }
        ),
    )
    before = server.refresh_count
    client.ensure_active_token()
    refreshes = server.refresh_count - before
    assert refreshes == 1
    assert client.token["access_token"] == f"at-{server.refresh_count}"
    print("[sync ] no token_store: legacy direct refresh still works")


def main():
    server = RotatingTokenServer()
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "tokens.db")
        seed_store(
            SQLiteTokenStore(db_path),
            expired(
                {
                    "access_token": "at-0",
                    "refresh_token": "rt-0",
                    "token_type": "Bearer",
                }
            ),
        )
        run_sync_round(server, db_path)
        seed_store(
            SQLiteTokenStore(db_path),
            expired(SQLiteTokenStore(db_path).read().token),
        )
        asyncio.run(run_async_round(server, db_path))
        run_crash_recovery_round(server, db_path)
        run_uncertain_state_round(server, db_path)
        run_default_compat_round(server)
    print("OK: all shared token store scenarios passed")


if __name__ == "__main__":
    main()
