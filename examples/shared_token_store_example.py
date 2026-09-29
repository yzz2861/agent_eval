"""Two OAuth2 clients coordinating one rotating refresh token.

This example simulates an authorization server with rotating refresh
tokens in-process, then lets two independent client instances share the
token through a local SQLite store:

* without a shared store, both clients refresh concurrently and the
  loser replays an already-rotated refresh token (``invalid_grant``);
* with :class:`SQLiteSharedTokenStore`, exactly one client refreshes
  and the other re-reads the published result.

Run it with::

    python examples/shared_token_store_example.py
"""

import json
import os
import sqlite3
import tempfile
import threading
import time
from urllib.parse import parse_qs

from requests import Response
from requests.structures import CaseInsensitiveDict

from authlib.integrations.requests_client import OAuth2Session
from authlib.oauth2.token_store import SQLiteSharedTokenStore

TOKEN_ENDPOINT = "https://provider.example/token"


class DemoAuthorizationServer:
    """Token endpoint with rotating refresh tokens.

    Replaying an already-rotated refresh token is rejected with
    ``invalid_grant``, like strict production servers do.
    """

    def __init__(self):
        self.current_refresh_token = "refresh-1"
        self.access_counter = 0
        self.refresh_calls = 0

    def handle(self, body):
        self.refresh_calls += 1
        time.sleep(0.1)  # make concurrent refreshes overlap
        params = parse_qs(body)
        if params.get("refresh_token", [None])[0] != self.current_refresh_token:
            return 400, {"error": "invalid_grant"}
        self.access_counter += 1
        self.current_refresh_token = f"refresh-{self.access_counter + 1}"
        return 200, {
            "access_token": f"access-{self.access_counter}",
            "refresh_token": self.current_refresh_token,
            "token_type": "Bearer",
            "expires_in": 3600,
        }


def make_send(server):
    """Wire a session to the demo server without real HTTP."""

    def send(request, **kwargs):
        status, payload = server.handle(request.body)
        resp = Response()
        resp.status_code = status
        resp._content = json.dumps(payload).encode()
        resp.headers = CaseInsensitiveDict({"Content-Type": "application/json"})
        resp.url = request.url
        resp.request = request
        return resp

    return send


def expired_token():
    return {
        "token_type": "Bearer",
        "access_token": "expired-access",
        "refresh_token": "refresh-1",
        "expires_at": int(time.time()) - 10,
    }


def refresh_concurrently(server, token_store=None):
    results = {}

    def ensure(name):
        session = OAuth2Session(
            "demo-client",
            token=expired_token(),
            token_endpoint=TOKEN_ENDPOINT,
            token_store=token_store,
            token_store_poll_interval=0.05,
        )
        session.send = make_send(server)
        try:
            session.ensure_active_token()
            results[name] = ("ok", session.token["access_token"])
        except Exception as exc:
            results[name] = ("error", f"{type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=ensure, args=(name,)) for name in ("A", "B")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return results


def main():
    print("1) Two clients WITHOUT a shared store:")
    server = DemoAuthorizationServer()
    results = refresh_concurrently(server)
    print(f"   refresh calls to server: {server.refresh_calls}")
    for name, (status, value) in sorted(results.items()):
        print(f"   client {name}: {status} -> {value}")

    print()
    print("2) Two clients sharing a SQLite token store:")
    server = DemoAuthorizationServer()
    try:
        db_path = os.path.join(tempfile.mkdtemp(), "tokens.db")
        SQLiteSharedTokenStore(db_path).close()
    except (OSError, sqlite3.OperationalError):
        # restricted environment without a writable temp dir
        db_path = os.path.abspath("shared_tokens_demo.db")
    store = SQLiteSharedTokenStore(db_path)
    store.initialize(expired_token())
    results = refresh_concurrently(server, token_store=store)
    print(f"   refresh calls to server: {server.refresh_calls}")
    for name, (status, value) in sorted(results.items()):
        print(f"   client {name}: {status} -> {value}")
    record = store.read()
    print(f"   store version: {record.version}")
    print(f"   store refresh token: {record.token['refresh_token']}")
    store.close()
    if os.path.dirname(db_path) == os.getcwd():
        os.remove(db_path)


if __name__ == "__main__":
    main()
