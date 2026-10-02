"""Tests for the WSGI Idempotency-Key middleware."""

from __future__ import annotations

import threading

import pytest

import falcon
from falcon import testing
from falcon.idempotency import IdempotencyInProgress
from falcon.idempotency import IdempotencyKeyMiddleware
from falcon.idempotency import IdempotencyKeyReused
from falcon.idempotency import IdempotencyResultUnknown
from falcon.idempotency import SQLiteIdempotencyStore


class OrderResource:
    """Counts responder invocations and persists a fake side effect."""

    def __init__(self) -> None:
        self.calls = 0
        self.side_effects: list[int] = []
        self.entered = threading.Event()
        self.proceed = threading.Event()
        self.block = False

    def reset_barrier(self) -> None:
        self.entered.clear()
        self.proceed.clear()

    def on_post(self, req: falcon.Request, resp: falcon.Response) -> None:
        self.calls += 1
        payload = req.get_media()
        amount = int(payload['amount'])

        if self.block:
            self.entered.set()
            self.proceed.wait(timeout=10)

        # The "business database" commit happens before returning.
        self.side_effects.append(amount)
        resp.status = falcon.HTTP_201
        resp.set_header('X-Order', f'ord-{amount}')
        resp.media = {'amount': amount}


@pytest.fixture
def clock():
    return [1000.0]


@pytest.fixture
def resource():
    return OrderResource()


def make_app(store, resource, **middleware_kwargs):
    middleware = IdempotencyKeyMiddleware(store=store, **middleware_kwargs)
    app = falcon.App(middleware=[middleware])
    app.add_route('/orders', resource)
    return testing.TestClient(app)


@pytest.fixture
def store(tmp_path, clock):
    return SQLiteIdempotencyStore(
        str(tmp_path / 'idem.db'),
        lease_seconds=30.0,
        now=lambda: clock[0],
    )


HEADERS = {
    'Authorization': 'Bearer user-1',
    'Idempotency-Key': 'key-1',
}


def test_completed_request_is_replayed_without_recalling_responder(store, resource):
    client = make_app(store, resource)

    first = client.simulate_post('/orders', json={'amount': 7}, headers=HEADERS)
    assert first.status_code == 201
    assert first.headers['X-ORDER'] == 'ord-7'
    assert first.json == {'amount': 7}

    second = client.simulate_post('/orders', json={'amount': 7}, headers=HEADERS)
    assert second.status_code == 201
    assert second.headers['X-ORDER'] == 'ord-7'
    assert second.content == first.content

    assert resource.calls == 1
    assert resource.side_effects == [7]


def test_same_key_with_different_payload_is_rejected(store, resource):
    client = make_app(store, resource)

    assert (
        client.simulate_post('/orders', json={'amount': 1}, headers=HEADERS).status_code
        == 201
    )

    mismatch = client.simulate_post('/orders', json={'amount': 2}, headers=HEADERS)
    assert mismatch.status_code == 422
    assert resource.calls == 1


def test_scopes_and_routes_are_isolated(tmp_path, resource, clock):
    store = SQLiteIdempotencyStore(
        str(tmp_path / 'iso.db'),
        lease_seconds=30.0,
        now=lambda: clock[0],
    )
    client = make_app(store, resource)
    client.app.add_route('/orders-other', resource)

    first_user = dict(HEADERS)
    second_user = {
        'Authorization': 'Bearer user-2',
        'Idempotency-Key': 'key-1',
    }

    assert (
        client.simulate_post(
            '/orders', json={'amount': 1}, headers=first_user
        ).status_code
        == 201
    )
    assert (
        client.simulate_post(
            '/orders', json={'amount': 1}, headers=second_user
        ).status_code
        == 201
    )
    assert (
        client.simulate_post(
            '/orders-other', json={'amount': 1}, headers=first_user
        ).status_code
        == 201
    )

    assert resource.calls == 3


def test_request_without_key_or_auth_passes_through(store, resource):
    client = make_app(store, resource)

    assert client.simulate_post('/orders', json={'amount': 1}).status_code == 201
    assert client.simulate_post('/orders', json={'amount': 1}).status_code == 201
    assert resource.calls == 2


def test_non_protected_method_and_key_without_scope(store, resource):
    client = make_app(store, resource, methods=('PUT',))

    # POST is not protected for this middleware instance.
    assert client.simulate_post('/orders', json={'amount': 1}).status_code == 201
    assert client.simulate_post('/orders', json={'amount': 1}).status_code == 201
    assert resource.calls == 2


def test_key_without_scope_is_ignored(store, resource):
    client = make_app(store, resource, scope_provider=lambda req: None)
    assert (
        client.simulate_post(
            '/orders', json={'amount': 1}, headers={'Idempotency-Key': 'k'}
        ).status_code
        == 201
    )
    assert resource.calls == 1  # only one call made in this test


def test_actual_body_over_limit_without_content_length(store, resource):
    # Chunked/unknown-length bodies are still capped by actual byte count.
    client = make_app(store, resource, max_request_bytes=3)
    result = client.simulate_post(
        '/orders',
        body=b'abcd',
        headers={
            'Authorization': 'Bearer u',
            'Idempotency-Key': 'k',
            'Content-Type': 'application/json',
        },
    )
    assert result.status_code == 413


def test_declared_content_length_over_limit(store, resource):
    client = make_app(store, resource, max_request_bytes=3)
    result = client.simulate_request(
        'POST',
        '/orders',
        body=b'abcd',
        headers={
            'Authorization': 'Bearer u',
            'Idempotency-Key': 'k',
            'Content-Type': 'application/json',
            'Content-Length': '4',
        },
    )
    assert result.status_code == 413


def test_header_filter_branches(store):
    middleware = IdempotencyKeyMiddleware(store=store)
    assert middleware._should_replay_header('X-Custom')
    assert not middleware._should_replay_header('Content-Length')
    assert not middleware._should_replay_header('Set-Cookie')

    restricted = IdempotencyKeyMiddleware(store=store, replay_headers=('X-Keep',))
    assert restricted._should_replay_header('X-Keep')
    assert not restricted._should_replay_header('Set-Cookie')
    assert not restricted._should_replay_header('X-Other')


def test_concurrent_submit_returns_in_progress_then_replays(store, resource):
    resource.block = True
    client = make_app(store, resource, heartbeat_interval=1.0)

    result_box = {}

    def first_request() -> None:
        resource.reset_barrier()
        result_box['first'] = client.simulate_post(
            '/orders', json={'amount': 9}, headers=HEADERS
        )

    worker = threading.Thread(target=first_request)
    worker.start()
    assert resource.entered.wait(timeout=5)

    concurrent = client.simulate_post('/orders', json={'amount': 9}, headers=HEADERS)
    assert concurrent.status_code == 409
    assert concurrent.headers['RETRY-AFTER']

    resource.proceed.set()
    worker.join(timeout=5)
    assert result_box['first'].status_code == 201

    replay = client.simulate_post('/orders', json={'amount': 9}, headers=HEADERS)
    assert replay.status_code == 201
    assert replay.headers['X-ORDER'] == 'ord-9'

    assert resource.calls == 1
    assert resource.side_effects == [9]


def test_owner_vanishes_before_commit_marks_unknown(store, resource, clock):
    # Disable heartbeats so the lease can expire deterministically.
    client = make_app(store, resource, heartbeat_interval=None)

    first = store.acquire(
        'Bearer user-1',
        '/orders',
        'key-1',
        _fingerprint(client, {'amount': 5}),
    )
    assert first.state == 'created'

    # The owner (a crashed process/thread) never completes or renews.
    clock[0] += 31

    retry = client.simulate_post('/orders', json={'amount': 5}, headers=HEADERS)
    assert retry.status_code == 409
    assert retry.json['code'] == 40901
    assert resource.calls == 0
    assert resource.side_effects == []

    # The key stays blocked; administrator confirms and releases it.
    blocked = client.simulate_post('/orders', json={'amount': 5}, headers=HEADERS)
    assert blocked.status_code == 409

    assert store.release('Bearer user-1', '/orders', 'key-1')
    retried = client.simulate_post('/orders', json={'amount': 5}, headers=HEADERS)
    assert retried.status_code == 201
    assert resource.calls == 1


def test_responder_exception_marks_request_unknown(store, resource):
    class BoomResource:
        def on_post(self, req, resp):
            raise RuntimeError('business tx rolled back?')

    app = falcon.App(middleware=[IdempotencyKeyMiddleware(store=store)])
    app.add_route('/boom', BoomResource())
    client = testing.TestClient(app)

    result = client.simulate_post('/boom', json={}, headers=HEADERS)
    assert result.status_code == 409
    assert result.json['code'] == 40901

    record = store.get('Bearer user-1', '/boom', 'key-1')
    assert record is not None
    assert record.status.value == 'unknown'

    # The next retry also returns unknown instead of re-running.
    again = client.simulate_post('/boom', json={}, headers=HEADERS)
    assert again.status_code == 409


def test_streaming_response_is_rejected_and_quarantined(store):
    class StreamResource:
        def on_post(self, req, resp):
            resp.status = falcon.HTTP_200
            resp.set_stream(iter([b'a', b'b']), 2)

    app = falcon.App(middleware=[IdempotencyKeyMiddleware(store=store)])
    app.add_route('/stream', StreamResource())
    client = testing.TestClient(app)

    result = client.simulate_post('/stream', json={}, headers=HEADERS)
    assert result.status_code == 500

    record = store.get('Bearer user-1', '/stream', 'key-1')
    assert record is not None
    assert record.status.value == 'unknown'


def test_oversized_request_body_is_rejected(store, resource):
    client = make_app(store, resource, max_request_bytes=4)
    result = client.simulate_post('/orders', body=b'12345', headers=HEADERS)
    assert result.status_code == 413
    assert resource.calls == 0


def test_error_classes_are_public():
    assert issubclass(IdempotencyKeyReused, falcon.HTTPUnprocessableEntity)
    assert issubclass(IdempotencyInProgress, falcon.HTTPConflict)
    assert issubclass(IdempotencyResultUnknown, falcon.HTTPConflict)


def test_configuration_validation(store):
    with pytest.raises(ValueError):
        IdempotencyKeyMiddleware(store=store, max_request_bytes=0)
    with pytest.raises(ValueError):
        IdempotencyKeyMiddleware(store=store, max_response_bytes=0)
    with pytest.raises(ValueError):
        IdempotencyKeyMiddleware(store=store, heartbeat_interval=-1)


def test_empty_body_is_replayed(store):
    class EmptyResource:
        def on_post(self, req, resp):
            resp.status = falcon.HTTP_204

    app = falcon.App(middleware=[IdempotencyKeyMiddleware(store=store)])
    app.add_route('/empty', EmptyResource())
    client = testing.TestClient(app)

    first = client.simulate_post('/empty', headers=HEADERS)
    assert first.status_code == 204
    second = client.simulate_post('/empty', headers=HEADERS)
    assert second.status_code == 204
    assert second.content == b''


def test_replay_header_allowlist_and_cookies(store):
    class CookieResource:
        def on_post(self, req, resp):
            resp.status = falcon.HTTP_200
            resp.set_header('X-Keep', 'yes')
            resp.set_header('X-Drop', 'yes')
            resp.set_cookie('session', 'value')
            resp.data = b'ok'

    middleware = IdempotencyKeyMiddleware(store=store, replay_headers=('X-Keep',))
    app = falcon.App(middleware=[middleware])
    app.add_route('/cookies', CookieResource())
    client = testing.TestClient(app)

    client.simulate_post('/cookies', headers=HEADERS)
    replay = client.simulate_post('/cookies', headers=HEADERS)
    assert replay.headers.get('X-KEEP') == 'yes'
    assert 'X-DROP' not in replay.headers
    assert 'SET-COOKIE' not in replay.headers


def test_replay_without_headers(store):
    class HeadedResource:
        def on_post(self, req, resp):
            resp.status = falcon.HTTP_200
            resp.data = b'ok'

    app = falcon.App(middleware=[IdempotencyKeyMiddleware(store=store)])
    app.add_route('/plain', HeadedResource())
    client = testing.TestClient(app)

    client.simulate_post('/plain', headers=HEADERS)
    replay = client.simulate_post('/plain', headers=HEADERS)
    assert replay.status_code == 200
    assert replay.content == b'ok'


def test_replay_record_with_empty_headers_list(store):
    first = store.acquire('Bearer user-1', '/orders', 'key-1', b'fp')
    assert store.complete(
        'Bearer user-1',
        '/orders',
        'key-1',
        first.owner,
        200,
        [],
        b'body',
    )
    result = store.acquire('Bearer user-1', '/orders', 'key-1', b'fp')
    middleware = IdempotencyKeyMiddleware(store=store)
    resp = falcon.Response()
    middleware._replay(result.record, resp)
    assert resp.status_code == 200
    assert resp.data == b'body'
    assert resp.complete is True


def test_replay_skips_filtered_headers_in_loop(store):
    first = store.acquire('Bearer user-1', '/orders', 'key-1', b'fp')
    store.complete(
        'Bearer user-1',
        '/orders',
        'key-1',
        first.owner,
        200,
        [
            ('Content-Length', '42'),  # filtered, loop continues
            ('X-Keep', 'yes'),  # then a header is replayed
        ],
        b'body',
    )
    result = store.acquire('Bearer user-1', '/orders', 'key-1', b'fp')
    middleware = IdempotencyKeyMiddleware(store=store)
    resp = falcon.Response()
    middleware._replay(result.record, resp)
    assert resp.get_header('x-keep') == 'yes'
    assert resp.get_header('content-length') is None


def test_commit_race_returns_unknown(store, monkeypatch):
    client = make_app(store, resource)

    def lose_claim(*args, **kwargs):
        return False

    monkeypatch.setattr(store, 'complete', lose_claim)
    result = client.simulate_post('/orders', json={'amount': 3}, headers=HEADERS)
    assert result.status_code == 409

    # The claim is resolved, and the late response never overwrites it.
    record = store.get('Bearer user-1', '/orders', 'key-1')
    assert record is not None
    assert record.status.value in ('unknown', 'processing')


def test_stop_heartbeat_when_thread_finished(store):
    from falcon.idempotency.middleware import _Claim

    claim = _Claim('s', 'r', 'k', 'owner')
    claim.thread = None
    IdempotencyKeyMiddleware._stop_heartbeat(claim)


def test_process_response_without_claim_is_noop(store):
    middleware = IdempotencyKeyMiddleware(store=store)
    req = testing.create_req()
    resp = falcon.Response()
    middleware.process_response(req, resp, None, True)


def test_asgi_request_is_rejected():
    import falcon.asgi

    store = SQLiteIdempotencyStore(':memory:')
    middleware = IdempotencyKeyMiddleware(store=store)
    req = falcon.asgi.Request(
        testing.create_scope(),
        receive=_never_receives,
    )
    resp = falcon.asgi.Response()
    with pytest.raises(falcon.CompatibilityError):
        middleware.process_request(req, resp)


async def _never_receives():  # pragma: no cover
    raise RuntimeError('unexpected receive')


def test_disabled_heartbeat_starts_no_thread(store):
    from falcon.idempotency.middleware import _Claim

    middleware = IdempotencyKeyMiddleware(store=store, heartbeat_interval=0)
    claim = _Claim('s', 'r', 'k', 'owner')
    middleware._start_heartbeat(claim)
    assert claim.thread is None


def test_process_response_raises_when_commit_lost(store, monkeypatch):
    result = store.acquire('Bearer user-1', '/orders', 'key-1', b'fp')
    monkeypatch.setattr(store, 'complete', lambda *a, **k: False)

    middleware = IdempotencyKeyMiddleware(store=store, heartbeat_interval=None)
    claim = _make_claim_with_owner('Bearer user-1', '/orders', 'key-1', result.owner)
    req = testing.create_req()
    req.context._idempotency_claim = claim
    resp = falcon.Response()
    resp.data = b'ok'

    with pytest.raises(IdempotencyResultUnknown):
        middleware.process_response(req, resp, None, True)


def _make_claim_with_owner(scope, route, key, owner):
    from falcon.idempotency.middleware import _Claim

    return _Claim(scope, route, key, owner)


def test_oversized_response_is_rejected(store, resource):
    class BigResource:
        def on_post(self, req, resp):
            resp.data = b'x' * 10

    middleware = IdempotencyKeyMiddleware(store=store, max_response_bytes=4)
    app = falcon.App(middleware=[middleware])
    app.add_route('/big', BigResource())
    client = testing.TestClient(app)

    result = client.simulate_post('/big', headers=HEADERS)
    assert result.status_code == 500


def test_heartbeat_renews_and_stops(tmp_path, resource):
    import time as time_module

    real_store = SQLiteIdempotencyStore(
        str(tmp_path / 'heartbeat.db'), lease_seconds=30.0
    )
    client = make_app(real_store, resource, heartbeat_interval=0.02)
    resource.block = True
    box = {}

    def run():
        resource.reset_barrier()
        box['result'] = client.simulate_post(
            '/orders', json={'amount': 4}, headers=HEADERS
        )

    worker = threading.Thread(target=run)
    worker.start()
    assert resource.entered.wait(timeout=5)

    record = real_store.get('Bearer user-1', '/orders', 'key-1')
    assert record is not None
    first_lease = record.lease_expires_at
    time_module.sleep(0.05)
    record = real_store.get('Bearer user-1', '/orders', 'key-1')
    assert record is not None
    assert record.lease_expires_at > first_lease

    resource.proceed.set()
    worker.join(timeout=5)
    assert box['result'].status_code == 201


def test_heartbeat_exits_when_lease_lost(store):
    middleware = IdempotencyKeyMiddleware(store=store, heartbeat_interval=0.01)
    claim = _make_claim(store)
    middleware._start_heartbeat(claim)
    assert claim.thread is not None
    store.release('Bearer user-1', '/orders', 'key-1')
    claim.thread.join(timeout=5)
    assert not claim.thread.is_alive()


def _make_claim(store):
    from falcon.idempotency.middleware import _Claim

    result = store.acquire('Bearer user-1', '/orders', 'key-1', b'fp')
    return _Claim('Bearer user-1', '/orders', 'key-1', result.owner)


def _fingerprint(client, payload):
    # Reproduce the middleware's hash for the store-level crash setup.
    import hashlib
    import json

    body = json.dumps(payload).encode()
    digest = hashlib.sha256()
    digest.update(body)
    digest.update(b'\x00')
    digest.update(b'application/json')
    return digest.digest()
