import io
import sqlite3

import pytest

import falcon
from falcon.idempotency import IdempotencyDecision
from falcon.idempotency import IdempotencyMiddleware
from falcon.idempotency import SQLiteIdempotencyStore
from falcon.idempotency import StoredIdempotentResponse
import falcon.testing as testing
from falcon.testing.client import _simulate_request_asgi

KEY = 'key-123'


def scope(req):
    return req.get_header('X-User') or 'anonymous'


async def async_scope(req):
    return scope(req)


class IdempotentResource:
    def __init__(self, state):
        self.state = state

    def on_post(self, req, resp):
        body = req.bounded_stream.read()
        self.state['calls'] += 1
        self.state['bodies'].append(body)
        resp.status = falcon.HTTP_201
        resp.content_type = falcon.MEDIA_JSON
        resp.set_header('X-Custom', 'one')
        resp.set_cookie('session', 'abc')
        resp.media = {'created': True}


class AsyncIdempotentResource(IdempotentResource):
    async def on_post(self, req, resp):
        body = await req.bounded_stream.read()
        self.state['calls'] += 1
        self.state['bodies'].append(body)
        resp.status = falcon.HTTP_201
        resp.content_type = falcon.MEDIA_JSON
        resp.set_header('X-Custom', 'one')
        resp.set_cookie('session', 'abc')
        resp.media = {'created': True}


class FailingResource:
    def __init__(self, state, exit_after=None):
        self.state = state
        self.exit_after = exit_after

    def on_post(self, req, resp):
        body = req.bounded_stream.read()
        self.state['calls'] += 1
        self.state['body'] = body
        if self.exit_after is not None:
            self.exit_after()
        raise RuntimeError('owner exited before recording response')


class AsyncFailingResource(FailingResource):
    async def on_post(self, req, resp):
        body = await req.bounded_stream.read()
        self.state['calls'] += 1
        self.state['body'] = body
        if self.exit_after is not None:
            self.exit_after()
        raise RuntimeError('owner exited before recording response')


class ConcurrentOwnerResource:
    def __init__(self, state, other_client, side_effect_path=None):
        self.state = state
        self.other_client = other_client
        self.side_effect_path = side_effect_path

    def on_post(self, req, resp):
        req.bounded_stream.read()
        if self.side_effect_path is not None:
            self.side_effect_path.write_bytes(b'business-committed')
        self.state['concurrent'] = self.other_client.simulate_post(
            '/items',
            body=b'{}',
            headers=headers(),
            content_type=falcon.MEDIA_JSON,
        )
        self.state['calls'] += 1
        raise RuntimeError('owner exits before submitting response record')


class AsyncConcurrentOwnerResource(ConcurrentOwnerResource):
    async def on_post(self, req, resp):
        await req.bounded_stream.read()
        if self.side_effect_path is not None:
            self.side_effect_path.write_bytes(b'business-committed')
        self.state['concurrent'] = await _simulate_request_asgi(
            self.other_client.app,
            'POST',
            '/items',
            body=b'{}',
            headers=headers(),
            content_type=falcon.MEDIA_JSON,
            _one_shot=False,
        )
        self.state['calls'] += 1
        raise RuntimeError('owner exits before submitting response record')


class StreamResource:
    def on_post(self, req, resp):
        resp.status = falcon.HTTP_200
        resp.stream = io.BytesIO(b'streamed')


class AsyncStreamResource(StreamResource):
    async def on_post(self, req, resp):
        resp.status = falcon.HTTP_200
        resp.stream = _AsyncByteStream(b'streamed')


class _AsyncByteStream:
    def __init__(self, data):
        self._data = data
        self._pos = 0

    async def read(self, size=-1):
        if size < 0:
            size = len(self._data) - self._pos
        data = self._data[self._pos : self._pos + size]
        self._pos += len(data)
        return data

    async def close(self):
        return None


def make_client(asgi, db_path, state, resource=None, **middleware_kwargs):
    store = SQLiteIdempotencyStore(db_path)
    middleware = IdempotencyMiddleware(store, user_scope=scope, **middleware_kwargs)
    app = (
        falcon.asgi.App(middleware=middleware)
        if asgi
        else falcon.App(middleware=middleware)
    )
    if resource is None:
        resource = AsyncIdempotentResource(state) if asgi else IdempotentResource(state)
    app.add_route('/items', resource)
    return store, testing.TestClient(app)


def make_app(asgi, store, resource):
    middleware = IdempotencyMiddleware(store, user_scope=scope)
    app = (
        falcon.asgi.App(middleware=middleware)
        if asgi
        else falcon.App(middleware=middleware)
    )
    app.add_route('/items', resource)
    return testing.TestClient(app)


def headers(key=KEY, user='alice'):
    return {'Idempotency-Key': key, 'X-User': user}


def post(client, asgi, body=b'{}', path='/items', **kwargs):
    return client.simulate_post(path, body=body, **kwargs)


def test_replays_completed_response_without_recalling_responder(asgi, util, tmp_path):
    db_path = tmp_path / 'idempotency.sqlite3'
    state = {'calls': 0, 'bodies': []}
    store, client = make_client(asgi, db_path, state)

    first = post(
        client,
        asgi,
        headers=headers(),
        content_type=falcon.MEDIA_JSON,
    )
    second = post(
        client,
        asgi,
        headers=headers(),
        content_type=falcon.MEDIA_JSON,
    )

    assert first.status_code == 201
    assert second.status_code == 201
    assert second.content == first.content
    assert second.headers['X-Custom'] == 'one'
    assert second.headers['Idempotency-Replayed'] == 'true'
    assert 'session=' in second.headers['Set-Cookie']
    assert state['calls'] == 1
    assert state['bodies'] == [b'{}']
    store.close()


def test_rejects_same_key_with_different_request_content(asgi, tmp_path):
    db_path = tmp_path / 'idempotency.sqlite3'
    state = {'calls': 0, 'bodies': []}
    _, client = make_client(asgi, db_path, state)

    post(client, asgi, headers=headers(), content_type=falcon.MEDIA_JSON)
    mismatch = post(
        client,
        asgi,
        body=b'{"different":true}',
        headers=headers(),
        content_type=falcon.MEDIA_JSON,
    )

    assert mismatch.status_code == 422
    assert mismatch.headers['Idempotency-Status'] == 'fingerprint-mismatch'
    assert state['calls'] == 1


def test_rejects_same_key_with_different_content_type(asgi, tmp_path):
    db_path = tmp_path / 'idempotency.sqlite3'
    state = {'calls': 0, 'bodies': []}
    _, client = make_client(asgi, db_path, state)

    post(client, asgi, headers=headers(), content_type=falcon.MEDIA_JSON)
    mismatch = post(
        client,
        asgi,
        headers=headers(),
        content_type=falcon.MEDIA_TEXT,
    )

    assert mismatch.status_code == 422
    assert state['calls'] == 1


def test_rejects_same_key_with_different_query_string(asgi, tmp_path):
    db_path = tmp_path / 'idempotency.sqlite3'
    state = {'calls': 0, 'bodies': []}
    _, client = make_client(asgi, db_path, state)

    post(client, asgi, query_string='a=1', headers=headers())
    mismatch = post(
        client,
        asgi,
        query_string='a=2',
        headers=headers(),
    )

    assert mismatch.status_code == 422
    assert state['calls'] == 1


def test_isolates_user_scope_and_route_template(asgi, tmp_path):
    db_path = tmp_path / 'idempotency.sqlite3'
    state = {'calls': 0, 'bodies': []}
    _, client = make_client(asgi, db_path, state)

    alice = post(client, asgi, headers=headers(user='alice'))
    bob = post(client, asgi, headers=headers(user='bob'))

    assert alice.status_code == 201
    assert bob.status_code == 201
    assert state['calls'] == 2


def test_isolates_route_template_for_same_user_and_key(asgi, tmp_path):
    db_path = tmp_path / 'idempotency.sqlite3'
    state = {'calls': 0, 'bodies': []}
    store, client = make_client(asgi, db_path, state)
    other_resource = (
        AsyncIdempotentResource(state) if asgi else IdempotentResource(state)
    )
    client.app.add_route('/other-items', other_resource)

    first = post(
        client,
        asgi,
        path='/items',
        headers=headers(),
        content_type=falcon.MEDIA_JSON,
    )
    second = post(
        client,
        asgi,
        path='/other-items',
        headers=headers(),
        content_type=falcon.MEDIA_JSON,
    )

    assert first.status_code == 201
    assert second.status_code == 201
    assert state['calls'] == 2
    store.close()


def test_requests_without_idempotency_key_bypass_store(asgi, tmp_path):
    db_path = tmp_path / 'idempotency.sqlite3'
    state = {'calls': 0, 'bodies': []}
    _, client = make_client(asgi, db_path, state)

    first = post(client, asgi, headers={'X-User': 'alice'})
    second = post(client, asgi, headers={'X-User': 'alice'})

    assert first.status_code == 201
    assert second.status_code == 201
    assert state['calls'] == 2


def test_rejects_oversized_request_body(asgi, tmp_path):
    db_path = tmp_path / 'idempotency.sqlite3'
    state = {'calls': 0, 'bodies': []}
    _, client = make_client(asgi, db_path, state, max_request_body_size=3)

    result = post(
        client,
        asgi,
        body=b'abcd',
        headers=headers(),
        content_type=falcon.MEDIA_JSON,
    )

    assert result.status_code == 413
    assert state['calls'] == 0


def test_asgi_chunked_request_body_is_buffered_and_replayed(tmp_path):
    db_path = tmp_path / 'idempotency.sqlite3'
    state = {'calls': 0, 'bodies': []}
    store, client = make_client(True, db_path, state)
    request_headers = headers()
    request_headers['Content-Type'] = falcon.MEDIA_JSON
    scope_data = testing.create_scope(
        path='/items', method='POST', headers=request_headers
    )
    receive = testing.ASGIRequestEventEmitter(b'{}')
    collector = testing.ASGIResponseEventCollector()

    falcon.async_to_sync(client.app, scope_data, receive.emit, collector)
    first = testing.Result(
        collector.body_chunks,
        falcon.code_to_http_status(collector.status),
        collector.headers,
    )
    second = client.simulate_post(
        '/items',
        body=b'{}',
        headers=headers(),
        content_type=falcon.MEDIA_JSON,
    )

    assert first.status_code == 201
    assert second.status_code == 201
    assert state['calls'] == 1
    assert state['bodies'] == [b'{}']
    store.close()


def test_asgi_chunked_request_body_obeys_limit(tmp_path):
    db_path = tmp_path / 'idempotency.sqlite3'
    state = {'calls': 0, 'bodies': []}
    _, client = make_client(True, db_path, state, max_request_body_size=1)
    request_headers = headers()
    request_headers['Content-Type'] = falcon.MEDIA_JSON
    scope_data = testing.create_scope(
        path='/items', method='POST', headers=request_headers
    )
    receive = testing.ASGIRequestEventEmitter(b'ab')
    collector = testing.ASGIResponseEventCollector()

    falcon.async_to_sync(client.app, scope_data, receive.emit, collector)
    result = testing.Result(
        collector.body_chunks,
        falcon.code_to_http_status(collector.status),
        collector.headers,
    )

    assert result.status_code == 413
    assert state['calls'] == 0


def test_wsgi_requires_content_length(tmp_path):
    db_path = tmp_path / 'idempotency.sqlite3'
    state = {'calls': 0, 'bodies': []}
    _, client = make_client(False, db_path, state)

    environ = testing.create_environ(
        path='/items',
        method='POST',
        headers=headers(),
        body=b'{}',
    )
    environ.pop('CONTENT_LENGTH')

    srmock = testing.StartResponseMock()
    iterable = client.app(environ, srmock)
    result = testing.Result(iterable, srmock.status, srmock.headers)
    if hasattr(iterable, 'close'):
        iterable.close()

    assert result.status_code == 411
    assert state['calls'] == 0


def test_rejects_stream_response_as_unreplayable(asgi, tmp_path):
    db_path = tmp_path / 'idempotency.sqlite3'
    store = SQLiteIdempotencyStore(db_path)
    middleware = IdempotencyMiddleware(store, user_scope=scope)
    app = (
        falcon.asgi.App(middleware=middleware)
        if asgi
        else falcon.App(middleware=middleware)
    )
    app.add_route('/items', AsyncStreamResource() if asgi else StreamResource())
    client = testing.TestClient(app)

    result = post(
        client,
        asgi,
        headers=headers(),
        content_type=falcon.MEDIA_JSON,
    )
    retry = post(
        client,
        asgi,
        headers=headers(),
        content_type=falcon.MEDIA_JSON,
    )

    assert result.status_code == 503
    assert result.headers['Idempotency-Status'] == 'unknown'
    assert retry.status_code == 409
    assert retry.headers['Idempotency-Status'] == 'unknown'
    store.close()


def test_rejects_scheduled_callback_response_as_unreplayable(tmp_path):
    db_path = tmp_path / 'idempotency.sqlite3'
    store = SQLiteIdempotencyStore(db_path)
    middleware = IdempotencyMiddleware(store, user_scope=scope)
    app = falcon.asgi.App(middleware=middleware)

    class CallbackResource:
        async def on_post(self, req, resp):
            async def callback():
                return None

            resp.data = b'callback'
            resp.schedule(callback)

    app.add_route('/items', CallbackResource())
    client = testing.TestClient(app)

    result = client.simulate_post(
        '/items',
        body=b'{}',
        headers=headers(),
        content_type=falcon.MEDIA_JSON,
    )

    assert result.status_code == 503
    assert result.headers['Idempotency-Status'] == 'unknown'
    store.close()


def test_rejects_oversized_response_body(asgi, tmp_path):
    db_path = tmp_path / 'idempotency.sqlite3'
    state = {'calls': 0, 'bodies': []}
    _, client = make_client(asgi, db_path, state, max_response_body_size=10)

    result = post(
        client,
        asgi,
        body=b'12345678901',
        headers=headers(),
        content_type=falcon.MEDIA_JSON,
    )

    assert result.status_code == 503
    assert result.headers['Idempotency-Status'] == 'unknown'
    assert state['calls'] == 1


def test_empty_idempotency_key_is_bad_request(asgi, tmp_path):
    db_path = tmp_path / 'idempotency.sqlite3'
    state = {'calls': 0, 'bodies': []}
    _, client = make_client(asgi, db_path, state)

    result = post(
        client,
        asgi,
        headers={'Idempotency-Key': '', 'X-User': 'alice'},
    )

    assert result.status_code == 400
    assert state['calls'] == 0


def test_async_user_scope_is_supported(asgi, tmp_path):
    if not asgi:
        pytest.skip('ASGI-only user-scope provider behavior.')
    db_path = tmp_path / 'idempotency.sqlite3'
    state = {'calls': 0, 'bodies': []}
    store = SQLiteIdempotencyStore(db_path)
    app = falcon.asgi.App(
        middleware=IdempotencyMiddleware(store, user_scope=async_scope)
    )
    app.add_route('/items', AsyncIdempotentResource(state))
    client = testing.TestClient(app)

    result = post(
        client,
        asgi,
        headers=headers(),
        content_type=falcon.MEDIA_JSON,
    )

    assert result.status_code == 201
    store.close()


def test_sync_app_rejects_async_user_scope(tmp_path):
    class ClosableAwaitable:
        def __init__(self):
            self.closed = False

        def __await__(self):
            yield
            return 'alice'

        def close(self):
            self.closed = True

    class PlainAwaitable:
        def __await__(self):
            yield
            return 'alice'

    awaitable = ClosableAwaitable()
    req = testing.create_req(
        method='POST',
        path='/items',
        headers=headers(),
    )
    resp = falcon.Response()
    store = SQLiteIdempotencyStore(tmp_path / 'idempotency.sqlite3')
    middleware = IdempotencyMiddleware(store, user_scope=lambda request: awaitable)

    with pytest.raises(falcon.CompatibilityError):
        middleware.process_resource(req, resp, object(), {})
    assert awaitable.closed

    middleware = IdempotencyMiddleware(
        store, user_scope=lambda request: PlainAwaitable()
    )
    with pytest.raises(falcon.CompatibilityError):
        middleware.process_resource(req, resp, object(), {})


def test_non_idempotent_method_bypasses_middleware(asgi, tmp_path):
    db_path = tmp_path / 'idempotency.sqlite3'
    state = {'calls': 0, 'bodies': []}
    store = SQLiteIdempotencyStore(db_path)
    middleware = IdempotencyMiddleware(store, user_scope=scope)
    app = (
        falcon.asgi.App(middleware=middleware)
        if asgi
        else falcon.App(middleware=middleware)
    )

    class GetResource:
        def on_get(self, req, resp):
            state['calls'] += 1
            resp.text = 'ok'

    class AsyncGetResource:
        async def on_get(self, req, resp):
            state['calls'] += 1
            resp.text = 'ok'

    resource = AsyncGetResource() if asgi else GetResource()
    app.add_route('/items', resource)
    client = testing.TestClient(app)

    first = client.simulate_get('/items', headers=headers())
    second = client.simulate_get('/items', headers=headers())

    assert first.status_code == 200
    assert second.status_code == 200
    assert state['calls'] == 2
    store.close()


def test_invalid_limits_are_rejected(tmp_path):
    with pytest.raises(ValueError):
        IdempotencyMiddleware(
            SQLiteIdempotencyStore(tmp_path / 'a.sqlite3'),
            user_scope=scope,
            max_request_body_size=-1,
        )
    with pytest.raises(ValueError):
        IdempotencyMiddleware(
            SQLiteIdempotencyStore(tmp_path / 'b.sqlite3'),
            user_scope=scope,
            max_response_body_size=-1,
        )


def test_owner_failure_leaves_unknown_record_and_persists_side_effect(asgi, tmp_path):
    db_path = tmp_path / 'idempotency.sqlite3'
    state = {'calls': 0, 'body': None}
    resource = AsyncFailingResource(state) if asgi else FailingResource(state)
    store, client = make_client(asgi, db_path, state, resource=resource)

    first = post(
        client,
        asgi,
        headers=headers(),
        content_type=falcon.MEDIA_JSON,
    )
    retry = post(
        client,
        asgi,
        headers=headers(),
        content_type=falcon.MEDIA_JSON,
    )

    assert first.status_code == 500
    assert retry.status_code == 409
    assert retry.headers['Idempotency-Status'] == 'unknown'
    assert state['calls'] == 1
    assert state['body'] == b'{}'

    with pytest.raises(ValueError):
        store.release_unknown(
            user_scope='alice',
            route='/items',
            idempotency_key=KEY,
            confirmed=False,
        )
    assert store.release_unknown(
        user_scope='alice',
        route='/items',
        idempotency_key=KEY,
        confirmed=True,
    )
    retry_after_release = post(
        client,
        asgi,
        headers=headers(),
        content_type=falcon.MEDIA_JSON,
    )
    assert retry_after_release.status_code == 500
    assert state['calls'] == 2
    store.close()


def test_concurrent_submission_sees_processing_then_owner_unknown(asgi, tmp_path):
    db_path = tmp_path / 'idempotency.sqlite3'
    state = {'calls': 0, 'concurrent': None}
    side_effect_path = tmp_path / 'business-side-effect'
    owner_store = SQLiteIdempotencyStore(db_path)
    follower_store = SQLiteIdempotencyStore(db_path)
    second_client = make_app(asgi, follower_store, FailingResource({'calls': 0}))
    owner_resource = (
        AsyncConcurrentOwnerResource(state, second_client, side_effect_path)
        if asgi
        else ConcurrentOwnerResource(state, second_client, side_effect_path)
    )
    owner_client = make_app(asgi, owner_store, owner_resource)

    owner_result = post(
        owner_client,
        asgi,
        headers=headers(),
        content_type=falcon.MEDIA_JSON,
    )
    later_result = post(
        second_client,
        asgi,
        headers=headers(),
        content_type=falcon.MEDIA_JSON,
    )

    concurrent = state['concurrent']
    assert owner_result.status_code == 500
    assert concurrent.status_code == 409
    assert concurrent.headers['Idempotency-Status'] == 'processing'
    assert later_result.status_code == 409
    assert later_result.headers['Idempotency-Status'] == 'unknown'
    assert state['calls'] == 1
    assert side_effect_path.read_bytes() == b'business-committed'
    owner_store.close()
    follower_store.close()


def test_expired_completed_result_can_be_purged(tmp_path):
    clock = [100.0]
    store = SQLiteIdempotencyStore(
        tmp_path / 'idempotency.sqlite3',
        result_ttl_seconds=10.0,
        clock=lambda: clock[0],
    )
    result = store.begin(
        user_scope='alice',
        route='/items',
        idempotency_key='expired',
        request_fingerprint='fingerprint',
    )
    assert result.is_new
    assert store.complete(
        user_scope='alice',
        route='/items',
        idempotency_key='expired',
        owner_id=result.owner_id,
        response=StoredIdempotentResponse(200, (), b'ok'),
    )
    assert store.purge_expired(now=109.0) == 0
    clock[0] = 111.0
    assert store.purge_expired() == 1
    next_result = store.begin(
        user_scope='alice',
        route='/items',
        idempotency_key='expired',
        request_fingerprint='fingerprint',
    )
    assert next_result.is_new
    store.close()


def test_stale_processing_lease_becomes_unknown(tmp_path):
    clock = [100.0]
    store = SQLiteIdempotencyStore(
        tmp_path / 'idempotency.sqlite3',
        processing_lease_seconds=1.0,
        clock=lambda: clock[0],
    )
    first = store.begin(
        user_scope='alice',
        route='/items',
        idempotency_key='stale',
        request_fingerprint='fingerprint',
    )
    clock[0] = 102.0
    later = store.begin(
        user_scope='alice',
        route='/items',
        idempotency_key='stale',
        request_fingerprint='fingerprint',
    )
    assert later.decision is IdempotencyDecision.UNKNOWN
    assert not store.mark_unknown(
        user_scope='alice',
        route='/items',
        idempotency_key='stale',
        owner_id=first.owner_id,
    )
    store.close()


def test_close_is_safe_without_connection(tmp_path):
    store = SQLiteIdempotencyStore(tmp_path / 'idempotency.sqlite3')
    store.close()


def test_disconnect_event_for_cached_body_returns_http_disconnect():
    event = falcon.async_to_sync(falcon.idempotency._disconnect)
    assert event == {'type': 'http.disconnect'}


def test_completed_response_requires_current_owner(tmp_path):
    store = SQLiteIdempotencyStore(tmp_path / 'idempotency.sqlite3')
    store.begin(
        user_scope='alice',
        route='/items',
        idempotency_key='owner',
        request_fingerprint='fingerprint',
    )

    assert not store.complete(
        user_scope='alice',
        route='/items',
        idempotency_key='owner',
        owner_id='wrong-owner',
        response=StoredIdempotentResponse(200, (), b'ok'),
    )
    store.close()


def test_release_unknown_returns_false_for_other_states(tmp_path):
    store = SQLiteIdempotencyStore(tmp_path / 'idempotency.sqlite3')
    result = store.begin(
        user_scope='alice',
        route='/items',
        idempotency_key='processing',
        request_fingerprint='fingerprint',
    )

    assert not store.release_unknown(
        user_scope='alice',
        route='/items',
        idempotency_key='processing',
        confirmed=True,
    )
    assert result.owner_id is not None
    store.close()


def test_write_transaction_rolls_back_on_error(tmp_path):
    store = SQLiteIdempotencyStore(tmp_path / 'idempotency.sqlite3')
    store.begin(
        user_scope='alice',
        route='/items',
        idempotency_key='rollback',
        request_fingerprint='fingerprint',
    )
    connection = store._connect()

    class FailingConnection:
        execute = connection.execute

        def commit(self):
            raise sqlite3.Error('forced')

        def rollback(self):
            connection.rollback()

    store._connections.connection = FailingConnection()

    with pytest.raises(sqlite3.Error):
        store.begin(
            user_scope='alice',
            route='/items',
            idempotency_key='rollback',
            request_fingerprint='fingerprint',
        )
    store._connections.connection = None
