import falcon
from falcon.idempotency import IdempotencyDecision
from falcon.idempotency import IdempotencyMiddleware
from falcon.idempotency import SQLiteIdempotencyStore
from falcon.idempotency import StoredIdempotentResponse


async def scope(req):
    return 'alice'


def sync_scope(req):
    return 'alice'


def test_disabled_wal_and_in_memory_database(tmp_path):
    file_store = SQLiteIdempotencyStore(
        tmp_path / 'idempotency.sqlite3', enable_wal=False
    )
    file_result = file_store.begin(
        user_scope='alice',
        route='/items',
        idempotency_key='file',
        request_fingerprint='fingerprint',
    )
    assert file_result.is_new
    file_store.close()

    memory_store = SQLiteIdempotencyStore(':memory:')
    memory_result = memory_store.begin(
        user_scope='alice',
        route='/items',
        idempotency_key='memory',
        request_fingerprint='fingerprint',
    )
    assert memory_result.is_new
    memory_store.close()


def test_begin_replaces_expired_completed_record(tmp_path):
    clock = [100.0]
    store = SQLiteIdempotencyStore(
        tmp_path / 'idempotency.sqlite3',
        result_ttl_seconds=10.0,
        clock=lambda: clock[0],
    )
    first = store.begin(
        user_scope='alice',
        route='/items',
        idempotency_key='expired',
        request_fingerprint='fingerprint',
    )
    store.complete(
        user_scope='alice',
        route='/items',
        idempotency_key='expired',
        owner_id=first.owner_id,
        response=StoredIdempotentResponse(200, (), b'ok'),
    )
    clock[0] = 111.0
    result = store.begin(
        user_scope='alice',
        route='/items',
        idempotency_key='expired',
        request_fingerprint='fingerprint',
    )
    assert result.is_new
    store.close()


def test_existing_store_instance_initializes_schema_without_race(tmp_path):
    first = SQLiteIdempotencyStore(tmp_path / 'shared.sqlite3')
    first.begin(
        user_scope='alice',
        route='/items',
        idempotency_key='warm',
        request_fingerprint='fingerprint',
    )
    second = SQLiteIdempotencyStore(tmp_path / 'shared.sqlite3')
    result = second.begin(
        user_scope='alice',
        route='/items',
        idempotency_key='second',
        request_fingerprint='fingerprint',
    )
    assert result.is_new
    first.close()
    second.close()


def test_empty_chunked_asgi_request_terminates_while_loop(tmp_path):
    store = SQLiteIdempotencyStore(tmp_path / 'idempotency.sqlite3')
    app = falcon.asgi.App(middleware=IdempotencyMiddleware(store, user_scope=scope))

    class EmptyResource:
        async def on_post(self, req, resp):
            assert await req.bounded_stream.read(16) == b''
            resp.data = b''

    app.add_route('/items', EmptyResource())
    scope_data = falcon.testing.create_scope(
        path='/items',
        method='POST',
        headers={'Idempotency-Key': 'empty', 'X-User': 'alice'},
    )
    receive = falcon.testing.ASGIRequestEventEmitter(b'')
    collector = falcon.testing.ASGIResponseEventCollector()

    falcon.async_to_sync(app, scope_data, receive.emit, collector)

    assert collector.status == 200
    store.close()


def test_complete_returns_false_after_lease_becomes_unknown(tmp_path):
    clock = [100.0]
    store = SQLiteIdempotencyStore(
        tmp_path / 'idempotency.sqlite3',
        processing_lease_seconds=1.0,
        clock=lambda: clock[0],
    )
    first = store.begin(
        user_scope='alice',
        route='/items',
        idempotency_key='race',
        request_fingerprint='fingerprint',
    )
    clock[0] = 102.0
    later = store.begin(
        user_scope='alice',
        route='/items',
        idempotency_key='race',
        request_fingerprint='fingerprint',
    )
    assert later.decision is IdempotencyDecision.UNKNOWN
    assert not store.complete(
        user_scope='alice',
        route='/items',
        idempotency_key='race',
        owner_id=first.owner_id,
        response=StoredIdempotentResponse(200, (), b'ok'),
    )
    store.close()


def test_middleware_complete_false_returns_unknown_conflict(tmp_path):
    store = SQLiteIdempotencyStore(tmp_path / 'idempotency.sqlite3')
    middleware = IdempotencyMiddleware(store, user_scope=sync_scope)
    req = falcon.testing.create_req(method='POST', path='/items', body=b'{}')
    resp = falcon.Response()
    req.__dict__['_falcon_idempotency'] = {
        'user_scope': 'alice',
        'route': '/items',
        'idempotency_key': 'lost-owner',
        'owner_id': 'does-not-exist',
    }
    resp.data = b'ok'

    try:
        middleware.process_response(req, resp, None, True)
    except falcon.HTTPConflict as ex:
        assert ex.status == falcon.HTTP_409
        assert ('Idempotency-Status', 'unknown') in ex.headers
    else:
        raise AssertionError('Expected HTTPConflict')

    store.close()
