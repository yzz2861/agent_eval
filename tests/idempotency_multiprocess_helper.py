"""Helper worker for the multi-process idempotency tests.

It invokes a Falcon WSGI app in a separate process against the same SQLite
database file, avoiding sockets (which are restricted in the test sandbox).

Usage:
    python idempotency_multiprocess_helper.py DB_PATH MODE OUT_PATH
"""

from __future__ import annotations

import io
import json
import os
import sys
import time

import falcon
from falcon.idempotency import IdempotencyKeyMiddleware
from falcon.idempotency import SQLiteIdempotencyStore


def _call_wsgi(app, body: bytes = b'{}'):
    environ = {
        'REQUEST_METHOD': 'POST',
        'PATH_INFO': '/orders',
        'SERVER_NAME': 'test',
        'SERVER_PORT': '80',
        'wsgi.url_scheme': 'http',
        'wsgi.input': io.BytesIO(body),
        'wsgi.errors': sys.stderr,
        'wsgi.multithread': False,
        'wsgi.multiprocess': True,
        'wsgi.run_once': False,
        'CONTENT_TYPE': 'application/json',
        'CONTENT_LENGTH': str(len(body)),
        'HTTP_AUTHORIZATION': 'Bearer user-1',
        'HTTP_IDEMPOTENCY_KEY': 'shared-key',
    }
    captured = {}

    def start_response(status, headers, exc_info=None):
        captured['status'] = status
        captured['headers'] = headers

    chunks = app(environ, start_response)
    return captured['status'], captured['headers'], b''.join(chunks)


def main() -> None:
    db_path, mode, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    calls_path = os.path.join(os.path.dirname(db_path), 'business-calls.txt')
    lease = float(os.environ.get('IDEMPOTENCY_TEST_LEASE', '30.0'))
    store = SQLiteIdempotencyStore(db_path, lease_seconds=lease)

    class Resource:
        def on_post(self, req, resp):
            with open(calls_path, 'a', encoding='ascii') as handle:
                handle.write('x')

            if mode == 'owner':
                time.sleep(float(os.environ.get('IDEMPOTENCY_OWNER_DELAY', '0')))
                resp.status = falcon.HTTP_201
                resp.data = b'shared-result'
            elif mode == 'crash':
                # Side effect recorded above; exit before committing result.
                os._exit(2)
            else:
                resp.status = falcon.HTTP_200

    app = falcon.App(middleware=[IdempotencyKeyMiddleware(store=store)])
    app.add_route('/orders', Resource())

    try:
        status, headers, body = _call_wsgi(app)
        result = {
            'status': int(status.split(' ', 1)[0]),
            'headers': dict(headers),
            'body': body.decode('utf-8', 'replace'),
        }
    except Exception as ex:  # pragma: no cover - surfaced in test output
        result = {'error': repr(ex)}

    with open(out_path, 'w', encoding='utf-8') as handle:
        json.dump(result, handle)


if __name__ == '__main__':
    main()
