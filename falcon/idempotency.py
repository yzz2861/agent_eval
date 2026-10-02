"""SQLite-backed idempotency-key support for bounded HTTP APIs."""

from __future__ import annotations

from collections.abc import Awaitable
from collections.abc import Callable
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import enum
import hashlib
import inspect
import io
import json
import os
import sqlite3
import threading
import time
from typing import Any, cast, TYPE_CHECKING, Union
import uuid

from falcon import errors
from falcon.asgi.stream import BoundedStream as AsgiBoundedStream
from falcon.stream import BoundedStream as WsgiBoundedStream
from falcon.util.sync import sync_to_async

if TYPE_CHECKING:
    from falcon.asgi.request import Request as AsgiRequest
    from falcon.asgi.response import Response as AsgiResponse
    from falcon.request import Request
    from falcon.response import Response

__all__ = (
    'IdempotencyDecision',
    'IdempotencyMiddleware',
    'IdempotencyState',
    'SQLiteIdempotencyStore',
    'StoredIdempotentResponse',
    'StoredIdempotentResult',
)

UserScopeProvider = Callable[[Any], Union[str, Awaitable[str]]]

IDEMPOTENCY_KEY_HEADER = 'Idempotency-Key'
IDEMPOTENCY_STATUS_HEADER = 'Idempotency-Status'
IDEMPOTENCY_REPLAYED_HEADER = 'Idempotency-Replayed'

DEFAULT_KEY_HEADER = IDEMPOTENCY_KEY_HEADER
DEFAULT_MAX_REQUEST_BODY_SIZE = 1024 * 1024
DEFAULT_MAX_RESPONSE_BODY_SIZE = 1024 * 1024
DEFAULT_PROCESSING_LEASE_SECONDS = 60.0
DEFAULT_RESULT_TTL_SECONDS = 24 * 60 * 60.0

_HOP_BY_HOP_HEADERS = frozenset(
    (
        'connection',
        'content-length',
        'keep-alive',
        'proxy-authenticate',
        'proxy-authorization',
        'te',
        'trailer',
        'transfer-encoding',
        'upgrade',
    )
)


class IdempotencyState(str, enum.Enum):
    """Persisted state for an idempotency key."""

    PROCESSING = 'processing'
    COMPLETED = 'completed'
    UNKNOWN = 'unknown'


class IdempotencyDecision(str, enum.Enum):
    """Decision returned when an idempotent request is acquired."""

    NEW = 'new'
    PROCESSING = 'processing'
    COMPLETED = 'completed'
    UNKNOWN = 'unknown'
    FINGERPRINT_MISMATCH = 'fingerprint_mismatch'


@dataclass(frozen=True)
class StoredIdempotentResponse:
    """HTTP response persisted for a completed idempotent request."""

    status_code: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


@dataclass(frozen=True)
class StoredIdempotentResult:
    """Result of acquiring an idempotency key from the store."""

    decision: IdempotencyDecision
    owner_id: str | None = None
    response: StoredIdempotentResponse | None = None

    @property
    def is_new(self) -> bool:
        """Return whether the caller owns a newly created processing record."""

        return self.decision is IdempotencyDecision.NEW


class SQLiteIdempotencyStore:
    """Persist idempotency records in a SQLite database.

    The database is safe to share among application processes when it resides
    on a local filesystem. WAL mode and a busy timeout are enabled by default.

    Args:
        database: Path to the SQLite database file. In-memory databases are
            supported, but they are not shared between connections.
        processing_lease_seconds: Age after which an abandoned processing
            record is interpreted as result-unknown. This should exceed the
            responder's maximum expected duration.
        result_ttl_seconds: Lifetime assigned to completed response records.
        busy_timeout_milliseconds: SQLite busy timeout.
        enable_wal: Enable WAL journaling for file-based databases.
        clock: Injectable wall-clock function returning POSIX seconds.
    """

    def __init__(
        self,
        database: str | os.PathLike[str],
        *,
        processing_lease_seconds: float = DEFAULT_PROCESSING_LEASE_SECONDS,
        result_ttl_seconds: float = DEFAULT_RESULT_TTL_SECONDS,
        busy_timeout_milliseconds: int = 5000,
        enable_wal: bool = True,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._database = os.fspath(database)
        self._processing_lease_seconds = processing_lease_seconds
        self._result_ttl_seconds = result_ttl_seconds
        self._busy_timeout_milliseconds = busy_timeout_milliseconds
        self._enable_wal = enable_wal
        self._clock = clock
        self._connections = threading.local()
        self._schema_lock = threading.Lock()
        self._schema_ready = False

    def _connect(self) -> sqlite3.Connection:
        """Return the SQLite connection for the current thread."""

        connection = getattr(self._connections, 'connection', None)
        if connection is not None:
            return cast(sqlite3.Connection, connection)

        connection = sqlite3.connect(
            self._database,
            timeout=self._busy_timeout_milliseconds / 1000.0,
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        self._configure(connection)
        self._initialize_schema(connection)
        self._connections.connection = connection
        return connection

    def _configure(self, connection: sqlite3.Connection) -> None:
        """Configure a newly opened SQLite connection."""

        connection.execute(
            f'PRAGMA busy_timeout = {int(self._busy_timeout_milliseconds)}'
        )
        if self._enable_wal and self._database != ':memory:':
            connection.execute('PRAGMA journal_mode = WAL')

    @contextmanager
    def _write_transaction(self, connection: sqlite3.Connection) -> Iterator[None]:
        """Manage an immediate SQLite write transaction."""

        connection.execute('BEGIN IMMEDIATE')
        try:
            yield
            connection.commit()
        except Exception:
            connection.rollback()
            raise

    def _initialize_schema(self, connection: sqlite3.Connection) -> None:
        """Create the idempotency schema once for this store."""

        if self._schema_ready:
            return

        with self._schema_lock:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS idempotent_requests (
                    user_scope TEXT NOT NULL,
                    route TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    request_fingerprint TEXT NOT NULL,
                    state TEXT NOT NULL,
                    owner_id TEXT,
                    lease_expires_at REAL,
                    expires_at REAL,
                    response_status INTEGER,
                    response_headers TEXT,
                    response_body BLOB,
                    PRIMARY KEY (user_scope, route, idempotency_key)
                ) WITHOUT ROWID;

                CREATE INDEX IF NOT EXISTS idempotent_requests_expires_idx
                    ON idempotent_requests (state, expires_at);
                """
            )
            connection.commit()
            self._schema_ready = True

    @staticmethod
    def _load_response(row: sqlite3.Row) -> StoredIdempotentResponse:
        """Deserialize a completed response row."""

        headers = tuple(
            (str(name), str(value))
            for name, value in json.loads(row['response_headers'])
        )
        return StoredIdempotentResponse(
            row['response_status'], headers, bytes(row['response_body'])
        )

    def begin(
        self,
        *,
        user_scope: str,
        route: str,
        idempotency_key: str,
        request_fingerprint: str,
    ) -> StoredIdempotentResult:
        """Acquire an idempotency key or return its current persisted state."""

        now = self._clock()
        owner_id = uuid.uuid4().hex
        connection = self._connect()

        with self._write_transaction(connection):
            row = connection.execute(
                """
                SELECT request_fingerprint, state, lease_expires_at,
                       expires_at, response_status, response_headers,
                       response_body
                  FROM idempotent_requests
                 WHERE user_scope = ? AND route = ? AND idempotency_key = ?
                """,
                (user_scope, route, idempotency_key),
            ).fetchone()

            if row is None or self._is_expired_completed(row, now):
                if row is not None:
                    connection.execute(
                        """
                        DELETE FROM idempotent_requests
                         WHERE user_scope = ? AND route = ? AND idempotency_key = ?
                        """,
                        (user_scope, route, idempotency_key),
                    )
                self._insert_processing(
                    connection,
                    user_scope=user_scope,
                    route=route,
                    idempotency_key=idempotency_key,
                    request_fingerprint=request_fingerprint,
                    owner_id=owner_id,
                    now=now,
                )
                return StoredIdempotentResult(
                    IdempotencyDecision.NEW, owner_id=owner_id
                )

            state = IdempotencyState(row['state'])
            if row['request_fingerprint'] != request_fingerprint:
                decision = IdempotencyDecision.FINGERPRINT_MISMATCH
            elif state is IdempotencyState.PROCESSING:
                lease_expires_at = row['lease_expires_at']
                if lease_expires_at is not None and lease_expires_at <= now:
                    connection.execute(
                        """
                        UPDATE idempotent_requests
                           SET state = ?, owner_id = NULL,
                               lease_expires_at = NULL
                         WHERE user_scope = ?
                           AND route = ?
                           AND idempotency_key = ?
                        """,
                        (
                            IdempotencyState.UNKNOWN.value,
                            user_scope,
                            route,
                            idempotency_key,
                        ),
                    )
                    decision = IdempotencyDecision.UNKNOWN
                else:
                    decision = IdempotencyDecision.PROCESSING
            else:
                decision = IdempotencyDecision(state.value)

            response = None
            if decision is IdempotencyDecision.COMPLETED:
                response = self._load_response(row)

            return StoredIdempotentResult(decision, response=response)

    @staticmethod
    def _is_expired_completed(row: sqlite3.Row, now: float) -> bool:
        """Return whether a completed row has passed its result TTL."""

        return (
            row['state'] == IdempotencyState.COMPLETED.value
            and row['expires_at'] is not None
            and row['expires_at'] <= now
        )

    def _insert_processing(
        self,
        connection: sqlite3.Connection,
        *,
        user_scope: str,
        route: str,
        idempotency_key: str,
        request_fingerprint: str,
        owner_id: str,
        now: float,
    ) -> None:
        """Insert a record in the processing state."""

        connection.execute(
            """
            INSERT INTO idempotent_requests (
                user_scope, route, idempotency_key, request_fingerprint,
                state, owner_id, lease_expires_at, expires_at,
                response_status, response_headers, response_body
            ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL)
            """,
            (
                user_scope,
                route,
                idempotency_key,
                request_fingerprint,
                IdempotencyState.PROCESSING.value,
                owner_id,
                now + self._processing_lease_seconds,
            ),
        )

    def complete(
        self,
        *,
        user_scope: str,
        route: str,
        idempotency_key: str,
        owner_id: str,
        response: StoredIdempotentResponse,
    ) -> bool:
        """Persist a response if the caller still owns this processing record."""

        now = self._clock()
        connection = self._connect()
        with self._write_transaction(connection):
            cursor = connection.execute(
                """
                UPDATE idempotent_requests
                   SET state = ?,
                       owner_id = NULL,
                       lease_expires_at = NULL,
                       expires_at = ?,
                       response_status = ?,
                       response_headers = ?,
                       response_body = ?
                 WHERE user_scope = ?
                   AND route = ?
                   AND idempotency_key = ?
                   AND state = ?
                   AND owner_id = ?
                """,
                (
                    IdempotencyState.COMPLETED.value,
                    now + self._result_ttl_seconds,
                    response.status_code,
                    json.dumps(response.headers, separators=(',', ':')),
                    response.body,
                    user_scope,
                    route,
                    idempotency_key,
                    IdempotencyState.PROCESSING.value,
                    owner_id,
                ),
            )
            return cursor.rowcount == 1

    def mark_unknown(
        self,
        *,
        user_scope: str,
        route: str,
        idempotency_key: str,
        owner_id: str,
    ) -> bool:
        """Mark a processing record as result-unknown for its current owner."""

        connection = self._connect()
        with self._write_transaction(connection):
            cursor = connection.execute(
                """
                UPDATE idempotent_requests
                   SET state = ?, owner_id = NULL, lease_expires_at = NULL,
                       expires_at = NULL, response_status = NULL,
                       response_headers = NULL, response_body = NULL
                 WHERE user_scope = ?
                   AND route = ?
                   AND idempotency_key = ?
                   AND state = ?
                   AND owner_id = ?
                """,
                (
                    IdempotencyState.UNKNOWN.value,
                    user_scope,
                    route,
                    idempotency_key,
                    IdempotencyState.PROCESSING.value,
                    owner_id,
                ),
            )
            return cursor.rowcount == 1

    def purge_expired(self, *, now: float | None = None) -> int:
        """Delete completed records whose result TTL has expired."""

        current_time = self._clock() if now is None else now
        connection = self._connect()
        with self._write_transaction(connection):
            cursor = connection.execute(
                """
                DELETE FROM idempotent_requests
                 WHERE state = ? AND expires_at IS NOT NULL AND expires_at <= ?
                """,
                (IdempotencyState.COMPLETED.value, current_time),
            )
            return int(cursor.rowcount)

    def release_unknown(
        self,
        *,
        user_scope: str,
        route: str,
        idempotency_key: str,
        confirmed: bool,
    ) -> bool:
        """Delete one unknown record after an administrator confirms safety."""

        if not confirmed:
            raise ValueError(
                'An unknown idempotency record may only be released after the '
                'business effect has been explicitly confirmed.'
            )

        connection = self._connect()
        with self._write_transaction(connection):
            cursor = connection.execute(
                """
                DELETE FROM idempotent_requests
                 WHERE user_scope = ?
                   AND route = ?
                   AND idempotency_key = ?
                   AND state = ?
                """,
                (
                    user_scope,
                    route,
                    idempotency_key,
                    IdempotencyState.UNKNOWN.value,
                ),
            )
            return cursor.rowcount == 1

    def close(self) -> None:
        """Close the SQLite connection associated with the current thread."""

        connection = getattr(self._connections, 'connection', None)
        if connection is not None:
            connection.close()
            self._connections.connection = None


async def _await_if_needed(value: Awaitable[str] | str) -> str:
    """Await a value when the configured user-scope provider is asynchronous."""

    if inspect.isawaitable(value):
        return await value
    return value


async def _disconnect() -> dict[str, str]:
    """Return an ASGI disconnect event for a cached request body."""

    return {'type': 'http.disconnect'}


class IdempotencyMiddleware:
    """Replay bounded POST responses identified by an idempotency key.

    Only non-streaming responses up to the configured size are stored.
    Records are namespaced by a caller-provided authenticated user scope and
    the matched route template. Request method, target, query string,
    Content-Type, and body form a fingerprint; reuse of a key with different
    content is rejected.

    Args:
        store: Shared SQLite idempotency store.
        user_scope: Callable returning the authenticated user scope for a
            request. It may be a synchronous or asynchronous callable.
        key_header: Header containing the client's idempotency key.
        max_request_body_size: Maximum request body size in bytes.
        max_response_body_size: Maximum stored response body size in bytes.
        methods: HTTP methods handled by this middleware.
    """

    def __init__(
        self,
        store: SQLiteIdempotencyStore,
        *,
        user_scope: UserScopeProvider,
        key_header: str = DEFAULT_KEY_HEADER,
        max_request_body_size: int = DEFAULT_MAX_REQUEST_BODY_SIZE,
        max_response_body_size: int = DEFAULT_MAX_RESPONSE_BODY_SIZE,
        methods: tuple[str, ...] = ('POST',),
    ) -> None:
        if max_request_body_size < 0:
            raise ValueError('max_request_body_size must not be negative.')
        if max_response_body_size < 0:
            raise ValueError('max_response_body_size must not be negative.')

        self._store = store
        self._user_scope = user_scope
        self._key_header = key_header
        self._max_request_body_size = max_request_body_size
        self._max_response_body_size = max_response_body_size
        self._methods = frozenset(method.upper() for method in methods)

    def process_resource(
        self,
        req: Request,
        resp: Response,
        resource: object,
        params: dict[str, Any],
    ) -> None:
        """Acquire a WSGI request or short-circuit with a stored response."""

        if req.method.upper() not in self._methods:
            return
        key = req.get_header(self._key_header)
        if key is None:
            return
        if not key:
            raise errors.HTTPBadRequest(
                title='Invalid Idempotency Key',
                description='The idempotency key header must not be empty.',
            )

        scope = self._user_scope(req)
        if inspect.isawaitable(scope):
            close = getattr(scope, 'close', None)
            if callable(close):
                close()
            raise errors.CompatibilityError(
                'An asynchronous user_scope provider requires the ASGI version '
                'of IdempotencyMiddleware.'
            )
        self._handle_resource(req, resp, key=key, user_scope=scope)

    async def process_resource_async(
        self,
        req: AsgiRequest,
        resp: AsgiResponse,
        resource: object,
        params: dict[str, Any],
    ) -> None:
        """Acquire an ASGI request or short-circuit with a stored response."""

        if req.method.upper() not in self._methods:
            return
        key = req.get_header(self._key_header)
        if key is None:
            return
        if not key:
            raise errors.HTTPBadRequest(
                title='Invalid Idempotency Key',
                description='The idempotency key header must not be empty.',
            )

        scope = await _await_if_needed(self._user_scope(req))
        await self._handle_resource_async(req, resp, key=key, user_scope=scope)

    def process_response(
        self,
        req: Request,
        resp: Response,
        resource: object | None,
        req_succeeded: bool,
    ) -> None:
        """Persist a bounded WSGI response or mark the result as unknown."""

        metadata = req.__dict__.get('_falcon_idempotency')
        if metadata is None:
            return
        if not req_succeeded and resp.status_code >= 500:
            self._store.mark_unknown(**metadata)
            return
        body = resp.render_body() or b''
        self._finish_response(req, resp, metadata=metadata, body=body)

    async def process_response_async(
        self,
        req: AsgiRequest,
        resp: AsgiResponse,
        resource: object | None,
        req_succeeded: bool,
    ) -> None:
        """Persist a bounded ASGI response or mark the result as unknown."""

        metadata = req.__dict__.get('_falcon_idempotency')
        if metadata is None:
            return
        if not req_succeeded and resp.status_code >= 500:
            await sync_to_async(self._store.mark_unknown, **metadata)
            return
        body = await resp.render_body()
        await sync_to_async(
            self._finish_response,
            req,
            resp,
            metadata=metadata,
            body=body or b'',
        )

    def _handle_resource(
        self, req: Request, resp: Response, *, key: str, user_scope: str
    ) -> None:
        """Read a bounded WSGI body and apply the store decision."""

        content_length = req.content_length
        if content_length is None:
            raise errors.HTTPLengthRequired(
                title='Content-Length Required',
                description='Idempotent requests must declare Content-Length.',
            )
        if content_length > self._max_request_body_size:
            raise errors.HTTPContentTooLarge(
                title='Request Body Too Large',
                description='The idempotency request body exceeds the configured '
                'maximum size.',
            )

        body = req.bounded_stream.read(content_length)
        req._bounded_stream = WsgiBoundedStream(io.BytesIO(body), len(body))
        req.stream = req._bounded_stream
        result = self._store.begin(
            user_scope=user_scope,
            route=self._route(req),
            idempotency_key=key,
            request_fingerprint=self._fingerprint(req, body),
        )
        self._apply_result(req, resp, key, user_scope, result)

    async def _handle_resource_async(
        self, req: AsgiRequest, resp: AsgiResponse, *, key: str, user_scope: str
    ) -> None:
        """Read a bounded ASGI body and apply the store decision."""

        content_length = req.content_length
        if content_length is not None:
            if content_length > self._max_request_body_size:
                raise errors.HTTPContentTooLarge(
                    title='Request Body Too Large',
                    description='The idempotency request body exceeds the '
                    'configured maximum size.',
                )
            body = await req.stream.read(content_length)
        else:
            body = await self._read_until_limit(req)

        req._stream = AsgiBoundedStream(_disconnect, content_length=len(body))
        req._stream._buffer = body
        req._stream._bytes_remaining = 0
        req._stream._pos = len(body)
        result = cast(
            StoredIdempotentResult,
            await sync_to_async(
                self._store.begin,
                user_scope=user_scope,
                route=self._route(req),
                idempotency_key=key,
                request_fingerprint=self._fingerprint(req, body),
            ),
        )
        self._apply_result(req, resp, key, user_scope, result)

    async def _read_until_limit(self, req: AsgiRequest) -> bytes:
        """Read a request without Content-Length until the configured limit."""

        chunks = []
        remaining = self._max_request_body_size + 1
        while remaining:
            chunk = await req.stream.read(remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        body = b''.join(chunks)
        if len(body) > self._max_request_body_size:
            raise errors.HTTPContentTooLarge(
                title='Request Body Too Large',
                description='The idempotency request body exceeds the configured '
                'maximum size.',
            )
        return body

    @staticmethod
    def _route(req: Request) -> str:
        """Return the route namespace for a matched request."""

        return req.uri_template or req.path

    @staticmethod
    def _fingerprint(req: Request, body: bytes) -> str:
        """Calculate the request fingerprint associated with an idempotency key."""

        digest = hashlib.sha256()
        for value in (
            req.method.upper(),
            req.path,
            req.query_string,
            req.content_type or '',
        ):
            digest.update(len(value).to_bytes(4, 'big'))
            digest.update(value.encode('utf-8'))
        digest.update(len(body).to_bytes(8, 'big'))
        digest.update(body)
        return digest.hexdigest()

    def _apply_result(
        self,
        req: Request,
        resp: Response,
        key: str,
        user_scope: str,
        result: StoredIdempotentResult,
    ) -> None:
        """Apply a store decision to the current request."""

        decision = result.decision
        if decision is IdempotencyDecision.NEW:
            owner_id = cast(str, result.owner_id)
            req.__dict__['_falcon_idempotency'] = {
                'user_scope': user_scope,
                'route': self._route(req),
                'idempotency_key': key,
                'owner_id': owner_id,
            }
            return

        if decision is IdempotencyDecision.COMPLETED:
            stored_response = cast(StoredIdempotentResponse, result.response)
            self._replay(resp, stored_response)
            resp.complete = True
            return

        if decision is IdempotencyDecision.FINGERPRINT_MISMATCH:
            raise errors.HTTPUnprocessableEntity(
                title='Idempotency Key Reuse',
                description='The same idempotency key was submitted with '
                'different request content.',
                headers=[(IDEMPOTENCY_STATUS_HEADER, 'fingerprint-mismatch')],
            )

        if decision is IdempotencyDecision.PROCESSING:
            raise errors.HTTPConflict(
                title='Request Processing',
                description='Another request with this idempotency key is still '
                'being processed.',
                headers=[(IDEMPOTENCY_STATUS_HEADER, 'processing')],
            )

        raise errors.HTTPConflict(
            title='Result Unknown',
            description='The original request stopped before its response was '
            'recorded. Verify the business effect before retrying or ask an '
            'administrator to release this key.',
            headers=[(IDEMPOTENCY_STATUS_HEADER, 'unknown')],
        )

    def _finish_response(
        self,
        req: Request,
        resp: Response,
        *,
        metadata: dict[str, str],
        body: bytes,
    ) -> None:
        """Validate and persist a response, or leave the result unknown."""

        if resp.stream is not None or getattr(resp, '_sse', None) is not None:
            self._store.mark_unknown(**metadata)
            raise errors.HTTPServiceUnavailable(
                title='Response Cannot Be Replayed',
                description='Streaming responses are not supported by the '
                'idempotency middleware.',
                headers=[(IDEMPOTENCY_STATUS_HEADER, 'unknown')],
            )

        if getattr(resp, '_registered_callbacks', None) is not None:
            self._store.mark_unknown(**metadata)
            raise errors.HTTPServiceUnavailable(
                title='Response Cannot Be Replayed',
                description='Responses with scheduled callbacks are not supported.',
                headers=[(IDEMPOTENCY_STATUS_HEADER, 'unknown')],
            )

        if len(body) > self._max_response_body_size:
            self._store.mark_unknown(**metadata)
            raise errors.HTTPServiceUnavailable(
                title='Response Too Large',
                description='The response exceeds the maximum idempotency replay size.',
                headers=[(IDEMPOTENCY_STATUS_HEADER, 'unknown')],
            )

        stored = StoredIdempotentResponse(
            status_code=resp.status_code,
            headers=self._capture_headers(resp, resp.options.default_media_type),
            body=body,
        )
        if not self._store.complete(response=stored, **metadata):
            raise errors.HTTPConflict(
                title='Result Unknown',
                description='The request owner expired before the response was '
                'recorded. Verify the business effect before retrying.',
                headers=[(IDEMPOTENCY_STATUS_HEADER, 'unknown')],
            )

    @staticmethod
    def _capture_headers(
        resp: Response, default_media_type: str
    ) -> tuple[tuple[str, str], ...]:
        """Capture replay-safe response headers."""

        return tuple(
            (name, value)
            for name, value in resp._wsgi_headers(default_media_type)
            if name.lower() not in _HOP_BY_HOP_HEADERS
        )

    @staticmethod
    def _replay(resp: Response, stored: StoredIdempotentResponse) -> None:
        """Replace the response with a stored response."""

        resp.status_code = stored.status_code
        resp._headers.clear()
        resp._extra_headers = None
        resp._cookies = None
        resp.text = None
        resp.data = stored.body
        resp.media = None
        resp.stream = None
        setattr(resp, '_sse', None)
        setattr(resp, '_registered_callbacks', None)

        for name, value in stored.headers:
            if name.lower() == 'set-cookie':
                resp.append_header(name, value)
            else:
                resp.set_header(name, value)
        resp.set_header(IDEMPOTENCY_REPLAYED_HEADER, 'true')
