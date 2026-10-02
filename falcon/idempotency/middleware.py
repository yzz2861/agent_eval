"""WSGI middleware implementing optional Idempotency-Key support.

The middleware targets non-streaming responses with a bounded size. It makes
retried POST requests safe against duplicate responder execution: the first
request claims a key in a shared store and executes the responder; concurrent
duplicates receive a 409 in-progress response; later retries replay the
stored status code, headers and raw body without invoking the responder again.

If the request that owns a key disappears before its result is committed, the
key is eventually marked unknown and stays blocked. The middleware never
guesses that the responder had no side effects and never retries it in the
background; the caller must reconcile the outcome and an administrator must
release the key.
"""

from __future__ import annotations

from collections.abc import Callable
import hashlib
import io
import threading
from typing import Optional

from falcon import errors as http_errors
from falcon.idempotency.errors import IdempotencyInProgress
from falcon.idempotency.errors import IdempotencyKeyReused
from falcon.idempotency.errors import IdempotencyResultUnknown
from falcon.idempotency.store import FingerprintMismatch
from falcon.idempotency.store import IdempotencyRecord
from falcon.idempotency.store import SQLiteIdempotencyStore
from falcon.idempotency.store import STATE_PROCESSING
from falcon.idempotency.store import STATE_REPLAY
from falcon.idempotency.store import STATE_UNKNOWN
from falcon.request import Request
from falcon.response import Response

ScopeProvider = Callable[[Request], Optional[str]]

_EXCLUDED_HEADERS = frozenset(
    [
        'connection',
        'content-length',
        'date',
        'keep-alive',
        'proxy-authenticate',
        'proxy-authorization',
        'te',
        'trailer',
        'transfer-encoding',
        'upgrade',
    ]
)


class _Claim:
    """Per-request bookkeeping for a key claimed by this middleware."""

    __slots__ = ('scope', 'route', 'key', 'owner', 'stop_event', 'thread')

    def __init__(self, scope: str, route: str, key: str, owner: str) -> None:
        self.scope = scope
        self.route = route
        self.key = key
        self.owner = owner
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None


def _default_scope(req: Request) -> str | None:
    """Return the Authorization header as the default user scope."""
    return req.auth


def _is_asgi(req: Request) -> bool:
    """Return True for an ASGI request given to this WSGI-only middleware."""
    return req.__class__.__module__.startswith('falcon.asgi.')


class IdempotencyKeyMiddleware:
    """Optional WSGI middleware that deduplicates keyed POST requests.

    Only WSGI (synchronous) applications are currently supported; the
    middleware must not be added to an ASGI application.

    Keyword Args:
        store (SQLiteIdempotencyStore): Shared record store. A single store
            instance (and its database file) may be shared by every
            application process serving the API.
        key_header (str): Header carrying the idempotency key (default
            Idempotency-Key).
        methods (tuple[str, ...]): HTTP methods to protect (default POST).
        scope_provider (callable | None): Returns the user/security scope for
            a request. Requests for which it returns None pass through
            unprotected. Defaults to the Authorization header value.
        max_request_bytes (int): Maximum accepted request body size while
            fingerprinting (default 1 MiB). Larger bodies get 413.
        max_response_bytes (int): Maximum response body that may be recorded
            and replayed (default 1 MiB). Streaming or oversized responses are
            rejected as unsupported and the key is marked unknown.
        replay_headers (tuple[str, ...] | None): Response headers to replay.
            None replays every header except hop-by-hop and content-length
            headers; cookies are never replayed.
        heartbeat_interval (float | None): Lease renewal interval while the
            responder runs. Defaults to one third of the store lease; pass 0
            to disable the heartbeat (mainly useful in tests).

    """

    def __init__(
        self,
        *,
        store: SQLiteIdempotencyStore,
        key_header: str = 'Idempotency-Key',
        methods: tuple[str, ...] = ('POST',),
        scope_provider: ScopeProvider | None = None,
        max_request_bytes: int = 1024 * 1024,
        max_response_bytes: int = 1024 * 1024,
        replay_headers: tuple[str, ...] | None = None,
        heartbeat_interval: float | None = None,
    ) -> None:
        if max_request_bytes <= 0:
            raise ValueError('max_request_bytes must be positive')
        if max_response_bytes <= 0:
            raise ValueError('max_response_bytes must be positive')

        self._store = store
        self._key_header = key_header
        self._methods = frozenset(method.upper() for method in methods)
        self._scope_provider = scope_provider or _default_scope
        self._max_request_bytes = max_request_bytes
        self._max_response_bytes = max_response_bytes
        self._replay_headers = (
            None
            if replay_headers is None
            else frozenset(name.lower() for name in replay_headers)
        )
        if heartbeat_interval is None:
            self._heartbeat_interval = store.lease_seconds / 3.0
        else:
            if heartbeat_interval < 0:
                raise ValueError('heartbeat_interval must be non-negative or None')
            self._heartbeat_interval = heartbeat_interval

    def process_request(self, req: Request, resp: Response) -> None:
        """Buffer the body and stash the idempotency claim inputs."""
        if _is_asgi(req):
            raise http_errors.CompatibilityError(
                'IdempotencyKeyMiddleware only supports WSGI applications.'
            )

        req.context._idempotency_claim = None
        req.context._idempotency_scope = None

        if req.method not in self._methods:
            return

        key = req.get_header(self._key_header)
        if not key:
            return

        scope = self._scope_provider(req)
        if scope is None:
            return

        declared_length = req.content_length or 0
        if declared_length > self._max_request_bytes:
            raise http_errors.HTTPContentTooLarge(
                title='413 Payload Too Large',
                description=(
                    'The request body exceeds the maximum size accepted for '
                    'idempotent requests.'
                ),
            )

        body = req.bounded_stream.read(self._max_request_bytes + 1)
        if len(body) > self._max_request_bytes:
            raise http_errors.HTTPContentTooLarge(  # pragma: no cover
                title='413 Payload Too Large',
                description=(
                    'The request body exceeds the maximum size accepted for '
                    'idempotent requests.'
                ),
            )

        # Rewind the body so the responder (and media handlers) can read it.
        req._bounded_stream = io.BytesIO(body)

        digest = hashlib.sha256()
        digest.update(body)
        content_type = req.content_type or ''
        digest.update(b'\x00')
        digest.update(content_type.encode('latin-1', 'replace'))

        req.context._idempotency_scope = scope
        req.context._idempotency_key = key
        req.context._idempotency_fingerprint = digest.digest()

    def process_resource(
        self,
        req: Request,
        resp: Response,
        resource: object,
        params: dict,
    ) -> None:
        """Claim the key after routing, or replay/invalidate the request."""
        scope = getattr(req.context, '_idempotency_scope', None)
        if scope is None:
            return

        key = req.context._idempotency_key
        route = req.uri_template or req.path
        fingerprint = req.context._idempotency_fingerprint

        try:
            result = self._store.acquire(scope, route, key, fingerprint)
        except FingerprintMismatch as ex:
            raise IdempotencyKeyReused() from ex

        if result.state == STATE_REPLAY:
            assert result.record is not None
            self._replay(result.record, resp)
            return

        if result.state == STATE_PROCESSING:
            assert result.record is not None
            retry_after = self._heartbeat_interval
            raise IdempotencyInProgress(retry_after=float(retry_after))

        if result.state == STATE_UNKNOWN:
            raise IdempotencyResultUnknown()

        assert result.owner is not None
        claim = _Claim(scope, route, key, result.owner)
        req.context._idempotency_claim = claim
        self._start_heartbeat(claim)

    def _replay(self, record: IdempotencyRecord, resp: Response) -> None:
        """Rebuild a stored response without invoking the responder."""
        resp.status_code = record.status_code

        if record.headers:
            for name, value in record.headers:
                if self._should_replay_header(name):
                    resp.set_header(name, value)

        resp.data = record.body or b''
        resp.complete = True

    def _should_replay_header(self, name: str) -> bool:
        lower = name.lower()
        if lower.startswith('set-cookie'):
            return False
        if self._replay_headers is not None:
            return lower in self._replay_headers
        return lower not in _EXCLUDED_HEADERS

    def _start_heartbeat(self, claim: _Claim) -> None:
        interval = self._heartbeat_interval
        if interval is None or interval == 0:
            return

        def run() -> None:
            while not claim.stop_event.wait(interval):
                renewed = self._store.renew_lease(
                    claim.scope, claim.route, claim.key, claim.owner
                )
                if not renewed:
                    return

        thread = threading.Thread(
            target=run,
            name='falcon-idempotency-heartbeat',
            daemon=True,
        )
        claim.thread = thread
        thread.start()

    def process_response(
        self,
        req: Request,
        resp: Response,
        resource: object,
        req_succeeded: bool,
    ) -> None:
        """Commit the recorded response or quarantine an unsafe result."""
        claim = getattr(req.context, '_idempotency_claim', None)
        if claim is None:
            return

        self._stop_heartbeat(claim)

        if not req_succeeded:
            self._store.mark_unknown(claim.scope, claim.route, claim.key, claim.owner)
            raise IdempotencyResultUnknown()

        if resp.stream is not None:
            self._store.mark_unknown(claim.scope, claim.route, claim.key, claim.owner)
            raise _UnsupportedIdempotentResponse(
                'Streaming responses can not be recorded for replay.'
            )

        body = resp.render_body()
        if body is None:
            body = b''

        if len(body) > self._max_response_bytes:
            self._store.mark_unknown(claim.scope, claim.route, claim.key, claim.owner)
            raise _UnsupportedIdempotentResponse(
                'The response body exceeds the configured replay size limit.'
            )

        headers = self._collect_headers(resp)
        committed = self._store.complete(
            claim.scope,
            claim.route,
            claim.key,
            claim.owner,
            resp.status_code,
            headers,
            body,
        )
        if not committed:
            raise IdempotencyResultUnknown()

    def _collect_headers(self, resp: Response) -> list[tuple[str, str]]:
        headers: list[tuple[str, str]] = []
        for name, value in resp.headers.items():
            if self._should_replay_header(name):
                headers.append((name, value))
        return headers

    @staticmethod
    def _stop_heartbeat(claim: _Claim) -> None:
        claim.stop_event.set()
        thread = claim.thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=1.0)


class _UnsupportedIdempotentResponse(http_errors.HTTPInternalServerError):
    """500 raised when a response cannot be safely recorded for replay."""
