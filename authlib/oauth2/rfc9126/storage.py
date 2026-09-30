import threading
import time

from .models import PushedAuthorizationRequestInfo
from .models import PushedAuthorizationRequestNotFoundError


class PushedAuthorizationRequestStorage:
    """Storage interface for pushed authorization requests."""

    def save(self, request_uri, client_id, data, expires_at):
        raise NotImplementedError()

    def consume(self, request_uri, client_id=None):
        """Atomically fetch and remove a pushed authorization request.

        Expired and already consumed requests MUST be removed. Raise
        :class:`PushedAuthorizationRequestNotFoundError` when the request is
        unavailable, including when it is bound to another client.
        """
        raise NotImplementedError()


class InMemoryPushedAuthorizationRequestStorage(PushedAuthorizationRequestStorage):
    """Thread-safe local storage suitable for single-process applications."""

    def __init__(self):
        self._requests = {}
        self._lock = threading.RLock()

    def save(self, request_uri, client_id, data, expires_at):
        request = PushedAuthorizationRequestInfo(
            request_uri=request_uri,
            client_id=client_id,
            data=data,
            expires_at=expires_at,
        )
        with self._lock:
            self._requests[request_uri] = request
        return request

    def consume(self, request_uri, client_id=None):
        with self._lock:
            request = self._requests.pop(request_uri, None)
            if request is None:
                raise PushedAuthorizationRequestNotFoundError(request_uri)
            if client_id is not None and request.get_client_id() != client_id:
                raise PushedAuthorizationRequestNotFoundError(request_uri)
            if request.get_expires_at() < time.time():
                raise PushedAuthorizationRequestNotFoundError(request_uri)
            return request
