from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any


class PushedAuthorizationRequestStorageStatus(str, Enum):
    NOT_FOUND = "not_found"
    EXPIRED = "expired"
    WRONG_CLIENT = "wrong_client"
    ALREADY_CONSUMED = "already_consumed"


@dataclass(frozen=True)
class PushedAuthorizationRequest:
    request_uri: str
    client_id: str
    parameters: dict[str, Any]
    expires_at: int


class PushedAuthorizationRequestStorage:
    """Abstract storage for pushed authorization requests.

    ``consume`` MUST atomically return and invalidate one request URI. That
    makes duplicate authorization requests fail even when they arrive at the
    same time.
    """

    def save(self, pushed_request: PushedAuthorizationRequest, expires_in: int):
        raise NotImplementedError()

    def consume(
        self, request_uri: str, client_id: str | None
    ) -> PushedAuthorizationRequest | PushedAuthorizationRequestStorageStatus:
        raise NotImplementedError()


class LocalPushedAuthorizationRequestStorage(PushedAuthorizationRequestStorage):
    """Process-local pushed request storage with atomic replay protection."""

    def __init__(self, cleanup_threshold: int = 1000):
        self.cleanup_threshold = cleanup_threshold
        self._items: dict[str, tuple[PushedAuthorizationRequest, bool]] = {}
        self._lock = threading.Lock()

    def save(self, pushed_request: PushedAuthorizationRequest, expires_in: int):
        with self._lock:
            self._cleanup_if_needed()
            self._items[pushed_request.request_uri] = (pushed_request, False)

    def consume(
        self, request_uri: str, client_id: str | None
    ) -> PushedAuthorizationRequest | PushedAuthorizationRequestStorageStatus:
        with self._lock:
            item = self._items.get(request_uri)
            if item is None:
                return PushedAuthorizationRequestStorageStatus.NOT_FOUND

            pushed_request, consumed = item
            now = int(time.time())
            if pushed_request.expires_at <= now:
                self._items.pop(request_uri, None)
                return PushedAuthorizationRequestStorageStatus.EXPIRED

            if client_id is not None and pushed_request.client_id != client_id:
                return PushedAuthorizationRequestStorageStatus.WRONG_CLIENT

            if consumed:
                return PushedAuthorizationRequestStorageStatus.ALREADY_CONSUMED

            self._items[request_uri] = (pushed_request, True)
            return pushed_request

    def _cleanup_if_needed(self):
        if len(self._items) < self.cleanup_threshold:
            return

        now = int(time.time())
        for request_uri, (pushed_request, consumed) in list(self._items.items()):
            if consumed or pushed_request.expires_at <= now:
                self._items.pop(request_uri, None)
