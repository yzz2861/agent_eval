"""Idempotency-Key support for safe HTTP retries.

This package provides optional building blocks for making non-streaming,
size-bounded WSGI responses safely retryable with an ``Idempotency-Key``
request header. The canonical implementation is backed by SQLite so that the
same store may be shared by multiple application processes.
"""

from .errors import IdempotencyInProgress
from .errors import IdempotencyKeyReused
from .errors import IdempotencyResultUnknown
from .middleware import IdempotencyKeyMiddleware
from .store import IdempotencyRecord
from .store import IdempotencyStatus
from .store import SQLiteIdempotencyStore

__all__ = (
    'IdempotencyInProgress',
    'IdempotencyKeyMiddleware',
    'IdempotencyKeyReused',
    'IdempotencyRecord',
    'IdempotencyResultUnknown',
    'IdempotencyStatus',
    'SQLiteIdempotencyStore',
)
