"""
Stores custom jsonpickle errors.
"""

from typing import Any


class ClassNotFoundError(BaseException):
    def __init__(*args: Any, **kwargs: Any):
        pass


class DecodeError(Exception):
    """Base class for errors raised while decoding a jsonpickle payload."""


class GraphBudgetExceededError(DecodeError):
    """Raised when a decoded object graph exceeds a configured budget.

    The graph is never truncated; the decode is aborted as soon as one of
    the per-decode budgets (object count, reference table size, nesting
    depth, container width or elapsed time) is exceeded.
    """


class InvalidReferenceError(DecodeError):
    """Raised when a ``py/id`` entry cannot resolve to a known object.

    References may only point at ids that have already been registered
    earlier in the payload. Forward references, dangling ids and ids of
    the wrong type are rejected instead of being turned into proxies or
    silently replaced by ``None``.
    """
