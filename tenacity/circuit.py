import enum
import threading
import time
import typing as t

from ._utils import wrap_to_async_func
from .retry import retry_if_exception_type

if t.TYPE_CHECKING:
    import sys

    from .asyncio.retry import RetryBaseT as AsyncRetryBaseT
    from .retry import RetryBaseT as SyncRetryBaseT

    if sys.version_info >= (3, 11):
        from typing import Self
    else:
        from typing_extensions import Self

    FailurePredicate: t.TypeAlias = (
        SyncRetryBaseT | AsyncRetryBaseT | t.Callable[["RetryCallState"], t.Any]
    )
    RetryCallState = t.Any


class CircuitState(enum.Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerError(Exception):
    """Base class for circuit breaker failures."""


class CircuitBreakerOpenError(CircuitBreakerError):
    """Raised immediately when a call cannot obtain a circuit permit."""

    def __init__(self, breaker: "CircuitBreaker") -> None:
        self.breaker = breaker
        super().__init__(f"circuit breaker is {breaker.state.value}")


CircuitBreakerRejectedError = CircuitBreakerOpenError


def _is_cancellation(exception: BaseException) -> bool:
    import asyncio

    if isinstance(exception, asyncio.CancelledError):
        return True
    try:
        import trio
    except ImportError:
        return False
    return isinstance(exception, trio.Cancelled)


class CircuitBreakerPermit:
    """A single logical-call permit issued by a circuit breaker."""

    __slots__ = ("_breaker", "_generation", "_probe", "_recorded")

    def __init__(self, breaker: "CircuitBreaker", generation: int, probe: bool) -> None:
        self._breaker = breaker
        self._generation = generation
        self._probe = probe
        self._recorded = False

    @property
    def generation(self) -> int:
        return self._generation

    @property
    def probe(self) -> bool:
        return self._probe

    @property
    def recorded(self) -> bool:
        return self._recorded

    def record_success(self) -> None:
        if not self._recorded:
            self._recorded = True
            self._breaker.record_outcome(self._generation, False, False)

    def record_failure(self) -> None:
        if not self._recorded:
            self._recorded = True
            self._breaker.record_outcome(self._generation, True, False)

    def record_cancellation(self) -> None:
        if not self._recorded:
            self._recorded = True
            self._breaker.record_outcome(self._generation, False, True)

    def record_retry_state(
        self,
        retry_state: "RetryCallState",
        failure_predicate: "FailurePredicate | None" = None,
    ) -> None:
        outcome = retry_state.outcome
        if outcome is None:
            raise RuntimeError("record_retry_state() called before outcome was set")

        exception = outcome.exception() if outcome.failed else None
        if exception is not None and _is_cancellation(exception):
            self.record_cancellation()
            return

        predicate = failure_predicate or self._breaker.failure_predicate
        is_failure = bool(predicate(retry_state))
        if is_failure:
            self.record_failure()
        else:
            self.record_success()

    async def arecord_retry_state(
        self,
        retry_state: "RetryCallState",
        failure_predicate: "FailurePredicate | None" = None,
    ) -> None:
        outcome = retry_state.outcome
        if outcome is None:
            raise RuntimeError("record_retry_state() called before outcome was set")

        exception = outcome.exception() if outcome.failed else None
        if exception is not None and _is_cancellation(exception):
            self.record_cancellation()
            return

        predicate = wrap_to_async_func(
            failure_predicate or self._breaker.failure_predicate
        )
        is_failure = bool(await predicate(retry_state))
        if is_failure:
            self.record_failure()
        else:
            self.record_success()

    def __enter__(self) -> "Self":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: t.Any,
    ) -> None:
        if exc_value is None:
            self.record_success()
        elif _is_cancellation(exc_value) or not isinstance(exc_value, Exception):
            self.record_cancellation()
        else:
            self.record_failure()

    async def __aenter__(self) -> "Self":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: t.Any,
    ) -> None:
        self.__exit__(exc_type, exc_value, traceback)


class CircuitBreaker:
    """Share circuit state between synchronous and asynchronous callers."""

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        max_probes: int = 1,
        *,
        failure_predicate: "FailurePredicate | None" = None,
        clock: t.Callable[[], float] = time.monotonic,
        initial_state: CircuitState = CircuitState.CLOSED,
        **aliases: t.Any,
    ) -> None:
        failure_threshold = aliases.pop("threshold", failure_threshold)
        recovery_timeout = aliases.pop("timeout", recovery_timeout)
        max_probes = aliases.pop("max_concurrent_probes", max_probes)
        max_probes = aliases.pop("half_open_limit", max_probes)
        max_probes = aliases.pop("probe_limit", max_probes)
        if aliases:
            unknown = ", ".join(sorted(aliases))
            raise TypeError(f"unexpected keyword argument(s): {unknown}")
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be greater than zero")
        if recovery_timeout < 0:
            raise ValueError("recovery_timeout must not be negative")
        if max_probes < 1:
            raise ValueError("max_probes must be greater than zero")

        self.failure_threshold = failure_threshold
        self.recovery_timeout = float(recovery_timeout)
        self.max_probes = max_probes
        self.failure_predicate = failure_predicate or retry_if_exception_type()
        self._clock = clock
        self._lock = threading.Lock()
        self._state = initial_state
        self._failure_count = 0
        self._active_probes = 0
        self._generation = 0
        self._opened_at = clock() if initial_state is CircuitState.OPEN else 0.0

    @property
    def state(self) -> CircuitState:
        return self._state

    @property
    def failure_count(self) -> int:
        return self._failure_count

    @property
    def active_probes(self) -> int:
        return self._active_probes

    @property
    def generation(self) -> int:
        return self._generation

    def acquire(self) -> CircuitBreakerPermit:
        """Acquire a normal-call permit or a limited half-open probe."""
        with self._lock:
            if self._state is CircuitState.CLOSED:
                return CircuitBreakerPermit(self, self._generation, False)

            now = self._clock()
            if self._state is CircuitState.OPEN:
                if now < self._opened_at + self.recovery_timeout:
                    raise CircuitBreakerOpenError(self)
                self._state = CircuitState.HALF_OPEN

            if self._active_probes >= self.max_probes:
                raise CircuitBreakerOpenError(self)

            self._active_probes += 1
            return CircuitBreakerPermit(self, self._generation, True)

    def record_outcome(
        self, generation: int, failure: bool, cancellation: bool
    ) -> None:
        with self._lock:
            if generation != self._generation:
                return

            if cancellation:
                if self._state is CircuitState.HALF_OPEN:
                    self._active_probes = max(0, self._active_probes - 1)
                return

            if self._state is CircuitState.CLOSED:
                if failure:
                    self._failure_count += 1
                    if self._failure_count >= self.failure_threshold:
                        self._open()
                else:
                    self._failure_count = 0
                return

            if self._state is CircuitState.HALF_OPEN:
                self._active_probes = max(0, self._active_probes - 1)
                now = self._clock()
                if failure:
                    self._open(now)
                else:
                    self._close(now)

    def _open(self, now: float | None = None) -> None:
        self._state = CircuitState.OPEN
        self._opened_at = self._clock() if now is None else now
        self._active_probes = 0
        self._generation += 1

    def _close(self, now: float | None = None) -> None:
        del now
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._active_probes = 0
        self._generation += 1


__all__ = [
    "CircuitBreaker",
    "CircuitBreakerError",
    "CircuitBreakerOpenError",
    "CircuitBreakerPermit",
    "CircuitBreakerRejectedError",
    "CircuitState",
]
