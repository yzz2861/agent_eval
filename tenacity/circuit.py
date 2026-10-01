import dataclasses
import enum
import threading
import typing as t


class CircuitState(str, enum.Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half-open"


@dataclasses.dataclass(slots=True)
class CircuitBreakerSnapshot:
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    opened_at: float | None = None
    generation: int = 0


class CircuitBreakerError(Exception):
    """Raised when a circuit breaker rejects a call without invoking it."""


class CircuitBreakerOpenError(CircuitBreakerError):
    """Raised while an open circuit is still cooling down."""

    def __init__(self, retry_after: float = 0.0) -> None:
        self.retry_after = retry_after
        super().__init__(retry_after)


class CircuitBreakerFullError(CircuitBreakerOpenError):
    """Raised when all half-open probe permits are in use."""


ClockT = t.Callable[[], float]


class CircuitPermit:
    __slots__ = ("_breaker", "_completed", "generation", "probe")

    def __init__(self, breaker: "CircuitBreaker", generation: int, probe: bool) -> None:
        self._breaker = breaker
        self.generation = generation
        self.probe = probe
        self._completed = False

    def record_success(self) -> None:
        if not self._completed:
            self._completed = True
            self._breaker._record_success(self)  # noqa: SLF001

    def record_failure(self) -> None:
        if not self._completed:
            self._completed = True
            self._breaker._record_failure(self)  # noqa: SLF001

    def release(self) -> None:
        """Release a permit without counting its outcome."""
        if not self._completed:
            self._completed = True
            self._breaker._release_probe(self)  # noqa: SLF001


class CircuitBreaker:
    """A shareable circuit breaker for synchronous and asynchronous calls."""

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        half_open_limit: int = 1,
        *,
        state: CircuitBreakerSnapshot | CircuitState | None = None,
        clock: ClockT | None = None,
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be greater than zero")
        if recovery_timeout < 0:
            raise ValueError("recovery_timeout must not be negative")
        if half_open_limit < 1:
            raise ValueError("half_open_limit must be greater than zero")

        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_limit = half_open_limit
        self.clock = clock or self._default_clock
        self._lock = threading.RLock()

        if state is None:
            self._snapshot = CircuitBreakerSnapshot()
        elif isinstance(state, CircuitBreakerSnapshot):
            self._snapshot = state
        else:
            self._snapshot = CircuitBreakerSnapshot(state=state)

        if (
            self._snapshot.state is CircuitState.OPEN
            and self._snapshot.opened_at is None
        ):
            self._snapshot.opened_at = self.clock()

        self._active_probes = 0

    @staticmethod
    def _default_clock() -> float:
        import time

        return time.monotonic()

    @property
    def state(self) -> CircuitState:
        """Current state after applying clock-based recovery."""
        with self._lock:
            self._refresh_state()
            return self._snapshot.state

    @property
    def snapshot(self) -> CircuitBreakerSnapshot:
        with self._lock:
            self._refresh_state()
            return self._snapshot

    @property
    def current_state(self) -> CircuitState:
        return self.state

    @property
    def failure_count(self) -> int:
        with self._lock:
            self._refresh_state()
            return self._snapshot.failure_count

    def acquire(self) -> CircuitPermit:
        """Acquire either a normal-call permit or a half-open probe permit."""
        with self._lock:
            self._refresh_state()
            current = self._snapshot.state

            if current is CircuitState.OPEN:
                raise CircuitBreakerOpenError(self._retry_after())

            if current is CircuitState.HALF_OPEN:
                if self._active_probes >= self.half_open_limit:
                    raise CircuitBreakerFullError
                self._active_probes += 1
                return CircuitPermit(self, self._snapshot.generation, True)

            return CircuitPermit(self, self._snapshot.generation, False)

    def _refresh_state(self) -> None:
        if self._snapshot.state is not CircuitState.OPEN:
            return

        opened_at = self._snapshot.opened_at
        if opened_at is None:
            return
        if self.clock() - opened_at < self.recovery_timeout:
            return

        self._snapshot.state = CircuitState.HALF_OPEN
        self._snapshot.failure_count = 0
        self._snapshot.generation += 1
        self._active_probes = 0

    def _retry_after(self) -> float:
        opened_at = self._snapshot.opened_at
        if opened_at is None:
            return 0.0
        return max(0.0, self.recovery_timeout - (self.clock() - opened_at))

    def _record_success(self, permit: CircuitPermit) -> None:
        with self._lock:
            if permit.generation != self._snapshot.generation:
                self._release_probe(permit)
                return

            if permit.probe:
                self._active_probes -= 1
            self._snapshot.state = CircuitState.CLOSED
            self._snapshot.failure_count = 0
            self._snapshot.opened_at = None
            if permit.probe:
                self._snapshot.generation += 1

    def _record_failure(self, permit: CircuitPermit) -> None:
        with self._lock:
            if permit.generation != self._snapshot.generation:
                self._release_probe(permit)
                return

            if permit.probe:
                self._active_probes -= 1
                self._open()
                return

            self._snapshot.failure_count += 1
            if self._snapshot.failure_count >= self.failure_threshold:
                self._open()

    def _release_probe(self, permit: CircuitPermit) -> None:
        with self._lock:
            if (
                permit.probe
                and permit.generation == self._snapshot.generation
                and self._snapshot.state is CircuitState.HALF_OPEN
                and self._active_probes > 0
            ):
                self._active_probes -= 1

    def _open(self) -> None:
        self._snapshot.state = CircuitState.OPEN
        self._snapshot.opened_at = self.clock()
        self._snapshot.failure_count = 0
        self._snapshot.generation += 1
        self._active_probes = 0


__all__ = [
    "CircuitBreaker",
    "CircuitBreakerError",
    "CircuitBreakerFullError",
    "CircuitBreakerOpenError",
    "CircuitBreakerSnapshot",
    "CircuitBreakerState",
    "CircuitPermit",
    "CircuitState",
]

CircuitBreakerState = CircuitState
