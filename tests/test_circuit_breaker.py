import asyncio
import threading
import typing

import pytest

import tenacity
from tenacity import (
    AsyncRetrying,
    CircuitBreaker,
    CircuitBreakerOpenError,
    CircuitState,
    Retrying,
    retry_if_exception_type,
    stop_after_attempt,
)


class UpstreamError(Exception):
    pass


class IgnoredError(Exception):
    pass


class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def test_counts_each_logical_call_once() -> None:
    breaker = CircuitBreaker(
        failure_threshold=3, failure_predicate=retry_if_exception_type(UpstreamError)
    )
    attempts = 0

    def flaky() -> None:
        nonlocal attempts
        attempts += 1
        raise UpstreamError

    with pytest.raises(UpstreamError):
        Retrying(
            stop=stop_after_attempt(4),
            reraise=True,
            circuit_breaker=breaker,
        )(flaky)

    assert attempts == 4
    assert breaker.failure_count == 1
    assert breaker.state is CircuitState.CLOSED


def test_final_success_resets_consecutive_failures() -> None:
    breaker = CircuitBreaker(
        failure_threshold=2, failure_predicate=retry_if_exception_type(UpstreamError)
    )
    attempts = 0

    def flaky() -> str:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise UpstreamError
        return "ok"

    assert Retrying(circuit_breaker=breaker)(flaky) == "ok"
    assert attempts == 2
    assert breaker.failure_count == 0


def test_caller_predicate_controls_counted_failures() -> None:
    breaker = CircuitBreaker(
        failure_threshold=1, failure_predicate=retry_if_exception_type(UpstreamError)
    )

    def ignored() -> None:
        raise IgnoredError

    with pytest.raises(IgnoredError):
        Retrying(
            stop=stop_after_attempt(1),
            reraise=True,
            circuit_breaker=breaker,
        )(ignored)

    assert breaker.state is CircuitState.CLOSED
    assert breaker.failure_count == 0


def test_result_predicate_can_count_failure() -> None:
    breaker = CircuitBreaker(
        failure_threshold=1,
        failure_predicate=lambda state: state.outcome.result() == "bad",
    )

    Retrying(
        stop=stop_after_attempt(1),
        retry_error_callback=lambda state: typing.cast(
            "tenacity.Future", state.outcome
        ).result(),
        circuit_breaker=breaker,
    )(lambda: "bad")

    assert breaker.state is CircuitState.OPEN


def test_open_fast_rejects_without_retry() -> None:
    clock = FakeClock()
    breaker = CircuitBreaker(
        failure_threshold=1,
        recovery_timeout=10,
        clock=clock,
        failure_predicate=retry_if_exception_type(UpstreamError),
    )

    with pytest.raises(UpstreamError):
        Retrying(
            stop=stop_after_attempt(1),
            reraise=True,
            circuit_breaker=breaker,
        )(lambda: (_ for _ in ()).throw(UpstreamError()))

    def should_not_run() -> None:
        raise AssertionError

    with pytest.raises(CircuitBreakerOpenError):
        Retrying(circuit_breaker=breaker)(should_not_run)

    assert breaker.state is CircuitState.OPEN


def test_cooldown_allows_limited_probes() -> None:
    clock = FakeClock()
    breaker = CircuitBreaker(
        failure_threshold=1,
        recovery_timeout=10,
        max_probes=2,
        clock=clock,
        failure_predicate=retry_if_exception_type(UpstreamError),
    )
    permit_one = breaker.acquire()
    permit_one.record_failure()
    assert breaker.state is CircuitState.OPEN

    with pytest.raises(CircuitBreakerOpenError):
        breaker.acquire()

    clock.now += 10
    probe_one = breaker.acquire()
    probe_two = breaker.acquire()

    assert probe_one.probe
    assert probe_two.probe
    state: CircuitState = breaker.state
    assert state is CircuitState.HALF_OPEN
    assert breaker.active_probes == 2

    with pytest.raises(CircuitBreakerOpenError):
        breaker.acquire()


def test_half_open_success_closes_and_ignores_late_failure() -> None:
    clock = FakeClock()
    breaker = CircuitBreaker(
        failure_threshold=1,
        recovery_timeout=1,
        max_probes=2,
        clock=clock,
        failure_predicate=retry_if_exception_type(UpstreamError),
    )
    old = breaker.acquire()
    old.record_failure()
    clock.now += 1

    probe = breaker.acquire()
    stale = breaker.acquire()
    probe.record_success()

    assert breaker.state is CircuitState.CLOSED
    assert breaker.failure_count == 0

    stale.record_failure()
    assert breaker.state is CircuitState.CLOSED
    assert breaker.failure_count == 0


def test_half_open_failure_reopens_and_ignores_late_failure() -> None:
    clock = FakeClock()
    breaker = CircuitBreaker(
        failure_threshold=1,
        recovery_timeout=1,
        max_probes=2,
        clock=clock,
        failure_predicate=retry_if_exception_type(UpstreamError),
    )
    old = breaker.acquire()
    old.record_failure()
    clock.now += 1

    probe = breaker.acquire()
    stale = breaker.acquire()
    generation = breaker.generation
    probe.record_failure()

    assert breaker.state is CircuitState.OPEN
    assert breaker.generation == generation + 1

    stale.record_failure()
    assert breaker.state is CircuitState.OPEN
    assert breaker.generation == generation + 1


def test_cancelled_probe_returns_slot_without_failure() -> None:
    clock = FakeClock()
    breaker = CircuitBreaker(
        failure_threshold=1,
        recovery_timeout=5,
        max_probes=1,
        clock=clock,
        initial_state=CircuitState.HALF_OPEN,
        failure_predicate=retry_if_exception_type(UpstreamError),
    )

    probe = breaker.acquire()
    assert breaker.active_probes == 1
    clock.now += 3
    probe.record_cancellation()

    assert breaker.failure_count == 0
    assert breaker.active_probes == 0
    assert breaker.state is CircuitState.HALF_OPEN

    replacement = breaker.acquire()
    assert replacement.probe
    assert breaker.active_probes == 1


def test_sync_concurrent_probe_limit_with_execution_barrier() -> None:
    clock = FakeClock()
    breaker = CircuitBreaker(
        failure_threshold=1,
        recovery_timeout=1,
        max_probes=2,
        clock=clock,
        initial_state=CircuitState.HALF_OPEN,
        failure_predicate=retry_if_exception_type(UpstreamError),
    )
    barrier = threading.Barrier(3)
    results: list[bool] = []

    def worker() -> None:
        try:
            permit = breaker.acquire()
        except CircuitBreakerOpenError:
            results.append(False)
        else:
            with permit:
                barrier.wait()
            results.append(True)

    threads = [threading.Thread(target=worker) for _ in range(3)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()

    assert sorted(results) == [False, True, True]


async def cancel_after_start(started: asyncio.Event) -> None:
    await started.wait()
    raise asyncio.CancelledError


async def cancel_on_sleep(seconds: float) -> None:
    raise asyncio.CancelledError


def test_async_cancellation_does_not_count_upstream_failure() -> None:
    breaker = CircuitBreaker(
        failure_threshold=1,
        max_probes=1,
        initial_state=CircuitState.HALF_OPEN,
        failure_predicate=retry_if_exception_type(UpstreamError),
    )

    async def main() -> None:
        started = asyncio.Event()
        task: asyncio.Task[None] = asyncio.ensure_future(
            AsyncRetrying(circuit_breaker=breaker)(cancel_after_start, started)
        )
        started.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=1)

    asyncio.run(main())

    assert breaker.state is CircuitState.HALF_OPEN
    assert breaker.failure_count == 0
    assert breaker.active_probes == 0


def test_async_final_failure_counts_once() -> None:
    breaker = CircuitBreaker(
        failure_threshold=3,
        failure_predicate=retry_if_exception_type(UpstreamError),
    )
    attempts = 0

    async def flaky() -> None:
        nonlocal attempts
        attempts += 1
        raise UpstreamError

    async def main() -> None:
        await AsyncRetrying(
            stop=stop_after_attempt(4),
            reraise=True,
            circuit_breaker=breaker,
        )(flaky)

    with pytest.raises(UpstreamError):
        asyncio.run(main())

    assert attempts == 4
    assert breaker.failure_count == 1


def test_async_cancellation_during_retry_wait_returns_slot() -> None:
    breaker = CircuitBreaker(
        failure_threshold=1,
        max_probes=1,
        initial_state=CircuitState.HALF_OPEN,
        failure_predicate=retry_if_exception_type(UpstreamError),
    )
    attempts = 0

    async def flaky() -> None:
        nonlocal attempts
        attempts += 1
        raise UpstreamError

    async def main() -> None:
        await AsyncRetrying(
            wait=lambda state: 10,
            sleep=cancel_on_sleep,
            circuit_breaker=breaker,
        )(flaky)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(main())

    assert attempts == 1
    assert breaker.active_probes == 0
    assert breaker.failure_count == 0


@pytest.mark.asyncio
async def test_async_probe_cancellation_returns_slot() -> None:
    breaker = CircuitBreaker(
        failure_threshold=1,
        max_probes=1,
        initial_state=CircuitState.HALF_OPEN,
        failure_predicate=retry_if_exception_type(UpstreamError),
    )
    started = asyncio.Event()
    task: asyncio.Task[None] = asyncio.ensure_future(
        AsyncRetrying(circuit_breaker=breaker)(cancel_after_start, started)
    )
    started.set()

    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=1)

    assert breaker.active_probes == 0
    assert breaker.failure_count == 0
