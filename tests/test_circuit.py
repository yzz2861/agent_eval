import asyncio
import threading

import pytest

from tenacity import (
    CircuitBreaker,
    CircuitBreakerFullError,
    CircuitBreakerOpenError,
    CircuitBreakerSnapshot,
    CircuitState,
    RetryError,
    Retrying,
    retry_if_exception_type,
    retry_if_result,
    stop_after_attempt,
)
from tenacity.asyncio import AsyncRetrying


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_failure_threshold_counts_logical_call_once() -> None:
    breaker = CircuitBreaker(failure_threshold=1)
    attempts = 0

    def flaky() -> None:
        nonlocal attempts
        attempts += 1
        raise RuntimeError("upstream")

    with pytest.raises(RetryError):
        Retrying(
            stop=stop_after_attempt(5),
            circuit_breaker=breaker,
        )(flaky)

    assert attempts == 5
    assert breaker.state is CircuitState.OPEN

    with pytest.raises(CircuitBreakerOpenError):
        Retrying(circuit_breaker=breaker)(flaky)
    assert attempts == 5


def test_breaker_keyword_alias_is_accepted() -> None:
    breaker = CircuitBreaker()
    retrying = Retrying(breaker=breaker)
    assert retrying.circuit_breaker is breaker
    assert retrying.copy().circuit_breaker is breaker


def test_cooldown_allows_limited_half_open_probes() -> None:
    clock = Clock()
    snapshot = CircuitBreakerSnapshot(
        state=CircuitState.OPEN,
        opened_at=10.0,
    )
    breaker = CircuitBreaker(
        recovery_timeout=5.0,
        half_open_limit=2,
        state=snapshot,
        clock=clock,
    )

    clock.now = 14.0
    with pytest.raises(CircuitBreakerOpenError) as rejected:
        breaker.acquire()
    assert rejected.value.retry_after == pytest.approx(1.0)

    clock.now = 15.0
    first = breaker.acquire()
    second = breaker.acquire()
    assert breaker.state is CircuitState.HALF_OPEN
    with pytest.raises(CircuitBreakerFullError):
        breaker.acquire()

    first.release()
    replacement = breaker.acquire()
    second.record_success()
    replacement.record_success()
    assert breaker.state is CircuitState.CLOSED


def test_caller_decides_which_failures_count() -> None:
    breaker = CircuitBreaker(failure_threshold=1)

    def ignored() -> None:
        raise ValueError("ignored")

    with pytest.raises(ValueError, match="ignored"):
        Retrying(
            retry=retry_if_result(lambda result: True),
            stop=stop_after_attempt(1),
            circuit_breaker=breaker,
        )(ignored)
    assert breaker.state is CircuitState.CLOSED
    assert breaker.failure_count == 0


def test_result_based_retry_failure_counts_once() -> None:
    breaker = CircuitBreaker(failure_threshold=2)
    calls = 0

    def bad_result() -> str:
        nonlocal calls
        calls += 1
        return "bad"

    with pytest.raises(RetryError):
        Retrying(
            retry=retry_if_result("bad".__eq__),
            stop=stop_after_attempt(3),
            circuit_breaker=breaker,
        )(bad_result)
    assert calls == 3
    assert breaker.failure_count == 1

    with pytest.raises(RetryError):
        Retrying(
            retry=retry_if_result("bad".__eq__),
            stop=stop_after_attempt(3),
            circuit_breaker=breaker,
        )(bad_result)
    assert calls == 6
    assert breaker.state is CircuitState.OPEN


def test_late_half_open_failure_cannot_reopen_recovered_breaker() -> None:
    clock = Clock()
    breaker = CircuitBreaker(clock=clock)

    threshold = breaker.failure_threshold
    for _ in range(threshold):
        permit = breaker.acquire()
        permit.record_failure()
    assert breaker.state is CircuitState.OPEN

    clock.now = breaker.recovery_timeout
    breaker.half_open_limit = 2
    stale_probe = breaker.acquire()
    recovering_probe = breaker.acquire()
    with pytest.raises(CircuitBreakerFullError):
        breaker.acquire()

    recovering_probe.record_success()
    assert breaker.state is CircuitState.CLOSED
    stale_probe.record_failure()
    assert breaker.state is CircuitState.CLOSED
    assert breaker.failure_count == 0


def test_sync_half_open_probe_uses_execution_barrier() -> None:
    clock = Clock()
    breaker = CircuitBreaker(
        failure_threshold=1,
        recovery_timeout=10.0,
        half_open_limit=1,
        clock=clock,
    )

    def fail() -> None:
        raise RuntimeError("upstream")

    with pytest.raises(RetryError):
        Retrying(
            stop=stop_after_attempt(1),
            circuit_breaker=breaker,
        )(fail)
    assert breaker.state is CircuitState.OPEN

    clock.now = 10.0
    barrier = threading.Barrier(2)
    release = threading.Event()

    def probe() -> None:
        barrier.wait()
        release.wait(0.1)

    worker = threading.Thread(
        target=Retrying(
            stop=stop_after_attempt(1),
            circuit_breaker=breaker,
        ),
        args=(probe,),
    )
    worker.start()
    barrier.wait(timeout=1)

    assert breaker.state is CircuitState.HALF_OPEN
    with pytest.raises(CircuitBreakerFullError):
        breaker.acquire()

    release.set()
    worker.join(timeout=1)
    assert not worker.is_alive()
    assert breaker.state is CircuitState.CLOSED


def test_sync_iterator_reports_terminal_outcome() -> None:
    breaker = CircuitBreaker(failure_threshold=1)
    attempts = 0

    with pytest.raises(RetryError):
        for attempt in Retrying(
            stop=stop_after_attempt(2),
            circuit_breaker=breaker,
        ):
            with attempt:
                attempts += 1
                raise RuntimeError("upstream")

    assert attempts == 2
    assert breaker.state is CircuitState.OPEN

    with pytest.raises(CircuitBreakerOpenError):
        for _ in Retrying(circuit_breaker=breaker):
            pytest.fail("fast rejection must not yield an attempt")


def test_async_half_open_probe_limit_and_cancellation() -> None:
    asyncio.run(_test_async_half_open_probe_limit_and_cancellation())


async def _test_async_half_open_probe_limit_and_cancellation() -> None:
    clock = Clock()
    breaker = CircuitBreaker(
        failure_threshold=1,
        recovery_timeout=10.0,
        half_open_limit=1,
        clock=clock,
    )

    async def fail_once() -> None:
        raise RuntimeError("upstream")

    with pytest.raises(RetryError):
        await AsyncRetrying(
            stop=stop_after_attempt(1),
            circuit_breaker=breaker,
        )(fail_once)
    assert breaker.state is CircuitState.OPEN

    clock.now = 10.0
    entered = asyncio.Event()
    release = asyncio.Event()

    async def probe() -> None:
        entered.set()
        await release.wait()

    retrying = AsyncRetrying(
        retry=retry_if_exception_type(RuntimeError),
        stop=stop_after_attempt(1),
        circuit_breaker=breaker,
    )
    probe_task = asyncio.create_task(retrying(probe))
    await entered.wait()
    assert breaker.state is CircuitState.HALF_OPEN

    with pytest.raises(CircuitBreakerFullError):
        await retrying(probe)

    probe_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await probe_task

    assert breaker.state is CircuitState.HALF_OPEN
    replacement = breaker.acquire()
    replacement.record_success()
    assert breaker.state is CircuitState.CLOSED


def test_async_recovered_probe_ignores_late_failure_behind_barrier() -> None:
    asyncio.run(_test_async_recovered_probe_ignores_late_failure_behind_barrier())


async def _test_async_recovered_probe_ignores_late_failure_behind_barrier() -> None:
    clock = Clock()
    breaker = CircuitBreaker(
        failure_threshold=1,
        recovery_timeout=10.0,
        half_open_limit=2,
        clock=clock,
    )

    async def fail() -> None:
        raise RuntimeError("upstream")

    with pytest.raises(RetryError):
        await AsyncRetrying(
            stop=stop_after_attempt(1),
            circuit_breaker=breaker,
        )(fail)

    clock.now = 10.0
    barrier = asyncio.Barrier(3)
    release_success = asyncio.Event()
    release_failure = asyncio.Event()

    async def successful_probe() -> None:
        await barrier.wait()
        await release_success.wait()

    async def failed_probe() -> None:
        await barrier.wait()
        await release_failure.wait()
        raise RuntimeError("late failure")

    success_task = asyncio.create_task(
        AsyncRetrying(
            stop=stop_after_attempt(1),
            circuit_breaker=breaker,
        )(successful_probe)
    )
    failure_task = asyncio.create_task(
        AsyncRetrying(
            stop=stop_after_attempt(1),
            circuit_breaker=breaker,
        )(failed_probe)
    )
    await asyncio.wait_for(barrier.wait(), timeout=1)

    assert breaker.state is CircuitState.HALF_OPEN
    with pytest.raises(CircuitBreakerFullError):
        await AsyncRetrying(
            stop=stop_after_attempt(1),
            circuit_breaker=breaker,
        )(successful_probe)

    release_success.set()
    await success_task
    assert breaker.state is CircuitState.CLOSED

    release_failure.set()
    results = await asyncio.gather(failure_task, return_exceptions=True)
    assert isinstance(results[0], RetryError)
    assert breaker.state is CircuitState.CLOSED
    assert breaker.failure_count == 0


def test_async_cancellation_is_not_upstream_failure() -> None:
    asyncio.run(_test_async_cancellation_is_not_upstream_failure())


async def _test_async_cancellation_is_not_upstream_failure() -> None:
    breaker = CircuitBreaker(failure_threshold=1)
    entered = asyncio.Event()

    async def cancelled_call() -> None:
        entered.set()
        await asyncio.Event().wait()

    task = asyncio.create_task(AsyncRetrying(circuit_breaker=breaker)(cancelled_call))
    await entered.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert breaker.state is CircuitState.CLOSED
    assert breaker.failure_count == 0


def test_async_iterator_reports_terminal_outcome() -> None:
    asyncio.run(_test_async_iterator_reports_terminal_outcome())


async def _test_async_iterator_reports_terminal_outcome() -> None:
    breaker = CircuitBreaker(failure_threshold=1)
    attempts = 0

    with pytest.raises(RetryError):
        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(2),
            circuit_breaker=breaker,
        ):
            async with attempt:
                attempts += 1
                raise RuntimeError("upstream")

    assert attempts == 2
    assert breaker.state is CircuitState.OPEN

    with pytest.raises(CircuitBreakerOpenError):
        async for _ in AsyncRetrying(circuit_breaker=breaker):
            pytest.fail("fast rejection must not yield an attempt")
