import asyncio

import pytest

from tenacity import (
    AsyncRetrying,
    RetryBudget,
    RetryBudgetAttemptsExceeded,
    RetryBudgetCancelled,
    RetryBudgetDeadlineExceeded,
    RetryError,
    Retrying,
    RetryStopReason,
    retry_if_exception_type,
    stop_after_attempt,
    stop_never,
    wait_fixed,
    wait_none,
)


class FakeClock:
    def __init__(self) -> None:
        self.current = 0.0

    def __call__(self) -> float:
        return self.current

    def advance(self, seconds: float) -> None:
        self.current += seconds


class TestRetryBudget:
    def test_constructor_aliases(self) -> None:
        budget = RetryBudget(max_attempts=3, deadline=1, clock=FakeClock())
        assert budget.max_extra_attempts == 2
        with budget:
            assert budget.remaining_time == 1.0

        with pytest.raises(TypeError):
            RetryBudget(max_extra_attempts=1, extra_attempts=2)
        with pytest.raises(ValueError, match="non-negative"):
            RetryBudget(max_extra_attempts=-1)

    def test_nested_retries_share_extra_attempts(self) -> None:
        attempts = []
        budget = RetryBudget(max_extra_attempts=2)

        def inner() -> None:
            attempts.append("inner")
            raise RuntimeError("retry")

        def outer() -> None:
            attempts.append("outer")
            Retrying(
                retry=retry_if_exception_type(RuntimeError),
                stop=stop_after_attempt(100),
                wait=wait_none(),
            )(inner)

        with budget, pytest.raises(RetryBudgetAttemptsExceeded) as exc_info:
            Retrying(
                retry=retry_if_exception_type(RuntimeError),
                stop=stop_after_attempt(100),
                wait=wait_none(),
            )(outer)

        assert attempts == ["outer", "inner", "inner", "inner"]
        assert budget.extra_attempts == 2
        assert exc_info.value.reason is RetryStopReason.ATTEMPT_LIMIT

    def test_first_local_failure_does_not_consume_budget(self) -> None:
        budget = RetryBudget(max_extra_attempts=1)

        def always_fails() -> None:
            raise RuntimeError("local")

        with budget, pytest.raises(RetryError) as exc_info:
            Retrying(stop=stop_after_attempt(1))(always_fails)

        assert exc_info.value.reason is RetryStopReason.LOCAL_POLICY
        assert budget.extra_attempts == 0

    def test_local_stop_cannot_relax_outer_attempt_budget(self) -> None:
        budget = RetryBudget(max_extra_attempts=10)

        def always_fails() -> None:
            raise RuntimeError("local")

        with budget, pytest.raises(RuntimeError):
            Retrying(stop=stop_after_attempt(1), reraise=True)(always_fails)

        with budget, pytest.raises(RetryError) as exc_info:
            Retrying(stop=stop_after_attempt(1))(always_fails)

        assert exc_info.value.reason is RetryStopReason.LOCAL_POLICY

    def test_deadline_uses_injected_clock_and_caps_wait(self) -> None:
        clock = FakeClock()
        sleeps = []

        def sleep_and_advance(seconds: float) -> None:
            sleeps.append(seconds)
            clock.advance(seconds)

        budget = RetryBudget(max_delay=10, clock=clock, sleep=sleep_and_advance)

        def inner() -> None:
            raise RuntimeError("retry")

        def outer() -> None:
            Retrying(
                retry=retry_if_exception_type(RuntimeError),
                stop=stop_never,
                wait=wait_fixed(6),
            )(inner)

        with budget, pytest.raises(RetryBudgetDeadlineExceeded):
            Retrying(
                retry=retry_if_exception_type(RuntimeError),
                stop=stop_never,
                wait=wait_none(),
            )(outer)

        assert sleeps == [6.0, 4.0]

    def test_deadline_boundary_is_checked_with_injected_clock(self) -> None:
        clock = FakeClock()
        calls = 0

        def always_fails() -> None:
            nonlocal calls
            calls += 1
            clock.advance(5)
            raise RuntimeError("retry")

        with (
            RetryBudget(deadline=10, clock=clock),
            pytest.raises(RetryBudgetDeadlineExceeded),
        ):
            Retrying(
                retry=retry_if_exception_type(RuntimeError),
                stop=stop_never,
                wait=wait_none(),
            )(always_fails)
        assert calls == 2

    def test_exit_context_resets_for_next_request(self) -> None:
        budget = RetryBudget(max_extra_attempts=1)

        def always_fails() -> None:
            raise RuntimeError("retry")

        with budget, pytest.raises(RetryBudgetAttemptsExceeded):
            Retrying(stop=stop_never, wait=wait_none())(always_fails)
        assert budget.extra_attempts == 1

        with budget, pytest.raises(RetryBudgetAttemptsExceeded):
            assert budget.extra_attempts == 0
            Retrying(stop=stop_never, wait=wait_none())(always_fails)
        assert budget.extra_attempts == 1

    def test_cancel_stops_wait_without_real_time(self) -> None:
        budget = RetryBudget(max_extra_attempts=5)

        def cancel_before_wait(retry_state: object) -> float:
            del retry_state
            budget.cancel()
            return 0.0

        def always_fails() -> None:
            raise RuntimeError("retry")

        def cancel_after_reservation(retry_state: object) -> None:
            del retry_state
            budget.cancel()

        with budget, pytest.raises(RetryBudgetCancelled) as exc_info:
            Retrying(
                before_sleep=cancel_after_reservation,
                stop=stop_never,
                wait=wait_fixed(300),
            )(always_fails)

        assert exc_info.value.reason is RetryStopReason.CANCELLED

        with budget, pytest.raises(RetryBudgetCancelled) as exc_info:
            Retrying(stop=stop_never, wait=cancel_before_wait)(always_fails)


class TestAsyncRetryBudget:
    def test_async_deadline_uses_injected_clock(self) -> None:
        clock = FakeClock()

        async def fake_sleep(seconds: float) -> None:
            clock.advance(seconds)

        async def always_fails() -> None:
            clock.advance(5)
            raise RuntimeError("retry")

        async def run() -> None:
            budget = RetryBudget(max_delay=10, clock=clock, sleep=fake_sleep)
            with budget, pytest.raises(RetryBudgetDeadlineExceeded):
                await AsyncRetrying(
                    retry=retry_if_exception_type(RuntimeError),
                    stop=stop_never,
                    wait=wait_fixed(6),
                )(always_fails)

        asyncio.run(run())

    def test_concurrent_siblings_cannot_overspend_extra_attempts(self) -> None:
        attempts = []
        ready = 0
        budget = RetryBudget(max_extra_attempts=2, clock=FakeClock())

        async def run() -> None:
            barrier = asyncio.Event()

            async def child(number: int) -> None:
                nonlocal ready
                attempts.append(number)
                ready += 1
                if ready == 3:
                    barrier.set()
                await barrier.wait()
                raise RuntimeError("retry")

            async def parent() -> None:
                children = [
                    AsyncRetrying(
                        retry=retry_if_exception_type(RuntimeError),
                        stop=stop_after_attempt(100),
                        wait=wait_none(),
                    )(child, number)
                    for number in range(3)
                ]
                await asyncio.gather(*children)

            with budget, pytest.raises(RetryBudgetAttemptsExceeded):
                await AsyncRetrying(
                    retry=retry_if_exception_type(RuntimeError),
                    stop=stop_never,
                    wait=wait_none(),
                )(parent)

        asyncio.run(run())
        assert attempts == [0, 1, 2]

    def test_async_cancel_interrupts_default_wait(self) -> None:
        async def run() -> None:
            budget = RetryBudget(max_extra_attempts=5)

            async def always_fails() -> None:
                raise RuntimeError("retry")

            async def cancel_after_yield() -> None:
                await asyncio.sleep(0)
                budget.cancel()

            task = asyncio.ensure_future(cancel_after_yield())
            with budget, pytest.raises(RetryBudgetCancelled):
                await AsyncRetrying(stop=stop_never, wait=wait_fixed(300))(always_fails)
            await task

        asyncio.run(run())
