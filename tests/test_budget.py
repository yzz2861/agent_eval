# Copyright 2026 Tenacity Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import asyncio
import contextvars
import threading
import unittest

import pytest

from tenacity import (
    AsyncRetrying,
    RetryBudget,
    RetryBudgetAttemptsExhausted,
    RetryBudgetDeadlineExceeded,
    RetryBudgetExceeded,
    RetryError,
    Retrying,
    current_budget,
    stop_after_attempt,
    wait_fixed,
)

from .test_asyncio import asynctest


class FakeClock:
    """Deterministic monotonic clock; only moves when told to."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class _CallCounter:
    """Fails forever while counting how often it was invoked."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self) -> None:
        self.calls += 1
        raise OSError("boom")


def _no_sleep(seconds: float) -> None:
    pass


class TestRetryBudgetValidation(unittest.TestCase):
    def test_requires_a_limit(self) -> None:
        with pytest.raises(ValueError):
            RetryBudget()

    def test_rejects_negative_attempts(self) -> None:
        with pytest.raises(ValueError):
            RetryBudget(max_extra_attempts=-1)

    def test_no_budget_outside_context(self) -> None:
        assert current_budget() is None
        with RetryBudget(max_extra_attempts=1):
            assert current_budget() is not None
        assert current_budget() is None


class TestSharedAttemptBudget(unittest.TestCase):
    def test_nested_retryings_share_one_pool(self) -> None:
        innermost = _CallCounter()
        inner = Retrying(stop=stop_after_attempt(10), sleep=_no_sleep)
        outer = Retrying(stop=stop_after_attempt(10), sleep=_no_sleep)

        def inner_call() -> None:
            inner(innermost)

        with (
            RetryBudget(max_extra_attempts=3),
            pytest.raises(RetryBudgetAttemptsExhausted),
        ):
            outer(inner_call)

        # Without a budget this would be 10*10 calls; the shared pool
        # allows exactly 1 free first attempt + 3 extra ones.
        assert innermost.calls == 4

    def test_first_attempt_is_free(self) -> None:
        ok_calls = 0

        def ok() -> str:
            nonlocal ok_calls
            ok_calls += 1
            return "fine"

        retrying = Retrying(sleep=_no_sleep)
        with RetryBudget(max_extra_attempts=0):
            assert retrying(ok) == "fine"
            fails = _CallCounter()
            with pytest.raises(RetryBudgetAttemptsExhausted):
                retrying(fails)
        assert fails.calls == 1
        assert ok_calls == 1

    def test_local_stop_still_applies(self) -> None:
        fails = _CallCounter()
        retrying = Retrying(stop=stop_after_attempt(3), sleep=_no_sleep)
        with RetryBudget(max_extra_attempts=100), pytest.raises(RetryError) as exc_info:
            retrying(fails)
        # A local stop decision is not a budget exhaustion.
        assert not isinstance(exc_info.value, RetryBudgetExceeded)
        assert fails.calls == 3

    def test_local_stop_cannot_loosen_budget(self) -> None:
        fails = _CallCounter()
        retrying = Retrying(stop=stop_after_attempt(10), sleep=_no_sleep)
        with (
            RetryBudget(max_extra_attempts=1),
            pytest.raises(RetryBudgetAttemptsExhausted),
        ):
            retrying(fails)
        assert fails.calls == 2

    def test_fresh_context_recounts(self) -> None:
        fails = _CallCounter()
        retrying = Retrying(stop=stop_after_attempt(10), sleep=_no_sleep)

        budget = RetryBudget(max_extra_attempts=1)
        with budget, pytest.raises(RetryBudgetAttemptsExhausted):
            retrying(fails)
        assert fails.calls == 2

        # Outside the context no budget applies at all.
        with pytest.raises(RetryError):
            retrying(fails)
        assert fails.calls == 2 + 10

        # Re-entering starts from a full quota again.
        with budget, pytest.raises(RetryBudgetAttemptsExhausted):
            retrying(fails)
        assert fails.calls == 2 + 10 + 2

    def test_iterator_protocol_consumes_budget(self) -> None:
        attempts = 0
        retrying = Retrying(stop=stop_after_attempt(10), sleep=_no_sleep)
        with (
            RetryBudget(max_extra_attempts=1),
            pytest.raises(RetryBudgetAttemptsExhausted),
        ):
            for attempt in retrying:
                with attempt:
                    attempts += 1
                    raise ValueError("nope")
        assert attempts == 2


class TestSharedDeadline(unittest.TestCase):
    def test_deadline_shared_and_wait_clamped(self) -> None:
        clock = FakeClock()
        sleeps = []

        def fake_sleep(seconds: float) -> None:
            sleeps.append(seconds)
            clock.sleep(seconds)

        fails = _CallCounter()
        retrying = Retrying(wait=wait_fixed(4), sleep=fake_sleep)

        with (
            RetryBudget(max_delay=10, clock=clock),
            pytest.raises(RetryBudgetDeadlineExceeded),
        ):
            retrying(fails)

        # t=0: attempt 1, t=4: attempt 2, t=8: attempt 3; the third wait
        # is clamped from 4 to the 2 seconds left, then the deadline
        # denies the fourth attempt. No real time was spent.
        assert fails.calls == 3
        assert sleeps == [4, 4, 2]

    def test_wait_never_overshoots_deadline(self) -> None:
        clock = FakeClock()
        sleeps = []

        def fake_sleep(seconds: float) -> None:
            sleeps.append(seconds)
            clock.sleep(seconds)

        fails = _CallCounter()
        retrying = Retrying(wait=wait_fixed(100), sleep=fake_sleep)

        with (
            RetryBudget(max_delay=10, clock=clock),
            pytest.raises(RetryBudgetDeadlineExceeded),
        ):
            retrying(fails)

        assert fails.calls == 1
        assert sleeps == [10]

    def test_attempt_and_deadline_limits_combine(self) -> None:
        clock = FakeClock()
        fails = _CallCounter()
        retrying = Retrying(sleep=clock.sleep)

        # Attempt quota runs out long before the distant deadline.
        with (
            RetryBudget(max_extra_attempts=1, max_delay=1000, clock=clock),
            pytest.raises(RetryBudgetAttemptsExhausted),
        ):
            retrying(fails)
        assert fails.calls == 2


class TestAsyncSharedBudget(unittest.TestCase):
    @asynctest
    async def test_nested_async_retryings_share_one_pool(self) -> None:
        calls = 0

        async def fails() -> None:
            nonlocal calls
            calls += 1
            raise OSError("boom")

        async def no_sleep(seconds: float) -> None:
            pass

        inner = AsyncRetrying(stop=stop_after_attempt(10), sleep=no_sleep)
        outer = AsyncRetrying(stop=stop_after_attempt(10), sleep=no_sleep)

        async def inner_call() -> None:
            await inner(fails)

        async with RetryBudget(max_extra_attempts=3):
            with pytest.raises(RetryBudgetAttemptsExhausted):
                await outer(inner_call)

        assert calls == 4

    @asynctest
    async def test_concurrent_tasks_cannot_overspend(self) -> None:
        calls = 0

        async def fails() -> None:
            nonlocal calls
            calls += 1
            raise OSError("boom")

        async def yield_sleep(seconds: float) -> None:
            await asyncio.sleep(0)

        retrying = AsyncRetrying(sleep=yield_sleep)

        async with RetryBudget(max_extra_attempts=5):
            results = await asyncio.gather(
                retrying(fails),
                retrying(fails),
                return_exceptions=True,
            )

        # Two free first attempts plus exactly five shared extra ones.
        assert calls == 7
        assert all(isinstance(r, RetryBudgetAttemptsExhausted) for r in results)


class TestThreadSharedBudget(unittest.TestCase):
    def test_concurrent_threads_cannot_overspend(self) -> None:
        calls = 0
        calls_lock = threading.Lock()

        def fails() -> None:
            nonlocal calls
            with calls_lock:
                calls += 1
            raise OSError("boom")

        retrying = Retrying(sleep=_no_sleep)
        errors = []
        barrier = threading.Barrier(4)

        def worker() -> None:
            barrier.wait(timeout=10)
            try:
                retrying(fails)
            except RetryBudgetAttemptsExhausted:
                pass
            except BaseException as exc:
                errors.append(exc)

        with RetryBudget(max_extra_attempts=5):
            # contextvars do not hop threads by themselves; copying the
            # context shares the very same budget object with the workers.
            # Each Context object may only be entered once, so every thread
            # gets its own copy of the same context.
            threads = [
                threading.Thread(target=contextvars.copy_context().run, args=(worker,))
                for _ in range(4)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=30)

        assert not errors
        # Four free first attempts plus exactly five shared extra ones,
        # however the acquisitions interleave.
        assert calls == 9


if __name__ == "__main__":
    unittest.main()
