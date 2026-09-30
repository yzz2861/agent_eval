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
"""Shared retry budget context.

Nesting ``Retrying``/``AsyncRetrying`` controllers multiplies attempts: an
outer loop of N retries around an inner loop of M retries can issue N*M
calls. Entering a :class:`RetryBudget` context makes every retry controller
running inside the context draw its *extra* attempts from one shared pool
and honour one shared deadline, so the total stays bounded no matter how
deep the nesting goes.
"""

import contextvars
import threading
import time
import typing as t

from tenacity import _utils
from tenacity._utils import override

if t.TYPE_CHECKING:
    import sys

    if sys.version_info >= (3, 11):
        from typing import Self
    else:
        from typing_extensions import Self

    import types

    from tenacity import RetryCallState


class RetryBudgetExceeded(Exception):
    """Base class for shared retry budget exhaustion.

    Raised when a retry loop is cut short by the shared :class:`RetryBudget`
    rather than by its own local ``stop`` strategy (which still raises
    :class:`tenacity.RetryError`), so callers can tell the two apart.
    """

    def __init__(
        self,
        message: str,
        retry_state: "RetryCallState | None" = None,
    ) -> None:
        super().__init__(message)
        #: State of the retry call that was denied an extra attempt.
        self.retry_state = retry_state


class RetryBudgetAttemptsExhausted(RetryBudgetExceeded):
    """The shared pool of extra attempts has been fully consumed."""


class RetryBudgetDeadlineExceeded(RetryBudgetExceeded):
    """The shared budget deadline has passed."""


_current_budget: contextvars.ContextVar["RetryBudget | None"] = contextvars.ContextVar(
    "tenacity_retry_budget", default=None
)


def current_budget() -> "RetryBudget | None":
    """Return the retry budget active in the current context, if any."""
    return _current_budget.get()


class RetryBudget:
    """Context manager bounding the total retry effort underneath it.

    :param max_extra_attempts: Maximum number of *extra* attempts shared by
        every ``Retrying``/``AsyncRetrying`` running inside the context.
        The first attempt of each call is always free; the quota is only
        debited when an extra attempt actually starts. ``None`` means
        unlimited.
    :param max_delay: Shared deadline, in seconds (or a ``timedelta``),
        counted from the moment the context is entered. ``None`` means no
        deadline.
    :param clock: Monotonic clock used for the deadline. Injectable so
        tests can drive boundary conditions without real time.

    The budget is propagated through a :class:`contextvars.ContextVar`, so
    ``asyncio`` tasks created inside the context (and threads started via
    ``contextvars.copy_context()``) share the same pool. Consumption is
    guarded by a lock: concurrent sub-calls racing for the last token
    cannot overspend.

    Local ``stop`` strategies keep applying on top of the budget -- they
    can only make a loop stop earlier, never past the budget. When the
    budget runs out, :class:`RetryBudgetAttemptsExhausted` or
    :class:`RetryBudgetDeadlineExceeded` is raised instead of
    :class:`tenacity.RetryError`.

    Exiting the context detaches the budget; entering a fresh context
    starts counting from a full quota again.
    """

    def __init__(
        self,
        max_extra_attempts: int | None = None,
        max_delay: "_utils.time_unit_type | None" = None,
        clock: t.Callable[[], float] = time.monotonic,
    ) -> None:
        if max_extra_attempts is None and max_delay is None:
            raise ValueError(
                "RetryBudget requires at least one of max_extra_attempts or max_delay"
            )
        if max_extra_attempts is not None and max_extra_attempts < 0:
            raise ValueError("max_extra_attempts must be >= 0")
        self.max_extra_attempts = max_extra_attempts
        self.max_delay = None if max_delay is None else _utils.to_seconds(max_delay)
        self.clock = clock
        self._lock = threading.Lock()
        self._remaining: int | None = None
        self._deadline: float | None = None
        self._token: contextvars.Token[RetryBudget | None] | None = None

    def __enter__(self) -> "Self":
        with self._lock:
            # (Re)entering always starts from a full quota so that the next
            # request after a previous context exited counts afresh.
            self._remaining = self.max_extra_attempts
            self._deadline = (
                None if self.max_delay is None else self.clock() + self.max_delay
            )
        self._token = _current_budget.set(self)
        return self

    def __exit__(
        self,
        exc_type: "type[BaseException] | None",
        exc_value: "BaseException | None",
        traceback: "types.TracebackType | None",
    ) -> None:
        if self._token is not None:
            _current_budget.reset(self._token)
            self._token = None

    async def __aenter__(self) -> "Self":
        return self.__enter__()

    async def __aexit__(
        self,
        exc_type: "type[BaseException] | None",
        exc_value: "BaseException | None",
        traceback: "types.TracebackType | None",
    ) -> None:
        self.__exit__(exc_type, exc_value, traceback)

    @property
    def remaining_attempts(self) -> int | None:
        """Extra attempts left, or ``None`` when unlimited/not entered."""
        with self._lock:
            return self._remaining

    @property
    def deadline(self) -> float | None:
        """Absolute deadline on the budget clock, or ``None`` if unbounded."""
        return self._deadline

    def time_remaining(self) -> float | None:
        """Seconds left before the deadline, or ``None`` when unbounded."""
        deadline = self._deadline
        if deadline is None:
            return None
        return max(0.0, deadline - self.clock())

    def acquire(self, retry_state: "RetryCallState | None" = None) -> None:
        """Consume one extra attempt from the shared pool.

        Atomic with respect to concurrent consumers: when the pool is empty
        or the deadline has passed, exactly one of the racing callers gets
        the last token and the others raise.

        :raises RetryBudgetDeadlineExceeded: the shared deadline has passed.
        :raises RetryBudgetAttemptsExhausted: no extra attempts are left.
        """
        with self._lock:
            if self._deadline is not None and self.clock() >= self._deadline:
                raise RetryBudgetDeadlineExceeded(
                    "shared retry budget deadline exceeded",
                    retry_state=retry_state,
                )
            if self._remaining is not None:
                if self._remaining <= 0:
                    raise RetryBudgetAttemptsExhausted(
                        "shared retry budget has no extra attempts left",
                        retry_state=retry_state,
                    )
                self._remaining -= 1

    def clamp_sleep(self, sleep: float) -> float:
        """Bound a wait so it never stretches past the shared deadline.

        This makes sleeps between attempts effectively cancellable at the
        deadline: instead of overshooting, the retry loop wakes up when the
        budget expires and its next attempt is denied.
        """
        remaining = self.time_remaining()
        if remaining is None:
            return sleep
        return max(0.0, min(sleep, remaining))

    @override
    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} object at 0x{id(self):x} ("
            f"max_extra_attempts={self.max_extra_attempts}, "
            f"max_delay={self.max_delay}, "
            f"remaining_attempts={self._remaining}, "
            f"deadline={self._deadline})>"
        )


__all__ = [
    "RetryBudget",
    "RetryBudgetAttemptsExhausted",
    "RetryBudgetDeadlineExceeded",
    "RetryBudgetExceeded",
    "current_budget",
]
