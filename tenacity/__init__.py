# Copyright 2016-2018 Julien Danjou
# Copyright 2017 Elisey Zanko
# Copyright 2016 Étienne Bersac
# Copyright 2016 Joshua Harlow
# Copyright 2013-2014 Ray Holder
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
import contextlib
import contextvars
import dataclasses
import enum
import functools
import sys
import threading
import time
import typing as t
import warnings
from abc import ABC, abstractmethod
from concurrent import futures

from . import _utils
from ._utils import override

# Import all built-in after strategies for easier usage.
from .after import after_log, after_nothing

# Import all built-in before strategies for easier usage.
from .before import before_log, before_nothing

# Import all built-in before sleep strategies for easier usage.
from .before_sleep import before_sleep_log, before_sleep_nothing

# Import all nap strategies for easier usage.
from .nap import sleep, sleep_using_event

# Import all built-in retry strategies for easier usage.
from .retry import (
    retry_all,
    retry_always,
    retry_any,
    retry_base,
    retry_if_exception,
    retry_if_exception_cause_type,
    retry_if_exception_message,
    retry_if_exception_type,
    retry_if_not_exception_message,
    retry_if_not_exception_type,
    retry_if_not_result,
    retry_if_result,
    retry_never,
    retry_unless_exception_type,
)

# Import all built-in stop strategies for easier usage.
from .stop import (
    stop_after_attempt,
    stop_after_delay,
    stop_all,
    stop_any,
    stop_before_delay,
    stop_never,
    stop_when_event_set,
)

# Import all built-in wait strategies for easier usage.
from .wait import (
    wait_chain,
    wait_combine,
    wait_exception,
    wait_exponential,
    wait_exponential_jitter,
    wait_fixed,
    wait_incrementing,
    wait_none,
    wait_random,
    wait_random_exponential,
)
from .wait import wait_random_exponential as wait_full_jitter

try:
    import tornado
except ImportError:
    tornado = None  # type: ignore[assignment]


def _has_tornado() -> bool:
    # A function, not a module-level constant: test suites force the
    # non-tornado path by setting `tenacity.tornado = None`, so the answer has
    # to be computed from the live global every time it is asked for.
    return tornado is not None


if t.TYPE_CHECKING:
    if sys.version_info >= (3, 11):
        from typing import Self
    else:
        from typing_extensions import Self

    import types

    from . import asyncio as tasyncio
    from .retry import RetryBaseT
    from .stop import StopBaseT
    from .wait import WaitBaseT


WrappedFnReturnT = t.TypeVar("WrappedFnReturnT")
WrappedFn = t.TypeVar("WrappedFn", bound=t.Callable[..., t.Any])
P = t.ParamSpec("P")
R = t.TypeVar("R")


@dataclasses.dataclass(slots=True)
class IterState:
    actions: list[t.Callable[["RetryCallState"], t.Any]] = dataclasses.field(
        default_factory=list
    )
    retry_run_result: bool = False
    stop_run_result: bool = False
    is_explicit_retry: bool = False

    def reset(self) -> None:
        self.actions = []
        self.retry_run_result = False
        self.stop_run_result = False
        self.is_explicit_retry = False


class TryAgain(Exception):
    """Always retry the executed function when raised."""


NO_RESULT = object()


class DoAttempt:
    pass


class DoSleep(float):
    pass


class BaseAction:
    """Base class for representing actions to take by retry object.

    Concrete implementations must define:
    - __init__: to initialize all necessary fields
    - REPR_FIELDS: class variable specifying attributes to include in repr(self)
    - NAME: for identification in retry object methods and callbacks
    """

    REPR_FIELDS: t.ClassVar[t.Sequence[str]] = ()
    NAME: t.ClassVar[str | None] = None

    @override
    def __repr__(self) -> str:
        state_str = ", ".join(
            f"{field}={getattr(self, field)!r}" for field in self.REPR_FIELDS
        )
        return f"{self.__class__.__name__}({state_str})"

    @override
    def __str__(self) -> str:
        return repr(self)


class RetryAction(BaseAction):
    REPR_FIELDS: t.ClassVar[t.Sequence[str]] = ("sleep",)
    NAME: t.ClassVar[str | None] = "retry"

    def __init__(self, sleep: t.SupportsFloat) -> None:
        self.sleep = float(sleep)


_unset = object()


def _first_set(first: t.Any | object, second: t.Any) -> t.Any:
    return second if first is _unset else first


class RetryError(Exception):
    """Encapsulates the last attempt instance right before giving up."""

    def __init__(
        self,
        last_attempt: "Future | None",
        reason: "RetryStopReason | None" = None,
    ) -> None:
        self.last_attempt = last_attempt
        self.reason = reason or RetryStopReason.LOCAL_POLICY
        super().__init__(last_attempt)

    def reraise(self) -> t.NoReturn:
        if self.last_attempt is None:
            raise self
        if self.last_attempt.failed:
            exc = self.last_attempt.exception()
            # When the user explicitly raises TryAgain (typically from within
            # an "except" block), surface the underlying exception that caused
            # the retry rather than the opaque TryAgain sentinel.
            if isinstance(exc, TryAgain):
                cause = exc.__cause__ or exc.__context__
                if cause is not None:
                    raise cause.with_traceback(cause.__traceback__) from None
            raise self.last_attempt.result()
        raise self

    @override
    def __str__(self) -> str:
        return f"{self.__class__.__name__}[{self.last_attempt}]"


class RetryStopReason(str, enum.Enum):
    """Reason why a retry controller stopped."""

    LOCAL_POLICY = "local_policy"
    ATTEMPT_LIMIT = "attempt_limit"
    DEADLINE = "deadline"
    CANCELLED = "cancelled"


class RetryBudgetError(RetryError):
    """Base class for shared retry budget failures."""


class RetryBudgetExceeded(RetryBudgetError):
    """Base class for exhausted attempt and time budgets."""


class RetryBudgetAttemptsExceeded(RetryBudgetExceeded):
    """Raised when no shared additional attempt remains."""

    reason = RetryStopReason.ATTEMPT_LIMIT


class RetryBudgetDeadlineExceeded(RetryBudgetExceeded):
    """Raised when the shared deadline is reached."""

    reason = RetryStopReason.DEADLINE


class RetryBudgetCancelled(RetryBudgetError):
    """Raised when the shared budget is cancelled."""

    reason = RetryStopReason.CANCELLED


@dataclasses.dataclass(slots=True)
class _RetryBudgetReservation:
    budget: "RetryBudget"
    active: bool = True

    def release(self) -> None:
        self.budget.release_reservation(self)


@dataclasses.dataclass(slots=True)
class _RetryBudgetAttempt:
    budget: "RetryBudget"
    parent: "_RetryBudgetAttempt | None"
    is_root: bool
    child_claimed: bool = False
    token: object | None = None
    id: int = 0


_budget_context: contextvars.ContextVar["RetryBudget | None"] = contextvars.ContextVar(
    "tenacity_retry_budget", default=None
)
_budget_attempt_context: contextvars.ContextVar["_RetryBudgetAttempt | None"] = (
    contextvars.ContextVar("tenacity_retry_budget_attempt", default=None)
)


class AttemptManager:
    """Manage attempt context."""

    def __init__(self, retry_state: "RetryCallState") -> None:
        self.retry_state = retry_state

    def __enter__(self) -> None:
        self._budget_cm: contextlib.AbstractContextManager[object] | None = None
        budget = self.retry_state.budget
        if budget is not None and not self.retry_state.budget_attempt_started:
            reservation = self.retry_state.budget_reservation
            self.retry_state.budget_reservation = None
            try:
                self._budget_cm = budget.attempt(self.retry_state, reservation)
                self._budget_cm.__enter__()
            except RetryBudgetError as exc:
                self.retry_state.stop_reason = exc.reason
                raise
            self.retry_state.budget_attempt_started = True

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: "types.TracebackType | None",
    ) -> bool | None:
        try:
            if exc_type is not None and exc_value is not None:
                self.retry_state.set_exception((exc_type, exc_value, traceback))
                return True  # Swallow exception.
            # We don't have the result, actually.
            self.retry_state.set_result(None)
            return None
        finally:
            if self._budget_cm is not None:
                self._budget_cm.__exit__(exc_type, exc_value, traceback)
                self._budget_cm = None

    async def __aenter__(self) -> None:
        self.__enter__()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: "types.TracebackType | None",
    ) -> bool | None:
        return self.__exit__(exc_type, exc_value, traceback)


class RetryBudget:
    """Shared additional-attempt and deadline budget for nested retries."""

    def __init__(
        self,
        max_extra_attempts: int | None = None,
        max_delay: _utils.time_unit_type | None = None,
        *,
        clock: t.Callable[[], float] | None = None,
        sleep: t.Callable[[float], t.Any] | None = None,
        deadline: _utils.time_unit_type | None = None,
        max_attempts: int | None = None,
        max_retries: int | None = None,
        extra_attempts: int | None = None,
        timeout: _utils.time_unit_type | None = None,
    ) -> None:
        attempt_aliases = (
            max_extra_attempts is not None,
            max_retries is not None,
            extra_attempts is not None,
        )
        if max_attempts is not None and max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if max_extra_attempts is not None and max_extra_attempts < 0:
            raise ValueError("max_extra_attempts must be non-negative")
        if extra_attempts is not None and extra_attempts < 0:
            raise ValueError("extra_attempts must be non-negative")
        if max_retries is not None and max_retries < 0:
            raise ValueError("max_retries must be non-negative")
        if max_attempts is not None and any(attempt_aliases):
            raise TypeError("attempt limit aliases cannot be combined")
        if sum(attempt_aliases) > 1:
            raise TypeError("attempt limit aliases cannot be combined")

        delay_args = (
            max_delay is not None,
            deadline is not None,
            timeout is not None,
        )
        if sum(delay_args) > 1:
            raise TypeError("max_delay, deadline, and timeout are mutually exclusive")

        if max_attempts is not None:
            max_extra_attempts = max_attempts - 1
        elif extra_attempts is not None:
            max_extra_attempts = extra_attempts
        elif max_retries is not None:
            max_extra_attempts = max_retries

        relative_delay = (
            max_delay
            if max_delay is not None
            else deadline
            if deadline is not None
            else timeout
        )

        self.max_extra_attempts = max_extra_attempts
        self.clock = clock or time.monotonic
        self.sleep_func = sleep
        self._relative_delay: float | None = (
            None if relative_delay is None else _utils.to_seconds(relative_delay)
        )
        if self._relative_delay is not None and self._relative_delay < 0:
            raise ValueError("deadline must be non-negative")
        self._deadline: float | None = None
        self._condition = threading.Condition()
        self._cancel_event = threading.Event()
        self._async_events: set[t.Any] = set()
        self.start_time = 0.0
        self.extra_attempts = 0
        self.reserved_attempts = 0
        self.root_started = False
        self._active_attempts: dict[int, _RetryBudgetAttempt] = {}
        self._next_attempt_id = 0
        self._active = 0
        self._cancelled = False

    def __enter__(self) -> "Self":
        previous_budget = _budget_context.get()
        with self._condition:
            if self._active == 0:
                self.extra_attempts = 0
                self.reserved_attempts = 0
                self.root_started = False
                self._active_attempts = {}
                self._next_attempt_id = 0
                self._cancelled = False
                self._cancel_event.clear()
                self._async_events.clear()
                self.start_time = self.clock()
                self._deadline = (
                    self.start_time + self._relative_delay
                    if self._relative_delay is not None
                    else None
                )
            self._active += 1

        self._budget_token = _budget_context.set(self)
        self._attempt_token: object | None = None
        if previous_budget is not self:
            self._attempt_token = _budget_attempt_context.set(None)
        return self

    def __exit__(self, *exc: object) -> None:
        _budget_context.reset(
            t.cast("contextvars.Token[RetryBudget | None]", self._budget_token)
        )
        if self._attempt_token is not None:
            _budget_attempt_context.reset(
                t.cast(
                    "contextvars.Token[_RetryBudgetAttempt | None]",
                    self._attempt_token,
                )
            )
        with self._condition:
            self._active -= 1

    async def __aenter__(self) -> "Self":
        return self.__enter__()

    async def __aexit__(self, *exc: object) -> None:
        self.__exit__(*exc)

    @property
    def cancelled(self) -> bool:
        with self._condition:
            return self._cancelled

    @property
    def remaining_attempts(self) -> int | None:
        with self._condition:
            if self.max_extra_attempts is None:
                return None
            return max(
                0,
                self.max_extra_attempts - self.extra_attempts - self.reserved_attempts,
            )

    @property
    def remaining_time(self) -> float | None:
        if self._deadline is None:
            return None
        return max(0.0, self._deadline - self.clock())

    def cancel(self) -> None:
        with self._condition:
            self._cancelled = True
            events = list(self._async_events)
            self._cancel_event.set()
        for event in events:
            event.set()

    def _expired(self, now: float) -> bool:
        return self._deadline is not None and now >= self._deadline

    def _stopped(self, now: float | None = None) -> RetryStopReason | None:
        if self._cancelled:
            return RetryStopReason.CANCELLED
        current_time = self.clock() if now is None else now
        if self._expired(current_time):
            return RetryStopReason.DEADLINE
        if (
            self.max_extra_attempts is not None
            and self.extra_attempts + self.reserved_attempts >= self.max_extra_attempts
        ):
            return RetryStopReason.ATTEMPT_LIMIT
        return None

    def _error(
        self, reason: RetryStopReason, last_attempt: "Future | None"
    ) -> RetryBudgetError:
        if reason is RetryStopReason.CANCELLED:
            return RetryBudgetCancelled(last_attempt, reason)
        if reason is RetryStopReason.DEADLINE:
            return RetryBudgetDeadlineExceeded(last_attempt, reason)
        return RetryBudgetAttemptsExceeded(last_attempt, reason)

    def reserve(self, retry_state: "RetryCallState") -> _RetryBudgetReservation:
        with self._condition:
            reason = self._stopped(self.clock())
            if reason is not None:
                raise self._error(reason, retry_state.outcome)
            reservation = _RetryBudgetReservation(budget=self)
            self.reserved_attempts += 1

        remaining = self.remaining_time
        if remaining is not None:
            retry_state.upcoming_sleep = max(
                0.0, min(float(retry_state.upcoming_sleep), remaining)
            )
        return reservation

    def release_reservation(self, reservation: _RetryBudgetReservation) -> None:
        with self._condition:
            if reservation.active:
                reservation.active = False
                self.reserved_attempts -= 1

    @contextlib.contextmanager
    def attempt(
        self,
        retry_state: "RetryCallState",
        reservation: _RetryBudgetReservation | None = None,
    ) -> t.Iterator[_RetryBudgetAttempt]:
        lease = self.begin_attempt(retry_state, reservation)
        try:
            yield lease
        finally:
            self.end_attempt(lease)

    def begin_attempt(
        self,
        retry_state: "RetryCallState",
        reservation: _RetryBudgetReservation | None = None,
    ) -> _RetryBudgetAttempt:
        parent_id: int | None = None
        lease_id: int

        with self._condition:
            if reservation is not None:
                if reservation.budget is not self:
                    raise RuntimeError("reservation belongs to a different budget")
                if reservation.active:
                    reservation.active = False
                    self.reserved_attempts -= 1

            reason = self._stopped(self.clock())
            if reason is not None:
                raise self._error(reason, retry_state.outcome)

            current_lease = _budget_attempt_context.get()
            if current_lease is not None and current_lease.budget is self:
                parent_id = current_lease.id
            parent = (
                self._active_attempts.get(parent_id) if parent_id is not None else None
            )

            if reservation is not None:
                is_additional = True
            elif parent_id is None:
                is_additional = self.root_started
                self.root_started = True
            else:
                if parent is None:
                    parent_id = None
                    is_additional = True
                else:
                    is_additional = parent.child_claimed
                    parent.child_claimed = True

            if (
                is_additional
                and self.max_extra_attempts is not None
                and self.extra_attempts + self.reserved_attempts
                >= self.max_extra_attempts
            ):
                raise self._error(RetryStopReason.ATTEMPT_LIMIT, retry_state.outcome)

            if is_additional:
                self.extra_attempts += 1

            lease_id = self._next_attempt_id
            self._next_attempt_id += 1
            lease = _RetryBudgetAttempt(
                budget=self,
                parent=parent,
                is_root=parent_id is None,
                id=lease_id,
            )
            self._active_attempts[lease_id] = lease

        lease.token = _budget_attempt_context.set(lease)
        return lease

    def end_attempt(self, lease: _RetryBudgetAttempt) -> None:
        token = lease.token
        with self._condition:
            self._active_attempts.pop(lease.id, None)
        _budget_attempt_context.reset(
            t.cast("contextvars.Token[_RetryBudgetAttempt | None]", token)
        )

    def sync_sleep(self, seconds: float) -> None:
        remaining = self.remaining_time
        timeout = seconds if remaining is None else min(seconds, remaining)
        timeout = max(0.0, timeout)
        if self.sleep_func is not None and not _utils.is_coroutine_callable(
            self.sleep_func
        ):
            self.sleep_func(timeout)
        else:
            self._cancel_event.wait(timeout)

    async def async_sleep(self, seconds: float) -> None:
        remaining = self.remaining_time
        timeout = seconds if remaining is None else min(seconds, remaining)
        timeout = max(0.0, timeout)

        if self.sleep_func is not None and _utils.is_coroutine_callable(
            self.sleep_func
        ):
            await self.sleep_func(timeout)
            return

        if "trio" in sys.modules:
            import sniffio
            import trio

            if sniffio.current_async_library() == "trio":
                event = trio.Event()
                with self._condition:
                    if self._cancelled:
                        event.set()
                    else:
                        self._async_events.add(event)
                try:
                    with trio.move_on_after(timeout):
                        await event.wait()
                finally:
                    with self._condition:
                        self._async_events.discard(event)
                return

        import asyncio

        event = asyncio.Event()
        with self._condition:
            if self._cancelled:
                event.set()
            else:
                self._async_events.add(event)
        try:
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(event.wait(), timeout=timeout)
        finally:
            with self._condition:
                self._async_events.discard(event)


class BaseRetrying(ABC):
    def __init__(
        self,
        sleep: t.Callable[[int | float], None] = sleep,
        stop: "StopBaseT" = stop_never,
        wait: "WaitBaseT" = wait_none(),
        retry: "RetryBaseT" = retry_if_exception_type(),
        before: t.Callable[["RetryCallState"], None] = before_nothing,
        after: t.Callable[["RetryCallState"], None] = after_nothing,
        before_sleep: t.Callable[["RetryCallState"], None] | None = None,
        reraise: bool = False,
        retry_error_cls: type[RetryError] = RetryError,
        retry_error_callback: t.Callable[["RetryCallState"], t.Any] | None = None,
        name: str | None = None,
        enabled: bool = True,
    ) -> None:
        self.sleep = sleep
        self.stop = stop
        self.wait = wait
        self.retry = retry
        self.before = before
        self.after = after
        self.before_sleep = before_sleep
        self.reraise = reraise
        self._local = threading.local()
        self.retry_error_cls = retry_error_cls
        self.retry_error_callback = retry_error_callback
        self._name = name
        self.enabled = enabled
        self._budget: RetryBudget | None = None

    def copy(
        self,
        sleep: t.Callable[[int | float], None] | object = _unset,
        stop: "StopBaseT | object" = _unset,
        wait: "WaitBaseT | object" = _unset,
        retry: retry_base | object = _unset,
        before: t.Callable[["RetryCallState"], None] | object = _unset,
        after: t.Callable[["RetryCallState"], None] | object = _unset,
        before_sleep: t.Callable[["RetryCallState"], None] | object | None = _unset,
        reraise: bool | object = _unset,
        retry_error_cls: type[RetryError] | object = _unset,
        retry_error_callback: t.Callable[["RetryCallState"], t.Any]
        | object
        | None = _unset,
        name: str | object | None = _unset,
        enabled: bool | object = _unset,
    ) -> "Self":
        """Copy this object with some parameters changed if needed."""
        return self.__class__(
            sleep=_first_set(sleep, self.sleep),
            stop=_first_set(stop, self.stop),
            wait=_first_set(wait, self.wait),
            retry=_first_set(retry, self.retry),
            before=_first_set(before, self.before),
            after=_first_set(after, self.after),
            before_sleep=_first_set(before_sleep, self.before_sleep),
            reraise=_first_set(reraise, self.reraise),
            retry_error_cls=_first_set(retry_error_cls, self.retry_error_cls),
            retry_error_callback=_first_set(
                retry_error_callback, self.retry_error_callback
            ),
            name=_first_set(name, self._name),
            enabled=_first_set(enabled, self.enabled),
        )

    # No @override: object.__getstate__ only exists from Python 3.11 on.
    def __getstate__(self) -> dict[str, t.Any]:
        # Exclude threading.local which cannot be pickled
        return {k: v for k, v in self.__dict__.items() if k != "_local"}

    def __setstate__(self, state: dict[str, t.Any]) -> None:
        self.__dict__.update(state)
        self._local = threading.local()

    @override
    def __str__(self) -> str:
        return self._name if self._name is not None else "<unknown>"

    @override
    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} object at 0x{id(self):x} ("
            f"stop={self.stop}, "
            f"wait={self.wait}, "
            f"sleep={self.sleep}, "
            f"retry={self.retry}, "
            f"before={self.before}, "
            f"after={self.after}, "
            f"name={self._name!r})>"
        )

    @property
    def statistics(self) -> dict[str, t.Any]:
        """Return a dictionary of runtime statistics.

        This dictionary will be empty when the controller has never been
        ran. When it is running or has ran previously it should have (but
        may not) have useful and/or informational keys and values when
        running is underway and/or completed.

        .. warning:: The keys in this dictionary **should** be somewhat
                     stable (not changing), but their existence **may**
                     change between major releases as new statistics are
                     gathered or removed so before accessing keys ensure that
                     they actually exist and handle when they do not.

        .. note:: The values in this dictionary are local to the thread
                  running call (so if multiple threads share the same retrying
                  object - either directly or indirectly) they will each have
                  their own view of statistics they have collected (in the
                  future we may provide a way to aggregate the various
                  statistics from each thread).
        """
        if not hasattr(self._local, "statistics"):
            self._local.statistics = t.cast("dict[str, t.Any]", {})
        return self._local.statistics  # type: ignore[no-any-return]

    @property
    def iter_state(self) -> IterState:
        if not hasattr(self._local, "iter_state"):
            self._local.iter_state = IterState()
        return self._local.iter_state  # type: ignore[no-any-return]

    def wraps(self, f: t.Callable[P, R]) -> "_RetryDecorated[P, R]":
        """Wrap a function for retrying.

        :param f: A function to wrap for retrying.
        """

        @functools.wraps(
            f, functools.WRAPPER_ASSIGNMENTS + ("__defaults__", "__kwdefaults__")
        )
        def wrapped_f(*args: t.Any, **kw: t.Any) -> t.Any:
            if not self.enabled:
                return f(*args, **kw)
            # Always create a copy to prevent overwriting the local contexts when
            # calling the same wrapped functions multiple times in the same stack
            copy = self.copy()
            # Reuse the same statistics dict rather than rebinding the attribute
            # so that the stats stay visible through additional decorators that
            # copy attributes via functools.wraps (which copies the reference to
            # this dict into the outer wrapper's __dict__). See issue #519.
            stats = wrapped_f.statistics  # type: ignore[attr-defined]
            stats.clear()
            copy._local.statistics = stats  # noqa: SLF001
            self._local.statistics = stats
            return copy(f, *args, **kw)

        def retry_with(*args: t.Any, **kwargs: t.Any) -> "_RetryDecorated[P, R]":
            return self.copy(*args, **kwargs).wraps(f)

        # Preserve attributes
        wrapped_f.retry = self  # type: ignore[attr-defined]
        wrapped_f.retry_with = retry_with  # type: ignore[attr-defined]
        wrapped_f.statistics = {}  # type: ignore[attr-defined]

        return t.cast("_RetryDecorated[P, R]", wrapped_f)

    def begin(self) -> None:
        self._budget = _budget_context.get()
        clock = self._budget.clock if self._budget is not None else time.monotonic
        self.statistics.clear()
        self.statistics["start_time"] = clock()
        self.statistics["attempt_number"] = 1
        self.statistics["idle_for"] = 0
        self.statistics["delay_since_first_attempt"] = 0

    def _add_action_func(self, fn: t.Callable[..., t.Any]) -> None:
        self.iter_state.actions.append(fn)

    def _run_retry(self, retry_state: "RetryCallState") -> None:
        self.iter_state.retry_run_result = self.retry(retry_state)

    def _run_wait(self, retry_state: "RetryCallState") -> None:
        # `wait` is annotated as always set, so a type checker sees this guard
        # as always true -- but untyped callers legitimately pass `None` or `0`
        # to mean "no wait", and `sum([])` over an empty list of strategies
        # yields the int 0. Keep honouring those.
        if not self.wait:  # type: ignore[truthy-bool]
            retry_state.upcoming_sleep = 0.0
        else:
            retry_state.upcoming_sleep = self.wait(retry_state)

    def _run_stop(self, retry_state: "RetryCallState") -> None:
        self.statistics["delay_since_first_attempt"] = retry_state.seconds_since_start
        self.iter_state.stop_run_result = self.stop(retry_state)

    def iter(self, retry_state: "RetryCallState") -> DoAttempt | DoSleep | t.Any:
        self._begin_iter(retry_state)
        result = None
        for action in self.iter_state.actions:
            result = action(retry_state)
        return result

    def _begin_iter(self, retry_state: "RetryCallState") -> None:
        self.iter_state.reset()

        fut = retry_state.outcome
        if fut is None:
            if self.before is not None:
                self._add_action_func(self.before)
            self._add_action_func(lambda rs: DoAttempt())
            return

        self.iter_state.is_explicit_retry = fut.failed and isinstance(
            fut.exception(), TryAgain
        )
        if not self.iter_state.is_explicit_retry:
            self._add_action_func(self._run_retry)
        self._add_action_func(self._post_retry_check_actions)

    def _post_retry_check_actions(self, retry_state: "RetryCallState") -> None:
        if not (self.iter_state.is_explicit_retry or self.iter_state.retry_run_result):
            self._add_action_func(lambda rs: rs.outcome.result())
            return

        if self.after is not None:
            self._add_action_func(self.after)

        self._add_action_func(self._run_wait)
        self._add_action_func(self._run_stop)
        self._add_action_func(self._post_stop_actions)

    def _post_stop_actions(self, retry_state: "RetryCallState") -> None:
        budget = retry_state.budget
        if budget is not None and not self.iter_state.stop_run_result:
            self._add_action_func(self._reserve_budget_attempt)
        self._add_action_func(self._post_stop_check_actions)

    def _reserve_budget_attempt(self, retry_state: "RetryCallState") -> None:
        budget = t.cast("RetryBudget", retry_state.budget)
        try:
            retry_state.budget_reservation = budget.reserve(retry_state)
        except RetryBudgetError as exc:
            retry_state.stop_reason = exc.reason
            raise

    def _post_stop_check_actions(self, retry_state: "RetryCallState") -> None:
        if self.iter_state.stop_run_result:
            retry_state.stop_reason = RetryStopReason.LOCAL_POLICY
            if self.retry_error_callback:
                self._add_action_func(self.retry_error_callback)
                return

            def exc_check(rs: "RetryCallState") -> None:
                fut = t.cast("Future", rs.outcome)
                rs.stop_reason = RetryStopReason.LOCAL_POLICY
                retry_exc = self.retry_error_cls(fut)
                if self.reraise:
                    retry_exc.reraise()
                raise retry_exc from fut.exception()

            self._add_action_func(exc_check)
            return

        def next_action(rs: "RetryCallState") -> None:
            sleep = rs.upcoming_sleep
            rs.next_action = RetryAction(sleep)
            rs.idle_for += sleep
            self.statistics["idle_for"] += sleep
            self.statistics["attempt_number"] += 1

        self._add_action_func(next_action)

        if self.before_sleep is not None:
            self._add_action_func(self.before_sleep)

        self._add_action_func(lambda rs: DoSleep(rs.upcoming_sleep))

    def __iter__(self) -> t.Generator[AttemptManager, None, None]:
        if not self.enabled:
            retry_state = RetryCallState(self, fn=None, args=(), kwargs={})
            yield AttemptManager(retry_state=retry_state)
            if retry_state.outcome is not None and retry_state.outcome.failed:
                raise retry_state.outcome.exception()  # type: ignore[misc]
            return

        self.begin()

        retry_state = RetryCallState(self, fn=None, args=(), kwargs={})
        while True:
            reservation = retry_state.budget_reservation
            try:
                do = self.iter(retry_state=retry_state)
            except BaseException:
                if reservation is not None:
                    reservation.release()
                raise
            if isinstance(do, DoAttempt):
                yield AttemptManager(retry_state=retry_state)
            elif isinstance(do, DoSleep):
                retry_state.prepare_for_next_attempt()
                retry_state.budget_attempt_started = False
                try:
                    self._sleep(do, retry_state.budget)
                except BaseException:
                    if reservation is not None:
                        reservation.release()
                    raise
            else:
                break

    @abstractmethod
    def __call__(
        self,
        fn: t.Callable[..., WrappedFnReturnT],
        *args: t.Any,
        **kwargs: t.Any,
    ) -> WrappedFnReturnT:
        pass


class Retrying(BaseRetrying):
    """Retrying controller."""

    @override
    def __call__(
        self,
        fn: t.Callable[..., WrappedFnReturnT],
        *args: t.Any,
        **kwargs: t.Any,
    ) -> WrappedFnReturnT:
        if not self.enabled:
            return fn(*args, **kwargs)

        self.begin()

        retry_state = RetryCallState(retry_object=self, fn=fn, args=args, kwargs=kwargs)
        while True:
            reservation = retry_state.budget_reservation
            try:
                do = self.iter(retry_state=retry_state)
            except BaseException:
                if reservation is not None:
                    reservation.release()
                raise
            if isinstance(do, DoAttempt):
                budget_lease: _RetryBudgetAttempt | None = None
                budget = retry_state.budget
                if budget is not None and not retry_state.budget_attempt_started:
                    try:
                        budget_lease = budget.begin_attempt(
                            retry_state, retry_state.budget_reservation
                        )
                        retry_state.budget_reservation = None
                        retry_state.budget_attempt_started = True
                    except RetryBudgetError as exc:
                        retry_state.stop_reason = exc.reason
                        if retry_state.budget_reservation is not None:
                            retry_state.budget_reservation.release()
                            retry_state.budget_reservation = None
                        raise
                reservation = None
                try:
                    try:
                        result = fn(*args, **kwargs)
                    except BaseException:
                        retry_state.set_exception(sys.exc_info())  # type: ignore[arg-type]
                    else:
                        retry_state.set_result(result)
                finally:
                    if budget_lease is not None:
                        budget.end_attempt(budget_lease)
                    retry_state.budget_attempt_started = False
            elif isinstance(do, DoSleep):
                reservation = retry_state.budget_reservation
                retry_state.prepare_for_next_attempt()
                retry_state.budget_attempt_started = False
                try:
                    self._sleep(do, retry_state.budget)
                except BaseException:
                    if reservation is not None:
                        reservation.release()
                    raise
            else:
                return do  # type: ignore[no-any-return]

    def _sleep(self, seconds: float, budget: RetryBudget | None) -> None:
        if budget is not None:
            budget.sync_sleep(float(seconds))
        else:
            self.sleep(seconds)


class Future(futures.Future[t.Any]):
    """Encapsulates a (future or past) attempted call to a target function."""

    def __init__(self, attempt_number: int) -> None:
        super().__init__()
        self.attempt_number = attempt_number

    @property
    def failed(self) -> bool:
        """Return whether a exception is being held in this future."""
        return self.exception() is not None

    @classmethod
    def construct(
        cls, attempt_number: int, value: t.Any, has_exception: bool
    ) -> "Future":
        """Construct a new Future object."""
        fut = cls(attempt_number)
        if has_exception:
            fut.set_exception(value)
        else:
            fut.set_result(value)
        return fut


class RetryCallState:
    """State related to a single call wrapped with Retrying."""

    def __init__(
        self,
        retry_object: BaseRetrying,
        fn: WrappedFn | None,
        args: t.Any,
        kwargs: t.Any,
    ) -> None:
        #: Retry call start timestamp
        self.budget = _budget_context.get()
        self.time_func = (
            self.budget.clock if self.budget is not None else time.monotonic
        )
        self.start_time = self.time_func()
        #: Retry manager object
        self.retry_object = retry_object
        #: Function wrapped by this retry call
        self.fn = fn
        #: Arguments of the function wrapped by this retry call
        self.args = args
        #: Keyword arguments of the function wrapped by this retry call
        self.kwargs = kwargs

        #: The number of the current attempt
        self.attempt_number: int = 1
        #: Last outcome (result or exception) produced by the function
        self.outcome: Future | None = None
        #: Timestamp of the last outcome
        self.outcome_timestamp: float | None = None
        #: Time spent sleeping in retries
        self.idle_for: float = 0.0
        #: Next action as decided by the retry manager
        self.next_action: RetryAction | None = None
        #: Next sleep time as decided by the retry manager.
        self.upcoming_sleep: float = 0.0

        #: Shared-budget reservation for the next physical attempt.
        self.budget_reservation: _RetryBudgetReservation | None = None
        #: Whether the shared-budget attempt lease is active.
        self.budget_attempt_started = False
        #: Reason this retry controller is stopping.
        self.stop_reason: RetryStopReason | None = None

    def get_fn_name(self) -> str:
        """Get the name of the function being retried.

        Returns the fully-qualified name of the wrapped function when used as a
        decorator, the ``name`` passed to the retrying object when used as a
        context manager, or ``"<unknown>"`` if neither is available.
        """
        if self.fn is not None:
            return _utils.get_callback_name(self.fn)
        return str(self.retry_object)

    @property
    def seconds_since_start(self) -> float | None:
        if self.outcome_timestamp is None:
            return None
        return self.outcome_timestamp - self.start_time

    def prepare_for_next_attempt(self) -> None:
        self.outcome = None
        self.outcome_timestamp = None
        self.attempt_number += 1
        self.next_action = None

    def set_result(self, val: t.Any) -> None:
        ts = self.time_func()
        fut = Future(self.attempt_number)
        fut.set_result(val)
        self.outcome, self.outcome_timestamp = fut, ts

    def set_exception(
        self,
        exc_info: tuple[
            type[BaseException], BaseException, "types.TracebackType | None"
        ],
    ) -> None:
        ts = self.time_func()
        fut = Future(self.attempt_number)
        fut.set_exception(exc_info[1])
        self.outcome, self.outcome_timestamp = fut, ts

    @override
    def __repr__(self) -> str:
        if self.outcome is None:
            result = "none yet"
        elif self.outcome.failed:
            exception = self.outcome.exception()
            result = f"failed ({exception.__class__.__name__} {exception})"
        else:
            result = f"returned {self.outcome.result()}"

        slept = float(round(self.idle_for, 2))
        clsname = self.__class__.__name__
        return f"<{clsname} {id(self)}: attempt #{self.attempt_number}; slept for {slept}; last result: {result}>"


class _RetryDecorated(t.Protocol[P, R]):
    """Protocol for functions decorated with @retry.

    Provides the original callable signature plus retry control attributes.
    """

    retry: "BaseRetrying"
    statistics: dict[str, t.Any]
    # Set by functools.wraps on the retry wrapper. Declared so that the
    # statistics stay accessible in a type-safe way even when the decorated
    # function is further wrapped by another functools.wraps-based decorator
    # (which copies these attributes onto the outer wrapper). See issue #519.
    __wrapped__: "_RetryDecorated[P, R]"

    def retry_with(self, *args: t.Any, **kwargs: t.Any) -> "_RetryDecorated[P, R]": ...

    def __call__(self, *args: P.args, **kwargs: P.kwargs) -> R: ...

    # Without an explicit `__get__`, type checkers treat `_RetryDecorated` as a
    # plain callable attribute rather than a descriptor, so accessing a
    # decorated method through an instance keeps demanding the original
    # unbound signature (including `self`). Declaring `__get__` here fixes
    # attribute access on both the class and an instance; the runtime object
    # is a real function (see `wraps` above), which already binds correctly,
    # so this only affects static analysis. See issue #532.
    @t.overload
    def __get__(
        self, instance: None, owner: type | None = None
    ) -> "_RetryDecorated[P, R]": ...
    @t.overload
    def __get__(
        self, instance: object, owner: type | None = None
    ) -> "_RetryDecorated[..., R]": ...


class _AsyncRetryDecorator(t.Protocol):
    @t.overload
    def __call__(
        self, fn: "t.Callable[P, types.CoroutineType[t.Any, t.Any, R]]"
    ) -> "_RetryDecorated[P, types.CoroutineType[t.Any, t.Any, R]]": ...
    @t.overload
    def __call__(
        self, fn: t.Callable[P, t.Coroutine[t.Any, t.Any, R]]
    ) -> "_RetryDecorated[P, t.Coroutine[t.Any, t.Any, R]]": ...
    @t.overload
    def __call__(
        self, fn: t.Callable[P, t.Awaitable[R]]
    ) -> "_RetryDecorated[P, t.Awaitable[R]]": ...
    @t.overload
    def __call__(
        self, fn: t.Callable[P, R]
    ) -> "_RetryDecorated[P, t.Awaitable[R]]": ...


@t.overload
def retry(func: t.Callable[P, R]) -> _RetryDecorated[P, R]: ...


@t.overload
def retry(
    *,
    sleep: t.Callable[[int | float], t.Awaitable[None]],
    stop: "StopBaseT" = ...,
    wait: "WaitBaseT" = ...,
    retry: "RetryBaseT | tasyncio.retry.RetryBaseT" = ...,
    before: t.Callable[["RetryCallState"], t.Awaitable[None] | None] = ...,
    after: t.Callable[["RetryCallState"], t.Awaitable[None] | None] = ...,
    before_sleep: t.Callable[["RetryCallState"], t.Awaitable[None] | None] | None = ...,
    reraise: bool = ...,
    retry_error_cls: type["RetryError"] = ...,
    retry_error_callback: t.Callable[["RetryCallState"], t.Any | t.Awaitable[t.Any]]
    | None = ...,
    enabled: bool = ...,
) -> _AsyncRetryDecorator: ...


@t.overload
def retry(
    sleep: t.Callable[[int | float], None] = sleep,
    stop: "StopBaseT" = stop_never,
    wait: "WaitBaseT" = wait_none(),
    retry: "RetryBaseT | tasyncio.retry.RetryBaseT" = retry_if_exception_type(),
    before: t.Callable[["RetryCallState"], t.Awaitable[None] | None] = before_nothing,
    after: t.Callable[["RetryCallState"], t.Awaitable[None] | None] = after_nothing,
    before_sleep: t.Callable[["RetryCallState"], t.Awaitable[None] | None]
    | None = None,
    reraise: bool = False,
    retry_error_cls: type["RetryError"] = RetryError,
    retry_error_callback: t.Callable[["RetryCallState"], t.Any | t.Awaitable[t.Any]]
    | None = None,
    enabled: bool = True,
) -> t.Callable[[t.Callable[P, R]], _RetryDecorated[P, R]]: ...


def retry(*dargs: t.Any, **dkw: t.Any) -> t.Any:
    """Wrap a function with a new `Retrying` object.

    :param dargs: positional arguments passed to Retrying object
    :param dkw: keyword arguments passed to the Retrying object
    """
    # support both @retry and @retry() as valid syntax
    if len(dargs) == 1 and callable(dargs[0]):
        return retry()(dargs[0])

    def wrap(f: t.Callable[P, R]) -> _RetryDecorated[P, R]:
        if isinstance(f, retry_base):
            warnings.warn(
                f"Got retry_base instance ({f.__class__.__name__}) as callable argument, "
                f"this will probably hang indefinitely (did you mean retry={f.__class__.__name__}(...)?)",
                stacklevel=2,
            )
        r: BaseRetrying
        sleep = dkw.get("sleep")
        if _utils.is_coroutine_callable(f) or (
            sleep is not None and _utils.is_coroutine_callable(sleep)
        ):
            r = AsyncRetrying(*dargs, **dkw)
        elif (
            _has_tornado()
            and hasattr(tornado.gen, "is_coroutine_function")
            and tornado.gen.is_coroutine_function(f)
        ):
            r = TornadoRetrying(*dargs, **dkw)
        else:
            r = Retrying(*dargs, **dkw)

        return r.wraps(f)

    return wrap


from tenacity.asyncio import AsyncRetrying  # noqa: E402

if _has_tornado():
    from tenacity.tornadoweb import TornadoRetrying


__all__ = [
    "NO_RESULT",
    "AsyncRetrying",
    "AttemptManager",
    "BaseAction",
    "BaseRetrying",
    "DoAttempt",
    "DoSleep",
    "Future",
    "RetryAction",
    "RetryBudget",
    "RetryBudgetAttemptsExceeded",
    "RetryBudgetCancelled",
    "RetryBudgetDeadlineExceeded",
    "RetryBudgetError",
    "RetryBudgetExceeded",
    "RetryCallState",
    "RetryError",
    "RetryStopReason",
    "Retrying",
    "TryAgain",
    "WrappedFn",
    "after_log",
    "after_nothing",
    "before_log",
    "before_nothing",
    "before_sleep_log",
    "before_sleep_nothing",
    "retry",
    "retry_all",
    "retry_always",
    "retry_any",
    "retry_base",
    "retry_if_exception",
    "retry_if_exception_cause_type",
    "retry_if_exception_message",
    "retry_if_exception_type",
    "retry_if_not_exception_message",
    "retry_if_not_exception_type",
    "retry_if_not_result",
    "retry_if_result",
    "retry_never",
    "retry_unless_exception_type",
    "sleep",
    "sleep_using_event",
    "stop_after_attempt",
    "stop_after_delay",
    "stop_all",
    "stop_any",
    "stop_before_delay",
    "stop_never",
    "stop_when_event_set",
    "wait_chain",
    "wait_combine",
    "wait_exception",
    "wait_exponential",
    "wait_exponential_jitter",
    "wait_fixed",
    "wait_full_jitter",
    "wait_incrementing",
    "wait_none",
    "wait_random",
    "wait_random_exponential",
]
