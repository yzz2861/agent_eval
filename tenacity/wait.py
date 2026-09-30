# Copyright 2016–2021 Julien Danjou
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

import abc
import math
import random
import time
import typing
import warnings
from collections.abc import Iterable
from concurrent.futures import Future as FutureResult
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

from tenacity import _utils
from tenacity._utils import override
from tenacity.stop import stop_base

if typing.TYPE_CHECKING:
    from tenacity import Future, RetryCallState


class wait_base(abc.ABC):
    """Abstract base class for wait strategies."""

    @abc.abstractmethod
    def __call__(self, retry_state: "RetryCallState") -> float:
        pass

    def __add__(self, other: "wait_base") -> "wait_combine":
        return wait_combine(self, other)

    # `other` is `int` rather than `Literal[0]` because typeshed's `sum()`
    # protocol demands `__radd__(x: int)`; narrowing it would make every
    # `sum()` over wait strategies need a `type: ignore`. A non-zero number is
    # rejected at runtime instead, below.
    def __radd__(self, other: "WaitBaseT | int") -> "wait_combine | wait_base":
        if isinstance(other, int):
            # `sum()` seeds its accumulator with the int 0; treat that as
            # identity so summing a list of strategies works. Any other number
            # is not a wait strategy, and saying so here raises TypeError at
            # the `+` rather than building a combination that fails when called.
            if other == 0:
                return self
            return NotImplemented
        # A plain callable -- `WaitBaseT` admits those, and a function has no
        # `__add__` of its own to handle `callable + strategy`.
        return wait_combine(self, other)


WaitBaseT = wait_base | typing.Callable[["RetryCallState"], float | int]

RetryAfterValueT = object
RetryAfterExtractorT = typing.Callable[[typing.Any], RetryAfterValueT]
RetryAfterServerTimeValueT = object
ServerTimeExtractorT = typing.Callable[
    [typing.Any], RetryAfterServerTimeValueT
]
MalformedPolicyT = typing.Literal["raise", "local", "zero"]
ExpiredPolicyT = typing.Literal["raise", "local", "zero"]
DuplicatePolicyT = typing.Literal["latest", "first", "raise", "local"]
RetryAfterWaitReasonT = typing.Literal[
    "server",
    "missing",
    "malformed",
    "duplicate",
    "expired",
]


@dataclass(frozen=True, slots=True)
class RetryAfterWaitDecision:
    """Information about a ``wait_retry_after`` decision.

    ``server_wait`` is the waiting time required by the upstream service,
    ``local_wait`` is the time suggested by the local backoff strategy, and
    ``wait`` is the final waiting time. When no usable ``Retry-After`` value
    is present, ``server_wait`` is ``None``.
    """

    wait: float
    local_wait: float
    server_wait: float | None
    retry_after_values: tuple[typing.Any, ...]
    selected_retry_after: typing.Any
    retry_after_at: datetime | None
    server_time: datetime | None
    clock_offset: float | None
    tolerance: float
    reason: RetryAfterWaitReasonT
    error: BaseException | None = None


class wait_fixed(wait_base):
    """Wait strategy that waits a fixed amount of time between each retry."""

    def __init__(self, wait: _utils.time_unit_type) -> None:
        self.wait_fixed = _utils.to_seconds(wait)

    @override
    def __call__(self, retry_state: "RetryCallState") -> float:
        return self.wait_fixed


class wait_none(wait_fixed):
    """Wait strategy that doesn't wait at all before retrying."""

    def __init__(self) -> None:
        super().__init__(0)


class wait_random(wait_base):
    """Wait strategy that waits a random amount of time between min/max."""

    def __init__(
        self, min: _utils.time_unit_type = 0, max: _utils.time_unit_type = 1
    ) -> None:
        self.wait_random_min = _utils.to_seconds(min)
        self.wait_random_max = _utils.to_seconds(max)

    @override
    def __call__(self, retry_state: "RetryCallState") -> float:
        return self.wait_random_min + (
            random.random() * (self.wait_random_max - self.wait_random_min)
        )


class wait_combine(wait_base):
    """Combine several waiting strategies."""

    def __init__(self, *strategies: "WaitBaseT") -> None:
        self.wait_funcs = strategies

    @override
    def __call__(self, retry_state: "RetryCallState") -> float:
        # Positional, like `BaseRetrying._run_wait`: a `WaitBaseT` callable is
        # only guaranteed to take the state positionally, so passing it by
        # keyword crashed on any callable whose parameter is not named
        # `retry_state`.
        return float(sum(x(retry_state) for x in self.wait_funcs))


class wait_chain(wait_base):
    """Chain two or more waiting strategies.

    If all strategies are exhausted, the very last strategy is used
    thereafter.

    For example::

        @retry(wait=wait_chain(*[wait_fixed(1) for i in range(3)] +
                               [wait_fixed(2) for j in range(5)] +
                               [wait_fixed(5) for k in range(4)]))
        def wait_chained():
            print("Wait 1s for 3 attempts, 2s for 5 attempts and 5s "
                  "thereafter.")
    """

    def __init__(self, *strategies: wait_base) -> None:
        if not strategies:
            raise ValueError("wait_chain() requires at least one strategy")
        self.strategies = strategies

    @override
    def __call__(self, retry_state: "RetryCallState") -> float:
        wait_func_no = min(max(retry_state.attempt_number, 1), len(self.strategies))
        wait_func = self.strategies[wait_func_no - 1]
        return wait_func(retry_state=retry_state)


class wait_exception(wait_base):
    """Wait strategy that waits the amount of time returned by the predicate.

    The predicate is passed the exception object. Based on the exception, the
    user can decide how much time to wait before retrying.

    For example::

        def http_error(exception: BaseException) -> float:
            if (
                isinstance(exception, requests.HTTPError)
                and exception.response.status_code == requests.codes.too_many_requests
            ):
                return float(exception.response.headers.get("Retry-After", "1"))
            return 60.0


        @retry(
            stop=stop_after_attempt(3),
            wait=wait_exception(http_error),
        )
        def http_get_request(url: str) -> None:
            response = requests.get(url)
            response.raise_for_status()
    """

    def __init__(self, predicate: typing.Callable[[BaseException], float]) -> None:
        self.predicate = predicate

    @override
    def __call__(self, retry_state: "RetryCallState") -> float:
        if retry_state.outcome is None:
            raise RuntimeError("__call__() called before outcome was set")

        exception = retry_state.outcome.exception()
        if exception is None:
            raise RuntimeError("outcome failed but the exception is None")
        return self.predicate(exception)


def _coerce_retry_after_value(value: object) -> datetime | timedelta:
    if isinstance(value, bool):
        raise ValueError("Retry-After must not be a boolean")

    if isinstance(value, bytes):
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("Retry-After must contain ASCII text") from exc

    if isinstance(value, datetime):
        return value

    if isinstance(value, timedelta):
        return value

    if isinstance(value, int | float):
        if not math.isfinite(value):
            raise ValueError("Retry-After delay must be finite")
        if value < 0:
            raise ValueError("Retry-After delay must not be negative")
        return timedelta(seconds=float(value))

    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("Retry-After must not be empty")

        try:
            delay = float(text)
        except ValueError:
            try:
                parsed = parsedate_to_datetime(text)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"invalid Retry-After value: {value!r}") from exc
            if parsed is None:
                raise ValueError(f"invalid Retry-After value: {value!r}")
            return parsed

        if not math.isfinite(delay) or delay < 0:
            raise ValueError("Retry-After delay must be a non-negative finite number")
        return timedelta(seconds=delay)

    raise ValueError(f"unsupported Retry-After value: {value!r}")


def _coerce_server_time(value: object) -> datetime:
    if value is None:
        raise ValueError("server time must not be None")

    if isinstance(value, bytes):
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("server time must contain ASCII text") from exc

    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        try:
            parsed = parsedate_to_datetime(text)
        except (TypeError, ValueError):
            try:
                parsed = datetime.fromisoformat(text)
            except ValueError as exc:
                raise ValueError(f"invalid server time value: {value!r}") from exc
        if parsed is None:
            raise ValueError(f"invalid server time value: {value!r}")
    else:
        raise ValueError(f"unsupported server time value: {value!r}")

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class _ExpiredRetryAfter(ValueError):
    pass


class retry_after_deadline_stop(stop_base):
    """Stop before a wait that would cross a ``wait_retry_after`` deadline."""

    def __init__(self, wait_strategy: "wait_retry_after") -> None:
        self.wait_strategy = wait_strategy

    @override
    def __call__(self, retry_state: "RetryCallState") -> bool:
        max_delay = self.wait_strategy.max_total_delay
        seconds_since_start = retry_state.seconds_since_start
        if max_delay is None or seconds_since_start is None:
            return False
        return seconds_since_start + retry_state.upcoming_sleep >= max_delay


class wait_retry_after(wait_base):
    """Wait according to a result-provided ``Retry-After`` value.

    ``retry_after_extractor`` receives the value returned by the retried
    callable and returns a delay in seconds, an HTTP-date, a timedelta, a
    datetime, or a sequence of those values. Exceptions are inspected through
    their ``RetryCallState.outcome``, so the extractor can read a response
    stored on an exception.

    ``wait`` is the local backoff used when no usable ``Retry-After`` value is
    available. The final sleep is the later of the local recommendation and
    the server requirement, so server values are never shortened.

    Malformed and expired values can raise, use the local recommendation, or
    use a zero-second server suggestion. Repeated values can select the latest
    or first value, raise, or use the local recommendation. When the upstream
    response date is unavailable, ``clock_skew_tolerance`` is added to
    HTTP-date waits to avoid requesting before the server's intended time.

    Use :meth:`with_total_delay` or :class:`tenacity.stop_before_delay` to
    stop without sleeping when the complete required wait does not fit within
    the overall deadline.
    """

    def __init__(
        self,
        retry_after_extractor: RetryAfterExtractorT,
        *,
        wait: WaitBaseT | None = None,
        server_time_extractor: ServerTimeExtractorT | None = None,
        clock_skew_tolerance: _utils.time_unit_type = 1,
        on_malformed: MalformedPolicyT = "raise",
        on_expired: ExpiredPolicyT = "local",
        on_duplicate: DuplicatePolicyT = "latest",
        on_decision: typing.Callable[[RetryAfterWaitDecision], None] | None = None,
    ) -> None:
        policies = {
            "on_malformed": (on_malformed, {"raise", "local", "zero"}),
            "on_expired": (on_expired, {"raise", "local", "zero"}),
            "on_duplicate": (
                on_duplicate,
                {"latest", "first", "raise", "local"},
            ),
        }
        for name, (policy, allowed) in policies.items():
            if policy not in allowed:
                raise ValueError(f"invalid {name}: {policy!r}")

        tolerance = _utils.to_seconds(clock_skew_tolerance)
        if tolerance < 0 or not math.isfinite(tolerance):
            raise ValueError("clock_skew_tolerance must be finite and non-negative")

        self.retry_after_extractor = retry_after_extractor
        self.local_wait = wait
        self.server_time_extractor = server_time_extractor
        self.clock_skew_tolerance = tolerance
        self.on_malformed = on_malformed
        self.on_expired = on_expired
        self.on_duplicate = on_duplicate
        self.on_decision = on_decision
        self.max_total_delay: float | None = None

    def with_total_delay(
        self, max_total_delay: _utils.time_unit_type
    ) -> tuple["wait_retry_after", retry_after_deadline_stop]:
        deadline = _utils.to_seconds(max_total_delay)
        if deadline < 0 or not math.isfinite(deadline):
            raise ValueError("max_total_delay must be finite and non-negative")
        self.max_total_delay = deadline
        return self, retry_after_deadline_stop(self)

    @override
    def __call__(self, retry_state: "RetryCallState") -> float:
        outcome = retry_state.outcome
        if outcome is None:
            raise RuntimeError("__call__() called before outcome was set")

        local_wait = max(0.0, self._local_wait(retry_state))
        result = self._get_outcome_result(outcome)
        raw_values = self._normalize_values(self.retry_after_extractor(result))

        selected_value: typing.Any = None
        retry_after_at: datetime | None = None
        server_time: datetime | None = None
        clock_offset: float | None = None
        server_wait: float | None = None
        reason: RetryAfterWaitReasonT
        error: BaseException | None = None
        final_wait = local_wait

        if not raw_values:
            reason = "missing"
        elif len(raw_values) > 1:
            reason = "duplicate"
            error = ValueError(
                f"received multiple Retry-After values: {raw_values!r}"
            )
            if self.on_duplicate == "first":
                selected_value = raw_values[0]
                error = None
            elif self.on_duplicate == "latest":
                selected_duplicate = self._select_latest_duplicate(raw_values, result)
                if selected_duplicate is not None:
                    selected_value = selected_duplicate
                    error = None
            elif self.on_duplicate == "raise":
                self._report(
                    retry_state, final_wait, local_wait, None, raw_values,
                    selected_value, None, None, None, reason, error,
                )
                raise error

        if error is None and (raw_values or selected_value is not None):
            if selected_value is None:
                selected_value = raw_values[0]
            try:
                parsed = _coerce_retry_after_value(selected_value)
                if isinstance(parsed, datetime):
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=timezone.utc)
                    retry_after_at = parsed.astimezone(timezone.utc)

                    if self.server_time_extractor is not None:
                        server_time = _coerce_server_time(
                            self.server_time_extractor(result)
                        )
                        outcome_wall_time = retry_state.outcome_wall_time
                        if outcome_wall_time is not None:
                            clock_offset = (
                                server_time.timestamp() - outcome_wall_time
                            )
                            server_wait = (
                                retry_after_at - server_time
                            ).total_seconds()
                        else:
                            server_wait = (
                                retry_after_at.timestamp() - time.time()
                            ) + self.clock_skew_tolerance
                    else:
                        server_wait = (
                            retry_after_at.timestamp() - time.time()
                        ) + self.clock_skew_tolerance
                else:
                    server_wait = parsed.total_seconds()

                if server_wait < 0:
                    raise _ExpiredRetryAfter(
                        f"Retry-After time is in the past: {selected_value!r}"
                    )
                reason = "server"
                final_wait = max(local_wait, server_wait)
            except _ExpiredRetryAfter as exc:
                reason = "expired"
                error = exc
                if self.on_expired == "raise":
                    self._report(
                        retry_state, final_wait, local_wait, server_wait,
                        raw_values, selected_value, retry_after_at,
                        server_time, clock_offset, reason, error,
                    )
                    raise
                server_wait, final_wait = self._invalid_wait(
                    self.on_expired, local_wait
                )
            except (TypeError, ValueError) as exc:
                reason = "malformed"
                error = exc
                if self.on_malformed == "raise":
                    self._report(
                        retry_state, final_wait, local_wait, None, raw_values,
                        selected_value, retry_after_at, server_time,
                        clock_offset, reason, error,
                    )
                    raise
                server_wait, final_wait = self._invalid_wait(
                    self.on_malformed, local_wait
                )

        self._report(
            retry_state,
            final_wait,
            local_wait,
            server_wait,
            raw_values,
            selected_value,
            retry_after_at,
            server_time,
            clock_offset,
            reason,
            error,
        )
        return final_wait

    def _local_wait(self, retry_state: "RetryCallState") -> float:
        if self.local_wait is None:
            return 0.0
        return float(self.local_wait(retry_state))

    def _select_latest_duplicate(
        self, raw_values: tuple[object, ...], result: object
    ) -> object | None:
        candidates = []
        if self.server_time_extractor is not None:
            try:
                response_server_time = _coerce_server_time(
                    self.server_time_extractor(result)
                )
            except (TypeError, ValueError):
                response_server_time = None
        else:
            response_server_time = None

        now = time.time()
        for value in raw_values:
            try:
                parsed = _coerce_retry_after_value(value)
            except (TypeError, ValueError):
                continue
            if isinstance(parsed, timedelta):
                order = now + parsed.total_seconds()
            else:
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                parsed = parsed.astimezone(timezone.utc)
                if response_server_time is None:
                    order = parsed.timestamp()
                    order += self.clock_skew_tolerance
                else:
                    order = now + (
                        parsed - response_server_time
                    ).total_seconds()
            candidates.append((order, value))

        if not candidates:
            return None
        return max(candidates, key=lambda candidate: candidate[0])[1]

    @staticmethod
    def _get_outcome_result(outcome: "Future | object") -> object:
        if isinstance(outcome, FutureResult):
            exception = outcome.exception()
            if exception is not None:
                return exception
            return outcome.result()
        return outcome

    @staticmethod
    def _invalid_wait(
        policy: MalformedPolicyT | ExpiredPolicyT, local_wait: float
    ) -> tuple[float | None, float]:
        if policy == "zero":
            return 0.0, local_wait
        return None, local_wait

    @staticmethod
    def _normalize_values(value: object) -> tuple[object, ...]:
        if value is None:
            return ()
        if isinstance(
            value, str | bytes | datetime | timedelta | int | float
        ) and not isinstance(value, bool):
            return (value,)
        if isinstance(value, Iterable):
            return tuple(item for item in value if item is not None)
        return (value,)

    def _report(
        self,
        retry_state: "RetryCallState",
        final_wait: float,
        local_wait: float,
        server_wait: float | None,
        raw_values: tuple[typing.Any, ...],
        selected_value: typing.Any,
        retry_after_at: datetime | None,
        server_time: datetime | None,
        clock_offset: float | None,
        reason: RetryAfterWaitReasonT,
        error: BaseException | None,
    ) -> None:
        decision = RetryAfterWaitDecision(
            wait=final_wait,
            local_wait=local_wait,
            server_wait=server_wait,
            retry_after_values=raw_values,
            selected_retry_after=selected_value,
            retry_after_at=retry_after_at,
            server_time=server_time,
            clock_offset=clock_offset,
            tolerance=self.clock_skew_tolerance,
            reason=reason,
            error=error,
        )
        retry_state.retry_after_wait_decision = decision
        if self.on_decision is not None:
            self.on_decision(decision)


class wait_incrementing(wait_base):
    """Wait an incremental amount of time after each attempt.

    Starting at a starting value and incrementing by a value for each attempt
    (and restricting the upper limit to some maximum value).
    """

    def __init__(
        self,
        start: _utils.time_unit_type = 0,
        increment: _utils.time_unit_type = 100,
        max: _utils.time_unit_type = _utils.MAX_WAIT,
    ) -> None:
        self.start = _utils.to_seconds(start)
        self.increment = _utils.to_seconds(increment)
        self.max = _utils.to_seconds(max)

    @override
    def __call__(self, retry_state: "RetryCallState") -> float:
        result = self.start + (self.increment * (retry_state.attempt_number - 1))
        return max(0, min(result, self.max))


class wait_exponential(wait_base):
    """Wait strategy that applies exponential backoff.

    It allows for a customized multiplier and an ability to restrict the
    upper and lower limits to some maximum and minimum value.

    The intervals are fixed (i.e. there is no jitter), so this strategy is
    suitable for balancing retries against latency when a required resource is
    unavailable for an unknown duration, but *not* suitable for resolving
    contention between multiple processes for a shared resource. Use
    wait_random_exponential for the latter case.
    """

    def __init__(
        self,
        multiplier: float = 1,
        max: _utils.time_unit_type = _utils.MAX_WAIT,
        exp_base: float = 2,
        min: _utils.time_unit_type = 0,
    ) -> None:
        self.multiplier = multiplier
        self.min = _utils.to_seconds(min)
        self.max = _utils.to_seconds(max)
        self.exp_base = exp_base

    @override
    def __call__(self, retry_state: "RetryCallState") -> float:
        exponent = retry_state.attempt_number - 1
        if (
            self.multiplier > 0
            and self.max > 0
            and self.exp_base > 1
            and math.isfinite(self.max)
            and exponent
            > math.log(self.max, self.exp_base)
            - math.log(self.multiplier, self.exp_base)
        ):
            return max(max(0, self.min), self.max)
        try:
            exp = self.exp_base**exponent
            result = self.multiplier * exp
        except OverflowError:
            return self.max
        return max(max(0, self.min), min(result, self.max))


class wait_random_exponential(wait_exponential):
    """Random wait with exponentially widening window.

    An exponential backoff strategy used to mediate contention between multiple
    uncoordinated processes for a shared resource in distributed systems. This
    is the sense in which "exponential backoff" is meant in e.g. Ethernet
    networking, and corresponds to the "Full Jitter" algorithm described in
    this blog post:

    https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/

    Each retry occurs at a random time in a geometrically expanding interval.
    It allows for a custom multiplier and an ability to restrict the upper
    limit of the random interval to some maximum value.

    Example::

        wait_random_exponential(multiplier=0.5,  # initial window 0.5s
                                max=60)          # max 60s timeout

    When waiting for an unavailable resource to become available again, as
    opposed to trying to resolve contention for a shared resource, the
    wait_exponential strategy (which uses a fixed interval) may be preferable.

    """

    @override
    def __call__(self, retry_state: "RetryCallState") -> float:
        high = super().__call__(retry_state=retry_state)
        return random.uniform(self.min, high)


class wait_exponential_jitter(wait_base):
    """Wait strategy that applies exponential backoff and jitter.

    It allows for a customized multiplier, maximum wait, jitter and minimum.

    This implements the strategy described here:
    https://cloud.google.com/storage/docs/retry-strategy

    The wait time is max(min, min(multiplier * 2**n + random.uniform(0, jitter), maximum))
    where n is the retry count.
    """

    def __init__(
        self,
        initial: float = 1,
        max: _utils.time_unit_type = _utils.MAX_WAIT,
        exp_base: float = 2,
        jitter: _utils.time_unit_type = 1,
        min: _utils.time_unit_type = 0,
        multiplier: float = 1,
    ) -> None:
        if initial != 1 and multiplier != 1:
            raise ValueError(
                "Cannot specify both 'initial' and 'multiplier' — use 'multiplier' only"
            )

        if initial != 1:
            warnings.warn(
                "The 'initial' parameter is deprecated, use 'multiplier' instead",
                DeprecationWarning,
                stacklevel=2,
            )
            multiplier = initial

        self.multiplier = multiplier
        self.max = _utils.to_seconds(max)
        self.exp_base = exp_base
        self.jitter = _utils.to_seconds(jitter)
        self.min = _utils.to_seconds(min)

    @override
    def __call__(self, retry_state: "RetryCallState") -> float:
        jitter = random.uniform(0, self.jitter)
        try:
            exp = self.exp_base ** (retry_state.attempt_number - 1)
            result = self.multiplier * exp + jitter
        except OverflowError:
            result = self.max
        return max(max(0, self.min), min(result, self.max))
