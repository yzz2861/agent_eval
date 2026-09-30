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
import enum
import math
import random
import time
import typing
import warnings
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

from tenacity import _utils
from tenacity._utils import override

if typing.TYPE_CHECKING:
    from tenacity import RetryCallState

    Sequence = typing.Sequence


class RetryAfterInvalidPolicy(enum.Enum):
    """How to handle a syntactically invalid ``Retry-After`` value."""

    RAISE = enum.auto()
    IGNORE = enum.auto()
    STOP = enum.auto()


class RetryAfterDuplicatePolicy(enum.Enum):
    """How to choose between more than one ``Retry-After`` value."""

    RAISE = enum.auto()
    USE_EARLIEST = enum.auto()
    USE_LATEST = enum.auto()


class RetryAfterStalePolicy(enum.Enum):
    """How to handle a ``Retry-After`` time that is already in the past."""

    RAISE = enum.auto()
    IGNORE = enum.auto()
    STOP = enum.auto()


class RetryAfterAction(enum.Enum):
    """The action selected by a :class:`wait_retry_after` strategy."""

    WAIT = enum.auto()
    LOCAL_WAIT = enum.auto()
    STOP = enum.auto()


@dataclass(frozen=True)
class RetryAfterHeader:
    """Header information extracted from a caller-defined response object.

    ``date`` is the response's ``Date`` HTTP-date. When it is available, an
    absolute ``Retry-After`` date is measured from that server timestamp
    rather than the local clock, which avoids requesting early because the
    local and server clocks disagree.
    """

    retry_after: object
    date: object | None = None


@dataclass(frozen=True)
class RetryAfterDecision:
    """The server, local, and final parts of one retry wait decision."""

    server_wait: float | None
    local_wait: float
    wait: float
    action: RetryAfterAction
    error: ValueError | None = None
    stop_reason: str | None = None


class RetryAfterError(ValueError):
    """Raised when a configured Retry-After policy is ``RAISE``."""


_HeaderInput = str | bytes | int | float | timedelta | datetime
_ParsedValue = int | float | timedelta | datetime


def _parse_http_date(value: str) -> datetime:
    parsed = parsedate_to_datetime(value)
    if not isinstance(parsed, datetime):
        raise RetryAfterError(f"invalid HTTP-date: {value!r}")
    if parsed.tzinfo is None:
        raise RetryAfterError(f"HTTP-date has no timezone: {value!r}")
    return parsed.astimezone(timezone.utc)


def _parse_retry_after_value(value: _HeaderInput) -> _ParsedValue:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise RetryAfterError("Retry-After datetime must be timezone-aware")
        return value.astimezone(timezone.utc)

    if isinstance(value, timedelta):
        return value

    if isinstance(value, bool):
        raise RetryAfterError(f"invalid Retry-After value: {value!r}")

    if isinstance(value, int | float):
        if not math.isfinite(float(value)):
            raise RetryAfterError(f"invalid Retry-After value: {value!r}")
        return value

    if isinstance(value, bytes):
        value = value.decode("ascii")

    if isinstance(value, str):
        value = value.strip()
        if not value:
            raise RetryAfterError("empty Retry-After value")
        try:
            number = float(value)
        except ValueError:
            return _parse_http_date(value)
        if not math.isfinite(number):
            raise RetryAfterError(f"invalid Retry-After value: {value!r}")
        return number

    raise RetryAfterError(f"unsupported Retry-After value: {value!r}")


def _parse_date(value: object) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise RetryAfterError("response Date must be timezone-aware")
        return value.astimezone(timezone.utc)
    if isinstance(value, bytes):
        value = value.decode("ascii")
    if isinstance(value, str):
        return _parse_http_date(value.strip())
    raise RetryAfterError(f"unsupported response Date value: {value!r}")


def _seconds(value: float | timedelta) -> float:
    if isinstance(value, timedelta):
        return value.total_seconds()
    return float(value)


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


class wait_retry_after(wait_base):
    """Wait according to an upstream ``Retry-After`` header.

    :param extractor: Receives the :class:`RetryCallState` and returns one
        header value, a :class:`RetryAfterHeader`, or a sequence of either.
        Returning ``None`` or an empty sequence means no header was present.
        The extractor can inspect either a successful result or an exception,
        which keeps this strategy independent of HTTP clients.
    :param local_wait: Local backoff strategy. The final wait is the later of
        this local recommendation and the server recommendation. Pass it here
        rather than using ``+`` because ``+`` adds waits together.
    :param malformed: Policy for syntactically invalid values.
    :param duplicate: Policy for more than one valid header value.
    :param stale: Policy for an HTTP-date or negative delta that is in the
        past.
    :param clock_skew_tolerance: Extra delay for absolute HTTP-date values
        when a response ``Date`` header is unavailable. It is not added to
        delta-seconds.
    :param on_decision: Optional callback invoked after the stop condition is
        evaluated. Use a sync callback with :class:`Retrying` and a sync or
        async callback with :class:`AsyncRetrying`. It receives the retry
        state and the final :class:`RetryAfterDecision`.
    """

    def __init__(
        self,
        extractor: typing.Callable[["RetryCallState"], typing.Any],
        local_wait: "WaitBaseT" = wait_none(),
        *,
        malformed: RetryAfterInvalidPolicy = RetryAfterInvalidPolicy.RAISE,
        duplicate: RetryAfterDuplicatePolicy = (RetryAfterDuplicatePolicy.USE_LATEST),
        stale: RetryAfterStalePolicy = RetryAfterStalePolicy.IGNORE,
        clock_skew_tolerance: _utils.time_unit_type = 0,
        on_decision: typing.Callable[..., typing.Any] | None = None,
    ) -> None:
        self.extractor = extractor
        self.local_wait = local_wait
        self.malformed_policy = malformed
        self.duplicate_policy = duplicate
        self.stale_policy = stale
        self.clock_skew_tolerance = _utils.to_seconds(clock_skew_tolerance)
        self.on_decision = on_decision
        if self.clock_skew_tolerance < 0 or not math.isfinite(
            self.clock_skew_tolerance
        ):
            raise ValueError("clock_skew_tolerance must be finite and non-negative")

    def _local_wait(self, retry_state: "RetryCallState") -> float:
        wait = max(0.0, float(self.local_wait(retry_state)))
        if not math.isfinite(wait):
            raise ValueError("local wait must be finite")
        return wait

    @staticmethod
    def _decision(
        *,
        server_wait: float | None,
        local_wait: float,
        action: RetryAfterAction,
        error: ValueError | None = None,
        stop_reason: str | None = None,
    ) -> RetryAfterDecision:
        wait = local_wait if server_wait is None else max(local_wait, server_wait)
        return RetryAfterDecision(
            server_wait=server_wait,
            local_wait=local_wait,
            wait=wait,
            action=action,
            error=error,
            stop_reason=stop_reason,
        )

    def _invalid_decision(
        self,
        policy: RetryAfterInvalidPolicy | RetryAfterStalePolicy,
        error: ValueError,
        local_wait: float,
    ) -> RetryAfterDecision:
        if policy in (
            RetryAfterInvalidPolicy.RAISE,
            RetryAfterStalePolicy.RAISE,
        ):
            raise error
        if policy in (
            RetryAfterInvalidPolicy.STOP,
            RetryAfterStalePolicy.STOP,
        ):
            return self._decision(
                server_wait=None,
                local_wait=local_wait,
                action=RetryAfterAction.STOP,
                error=error,
                stop_reason=str(error),
            )
        return self._decision(
            server_wait=None,
            local_wait=local_wait,
            action=RetryAfterAction.LOCAL_WAIT,
            error=error,
        )

    def _candidate_delay(
        self,
        value: RetryAfterHeader | _HeaderInput,
        retry_state: "RetryCallState",
    ) -> float:
        header_date = None
        if isinstance(value, RetryAfterHeader):
            header_date = _parse_date(value.date)
            raw_value = value.retry_after
        else:
            raw_value = value

        parsed = _parse_retry_after_value(typing.cast("_HeaderInput", raw_value))
        if isinstance(parsed, datetime):
            if header_date is not None:
                if retry_state.outcome_timestamp is None:
                    raise RetryAfterError("outcome timestamp is not set")
                server_delay = (parsed - header_date).total_seconds()
                elapsed = time.monotonic() - retry_state.outcome_timestamp
                return server_delay - elapsed
            return parsed.timestamp() - time.time() + self.clock_skew_tolerance

        delay = _seconds(parsed)
        if delay < 0:
            return delay
        return delay

    def _safe_candidate_delay(
        self,
        value: RetryAfterHeader | _HeaderInput,
        retry_state: "RetryCallState",
    ) -> tuple[float | None, RetryAfterError | None]:
        try:
            return self._candidate_delay(value, retry_state), None
        except (TypeError, ValueError, OverflowError, OSError) as exc:
            return None, RetryAfterError(str(exc))

    @override
    def __call__(self, retry_state: "RetryCallState") -> float:
        local_wait = self._local_wait(retry_state)
        raw_headers = self.extractor(retry_state)

        if raw_headers is None:
            return self._finish(
                retry_state,
                self._decision(
                    server_wait=None,
                    local_wait=local_wait,
                    action=RetryAfterAction.LOCAL_WAIT,
                ),
            )

        scalar_types = (
            RetryAfterHeader,
            str,
            bytes,
            int,
            float,
            timedelta,
            datetime,
        )
        values: Sequence[RetryAfterHeader | _HeaderInput] = (
            (raw_headers,)
            if isinstance(raw_headers, scalar_types)
            else tuple(raw_headers)
        )

        candidates: list[float] = []
        malformed_errors: list[RetryAfterError] = []
        for value in values:
            candidate, error = self._safe_candidate_delay(value, retry_state)
            if error is None:
                assert candidate is not None
                candidates.append(candidate)
            else:
                malformed_errors.append(error)

        if malformed_errors and self.malformed_policy is RetryAfterInvalidPolicy.RAISE:
            raise malformed_errors[0]
        if malformed_errors and self.malformed_policy is RetryAfterInvalidPolicy.STOP:
            return self._finish(
                retry_state,
                self._decision(
                    server_wait=None,
                    local_wait=local_wait,
                    action=RetryAfterAction.STOP,
                    error=malformed_errors[0],
                    stop_reason=str(malformed_errors[0]),
                ),
            )

        if not candidates:
            if malformed_errors:
                return self._finish(
                    retry_state,
                    self._invalid_decision(
                        self.malformed_policy,
                        malformed_errors[0],
                        local_wait,
                    ),
                )
            return self._finish(
                retry_state,
                self._decision(
                    server_wait=None,
                    local_wait=local_wait,
                    action=RetryAfterAction.LOCAL_WAIT,
                ),
            )

        stale = [delay for delay in candidates if delay < 0.0]
        fresh = [delay for delay in candidates if delay >= 0.0]
        stale_error: RetryAfterError | None = None
        if stale:
            stale_error = RetryAfterError("one Retry-After time is in the past")
            if self.stale_policy is not RetryAfterStalePolicy.IGNORE:
                return self._finish(
                    retry_state,
                    self._invalid_decision(self.stale_policy, stale_error, local_wait),
                )

        if not fresh:
            return self._finish(
                retry_state,
                self._invalid_decision(
                    self.stale_policy,
                    RetryAfterError("Retry-After time is in the past"),
                    local_wait,
                ),
            )

        if len(fresh) > 1 and self.duplicate_policy is RetryAfterDuplicatePolicy.RAISE:
            raise RetryAfterError("multiple Retry-After values were provided")
        if len(fresh) > 1:
            server_wait = (
                min(fresh)
                if self.duplicate_policy is RetryAfterDuplicatePolicy.USE_EARLIEST
                else max(fresh)
            )
        else:
            server_wait = fresh[0]

        error = malformed_errors[0] if malformed_errors else stale_error

        return self._finish(
            retry_state,
            self._decision(
                server_wait=server_wait,
                local_wait=local_wait,
                action=RetryAfterAction.WAIT,
                error=error,
            ),
        )

    def _finish(
        self,
        retry_state: "RetryCallState",
        decision: RetryAfterDecision,
    ) -> float:
        retry_state.wait_decision = decision
        retry_state.wait_decision_hook = self.on_decision
        retry_state.wait_decision_stop_requested = decision.action is (
            RetryAfterAction.STOP
        )
        if retry_state.retry_object is None and self.on_decision is not None:
            self.on_decision(retry_state, decision)
        return decision.wait


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
