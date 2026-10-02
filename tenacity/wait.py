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
import dataclasses
import json
import math
import random
import re
import threading
import typing
import warnings

from tenacity import _utils
from tenacity._utils import override

if typing.TYPE_CHECKING:
    from tenacity import RetryCallState


JsonValue = dict[str, "JsonValue"] | list["JsonValue"] | str | int | float | bool | None

_WaitStrategyT = typing.TypeVar("_WaitStrategyT", bound="wait_base")


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


@dataclasses.dataclass(frozen=True, slots=True)
class _RegisteredWaitStrategy:
    name: str
    version: int
    wait_type: type[wait_base]
    dump_state: typing.Callable[[typing.Any], dict[str, JsonValue]]
    load_state: typing.Callable[[dict[str, JsonValue]], typing.Any]
    builtin: bool


_WAIT_STRATEGY_LOCK = threading.Lock()
_WAIT_STRATEGY_TYPES: dict[type[wait_base], _RegisteredWaitStrategy] = {}
_WAIT_STRATEGY_NAMES: dict[tuple[str, int], _RegisteredWaitStrategy] = {}
_WAIT_STRATEGY_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")


def _json_object(value: JsonValue) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ValueError("wait strategy state must be a JSON object")
    return value


def _json_number(value: JsonValue, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(field_name + " must be a number")
    try:
        number = float(value)
    except OverflowError as exc:
        raise ValueError(field_name + " is too large") from exc
    if not math.isfinite(number):
        raise ValueError(field_name + " must be finite")
    return number


def _required_number(
    state: dict[str, JsonValue],
    field_name: str,
    *,
    minimum: float | None = 0.0,
) -> float:
    try:
        value = state[field_name]
    except KeyError as exc:
        raise ValueError("missing wait strategy field: " + field_name) from exc
    number = _json_number(value, field_name)
    if minimum is not None and number < minimum:
        raise ValueError(field_name + " is below the minimum allowed value")
    return number


def _require_fields(state: dict[str, JsonValue], fields: set[str]) -> None:
    if set(state) != fields:
        raise ValueError("invalid wait strategy state fields")


def _register_wait_strategy(
    wait_type: type[wait_base],
    *,
    name: str,
    version: int,
    dump_state: typing.Callable[[typing.Any], dict[str, JsonValue]],
    load_state: typing.Callable[[dict[str, JsonValue]], typing.Any],
    builtin: bool = False,
) -> None:
    if not isinstance(wait_type, type) or not issubclass(wait_type, wait_base):
        raise TypeError("wait strategy must be a wait_base subclass")
    if not isinstance(name, str) or not _WAIT_STRATEGY_NAME_RE.fullmatch(name):
        raise ValueError("wait strategy name must be a non-empty identifier")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise ValueError("wait strategy version must be a positive integer")

    entry = _RegisteredWaitStrategy(
        name=name,
        version=version,
        wait_type=wait_type,
        dump_state=dump_state,
        load_state=load_state,
        builtin=builtin,
    )
    key = (name, version)
    with _WAIT_STRATEGY_LOCK:
        existing_type = _WAIT_STRATEGY_TYPES.get(wait_type)
        existing_name = _WAIT_STRATEGY_NAMES.get(key)
        if existing_type is not None and existing_type != entry:
            raise ValueError(wait_type.__name__ + " is already registered")
        if existing_name is not None and existing_name != entry:
            raise ValueError(name + " version " + str(version) + " is registered")
        if not builtin:
            for registered in _WAIT_STRATEGY_NAMES.values():
                if registered.name == name and registered.builtin:
                    raise ValueError(name + " is a built-in wait strategy name")
        _WAIT_STRATEGY_TYPES[wait_type] = entry
        _WAIT_STRATEGY_NAMES[key] = entry


def register_wait_strategy(
    wait_type: type[_WaitStrategyT],
    *,
    name: str,
    version: int = 1,
    dump_state: typing.Callable[[_WaitStrategyT], dict[str, JsonValue]],
    load_state: typing.Callable[[dict[str, JsonValue]], _WaitStrategyT],
) -> None:
    """Register an explicitly JSON-serializable wait strategy."""
    _register_wait_strategy(
        wait_type,
        name=name,
        version=version,
        dump_state=dump_state,
        load_state=load_state,
    )


def unregister_wait_strategy(wait_type: type[wait_base]) -> None:
    """Remove a registered extension wait strategy."""
    with _WAIT_STRATEGY_LOCK:
        entry = _WAIT_STRATEGY_TYPES.pop(wait_type, None)
        if entry is not None:
            _WAIT_STRATEGY_NAMES.pop((entry.name, entry.version), None)
        if entry is None or entry.builtin:
            if entry is not None:
                _WAIT_STRATEGY_TYPES[wait_type] = entry
                _WAIT_STRATEGY_NAMES[(entry.name, entry.version)] = entry
                raise ValueError(entry.name + " is a built-in wait strategy")
            raise ValueError(wait_type.__name__ + " is not registered")


def serialize_wait_strategy(strategy: WaitBaseT) -> dict[str, JsonValue]:
    """Serialize a registered wait strategy to a JSON-compatible value."""
    strategy_type = type(strategy)
    with _WAIT_STRATEGY_LOCK:
        entry = _WAIT_STRATEGY_TYPES.get(strategy_type)  # type: ignore[arg-type]
        if entry is None:
            if isinstance(strategy, wait_base):
                raise TypeError(strategy_type.__name__ + " is not registered")
            raise TypeError("plain callable wait strategies cannot be serialized")
    state = entry.dump_state(strategy)
    serialized = {
        "type": entry.name,
        "version": entry.version,
        "state": state,
    }
    try:
        json.dumps(serialized, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise TypeError("wait strategy state must be JSON-serializable") from exc
    return serialized


def deserialize_wait_strategy(data: dict[str, JsonValue]) -> wait_base:
    """Reconstruct a registered wait strategy from a JSON-compatible value."""
    if set(data) != {"type", "version", "state"}:
        raise ValueError("invalid wait strategy checkpoint state")
    name = data["type"]
    version = data["version"]
    if not isinstance(name, str):
        raise ValueError("wait strategy type must be a string")
    if isinstance(version, bool) or not isinstance(version, int):
        raise ValueError("wait strategy version must be an integer")
    state = _json_object(data["state"])
    with _WAIT_STRATEGY_LOCK:
        entry = _WAIT_STRATEGY_NAMES.get((name, version))
    if entry is None:
        raise ValueError("unsupported wait strategy version: " + name)
    strategy = entry.load_state(state)
    if type(strategy) is not entry.wait_type:
        raise ValueError("wait strategy loader returned an unexpected type")
    return strategy


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


def _load_fixed(state: dict[str, JsonValue]) -> wait_fixed:
    _require_fields(state, {"wait"})
    return wait_fixed(_required_number(state, "wait"))


def _load_none(state: dict[str, JsonValue]) -> wait_none:
    if state:
        raise ValueError("wait_none state must be empty")
    return wait_none()


def _load_random(state: dict[str, JsonValue]) -> wait_random:
    _require_fields(state, {"min", "max"})
    minimum = _required_number(state, "min")
    maximum = _required_number(state, "max")
    if maximum < minimum:
        raise ValueError("max must be greater than or equal to min")
    return wait_random(
        min=minimum,
        max=maximum,
    )


def _load_strategy_list(state: dict[str, JsonValue]) -> list[wait_base]:
    _require_fields(state, {"strategies"})
    try:
        values = state["strategies"]
    except KeyError as exc:
        raise ValueError("missing wait strategy field: strategies") from exc
    if not isinstance(values, list) or not values:
        raise ValueError("strategies must be a non-empty list")
    return [deserialize_wait_strategy(_json_object(value)) for value in values]


def _load_combine(state: dict[str, JsonValue]) -> wait_combine:
    return wait_combine(*_load_strategy_list(state))


def _load_chain(state: dict[str, JsonValue]) -> wait_chain:
    return wait_chain(*_load_strategy_list(state))


def _load_incrementing(state: dict[str, JsonValue]) -> wait_incrementing:
    _require_fields(state, {"start", "increment", "max"})
    return wait_incrementing(
        start=_required_number(state, "start"),
        increment=_required_number(state, "increment"),
        max=_required_number(state, "max"),
    )


def _load_exponential(state: dict[str, JsonValue]) -> wait_exponential:
    _require_fields(state, {"multiplier", "min", "max", "exp_base"})
    return wait_exponential(
        multiplier=_required_number(state, "multiplier"),
        min=_required_number(state, "min"),
        max=_required_number(state, "max"),
        exp_base=_required_number(state, "exp_base"),
    )


def _load_random_exponential(state: dict[str, JsonValue]) -> wait_random_exponential:
    _require_fields(state, {"multiplier", "min", "max", "exp_base"})
    return wait_random_exponential(
        multiplier=_required_number(state, "multiplier"),
        min=_required_number(state, "min"),
        max=_required_number(state, "max"),
        exp_base=_required_number(state, "exp_base"),
    )


def _load_exponential_jitter(state: dict[str, JsonValue]) -> wait_exponential_jitter:
    _require_fields(state, {"multiplier", "min", "max", "exp_base", "jitter"})
    return wait_exponential_jitter(
        multiplier=_required_number(state, "multiplier"),
        min=_required_number(state, "min"),
        max=_required_number(state, "max"),
        exp_base=_required_number(state, "exp_base"),
        jitter=_required_number(state, "jitter"),
    )


_register_wait_strategy(
    wait_none,
    name="none",
    version=1,
    dump_state=lambda strategy: {},
    load_state=_load_none,
    builtin=True,
)
_register_wait_strategy(
    wait_fixed,
    name="fixed",
    version=1,
    dump_state=lambda strategy: {"wait": strategy.wait_fixed},
    load_state=_load_fixed,
    builtin=True,
)
_register_wait_strategy(
    wait_random,
    name="random",
    version=1,
    dump_state=lambda strategy: {
        "min": strategy.wait_random_min,
        "max": strategy.wait_random_max,
    },
    load_state=_load_random,
    builtin=True,
)
_register_wait_strategy(
    wait_combine,
    name="combine",
    version=1,
    dump_state=lambda strategy: {
        "strategies": [serialize_wait_strategy(item) for item in strategy.wait_funcs]
    },
    load_state=_load_combine,
    builtin=True,
)
_register_wait_strategy(
    wait_chain,
    name="chain",
    version=1,
    dump_state=lambda strategy: {
        "strategies": [serialize_wait_strategy(item) for item in strategy.strategies]
    },
    load_state=_load_chain,
    builtin=True,
)
_register_wait_strategy(
    wait_incrementing,
    name="incrementing",
    version=1,
    dump_state=lambda strategy: {
        "start": strategy.start,
        "increment": strategy.increment,
        "max": strategy.max,
    },
    load_state=_load_incrementing,
    builtin=True,
)
_register_wait_strategy(
    wait_exponential,
    name="exponential",
    version=1,
    dump_state=lambda strategy: {
        "multiplier": strategy.multiplier,
        "min": strategy.min,
        "max": strategy.max,
        "exp_base": strategy.exp_base,
    },
    load_state=_load_exponential,
    builtin=True,
)
_register_wait_strategy(
    wait_random_exponential,
    name="random_exponential",
    version=1,
    dump_state=lambda strategy: {
        "multiplier": strategy.multiplier,
        "min": strategy.min,
        "max": strategy.max,
        "exp_base": strategy.exp_base,
    },
    load_state=_load_random_exponential,
    builtin=True,
)
_register_wait_strategy(
    wait_exponential_jitter,
    name="exponential_jitter",
    version=1,
    dump_state=lambda strategy: {
        "multiplier": strategy.multiplier,
        "min": strategy.min,
        "max": strategy.max,
        "exp_base": strategy.exp_base,
        "jitter": strategy.jitter,
    },
    load_state=_load_exponential_jitter,
    builtin=True,
)


__all__ = [
    "JsonValue",
    "deserialize_wait_strategy",
    "register_wait_strategy",
    "serialize_wait_strategy",
    "unregister_wait_strategy",
    "wait_base",
    "wait_chain",
    "wait_combine",
    "wait_exception",
    "wait_exponential",
    "wait_exponential_jitter",
    "wait_fixed",
    "wait_incrementing",
    "wait_none",
    "wait_random",
    "wait_random_exponential",
]
