"""Explicitly serializable retry checkpoints for cross-process recovery."""

import abc
import dataclasses
import hashlib
import hmac
import json
import math
import threading
import time
import typing as t

from .wait import (
    wait_base,
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

if t.TYPE_CHECKING:
    from tenacity import RetryCallState

JSONValue = t.Union[  # noqa: UP007
    str, int, float, bool, None, list["JSONValue"], dict[str, "JSONValue"]
]
Secret = str | bytes

CHECKPOINT_VERSION = 1
CHECKPOINT_SCHEMA = "tenacity.retry-checkpoint"
CHECKPOINT_PHASE_BETWEEN_ATTEMPTS = "between_attempts"


class CheckpointError(ValueError):
    """A retry checkpoint is invalid, unsafe, or unsupported."""


class CheckpointableWait(wait_base, abc.ABC):
    """Base class for wait strategies with explicit checkpoint support."""

    checkpoint_name: t.ClassVar[str]
    checkpoint_version: t.ClassVar[int] = 1

    @abc.abstractmethod
    def to_checkpoint(self) -> JSONValue:
        """Return JSON-compatible state needed to reconstruct this strategy."""

    @classmethod
    @abc.abstractmethod
    def from_checkpoint(
        cls: type["_CheckpointableWaitT"], state: JSONValue
    ) -> "_CheckpointableWaitT":
        """Reconstruct this strategy from explicit checkpoint state."""


_CheckpointableWaitT = t.TypeVar("_CheckpointableWaitT", bound=CheckpointableWait)


@dataclasses.dataclass(frozen=True, slots=True)
class LoadedRetryCheckpoint:
    attempt_number: int
    elapsed_seconds: float
    saved_at: float
    next_allowed_at: float
    wait: wait_base


@dataclasses.dataclass(frozen=True, slots=True)
class _WaitStrategyEntry:
    strategy_type: type[wait_base]
    name: str
    version: int
    dump: t.Callable[[wait_base], JSONValue]
    load: t.Callable[[JSONValue], wait_base]


_wait_strategy_lock = threading.Lock()
_wait_strategies_by_type: dict[type[wait_base], _WaitStrategyEntry] = {}
_wait_strategies_by_key: dict[tuple[str, int], _WaitStrategyEntry] = {}


def wall_now() -> float:
    return time.time()


def monotonic_now() -> float:
    return time.monotonic()


def register_wait_strategy(
    name: str, version: int = 1
) -> t.Callable[[type[_CheckpointableWaitT]], type[_CheckpointableWaitT]]:
    """Register an explicitly checkpointable wait strategy extension."""

    if not isinstance(name, str) or not name:
        raise TypeError("wait strategy checkpoint name must be a non-empty string")
    if type(version) is not int or version < 1:
        raise TypeError("wait strategy checkpoint version must be a positive integer")

    def decorator(
        strategy_type: type[_CheckpointableWaitT],
    ) -> type[_CheckpointableWaitT]:
        strategy_type.checkpoint_name = name
        strategy_type.checkpoint_version = version
        entry = _WaitStrategyEntry(
            strategy_type=strategy_type,
            name=name,
            version=version,
            dump=lambda strategy: strategy.to_checkpoint(),
            load=lambda state: strategy_type.from_checkpoint(state),
        )
        _register_wait_strategy(entry)
        return strategy_type

    return decorator


def _register_wait_strategy(entry: _WaitStrategyEntry) -> None:
    with _wait_strategy_lock:
        existing_type = _wait_strategies_by_type.get(entry.strategy_type)
        existing_key = _wait_strategies_by_key.get((entry.name, entry.version))
        if existing_type is not None and (
            existing_type.strategy_type is not entry.strategy_type
            or existing_type.name != entry.name
            or existing_type.version != entry.version
        ):
            raise ValueError(
                f"{entry.strategy_type.__name__!r} is already registered as "
                f"{existing_type.name!r} version {existing_type.version}"
            )
        if existing_key is not None and existing_key.strategy_type is not (
            entry.strategy_type
        ):
            raise ValueError(
                f"Wait strategy checkpoint name {entry.name!r} version "
                f"{entry.version} is already registered"
            )
        _wait_strategies_by_type[entry.strategy_type] = entry
        _wait_strategies_by_key[(entry.name, entry.version)] = entry


def _register_builtin(
    strategy_type: type[wait_base],
    name: str,
    dump: t.Callable[[wait_base], JSONValue],
    load: t.Callable[[JSONValue], wait_base],
) -> None:
    _register_wait_strategy(
        _WaitStrategyEntry(
            strategy_type=strategy_type,
            name=name,
            version=1,
            dump=dump,
            load=load,
        )
    )


def _as_number(value: JSONValue, field: str) -> float:
    if type(value) not in (int, float) or isinstance(value, bool):
        raise CheckpointError(f"checkpoint field {field!r} must be a number")
    number = float(value)
    if not math.isfinite(number):
        raise CheckpointError(f"checkpoint field {field!r} must be finite")
    return number


def _positive_number(value: JSONValue, field: str) -> float:
    number = _as_number(value, field)
    if number <= 0:
        raise CheckpointError(f"checkpoint field {field!r} must be positive")
    return number


def _non_negative_number(value: JSONValue, field: str) -> float:
    number = _as_number(value, field)
    if number < 0:
        raise CheckpointError(f"checkpoint field {field!r} must not be negative")
    return number


def _exact_mapping(value: JSONValue, description: str) -> dict[str, JSONValue]:
    if type(value) is not dict:
        raise CheckpointError(f"{description} must be an object")
    return value


def _exact_keys(
    value: dict[str, JSONValue], required: set[str], description: str
) -> None:
    keys = set(value)
    if keys != required:
        missing = sorted(required - keys)
        unexpected = sorted(keys - required)
        details = []
        if missing:
            details.append(f"missing {missing}")
        if unexpected:
            details.append(f"unexpected {unexpected}")
        raise CheckpointError(f"{description} has invalid keys: {'; '.join(details)}")


def _strategy_state(
    value: JSONValue, required: set[str], description: str
) -> dict[str, JSONValue]:
    mapping = _exact_mapping(value, description)
    _exact_keys(mapping, required, description)
    return mapping


def _validate_json(value: JSONValue, *, depth: int = 0) -> None:
    if depth > 64:
        raise CheckpointError("wait strategy checkpoint state is too deeply nested")
    if type(value) in (str, int, float, bool) or value is None:
        if isinstance(value, float) and not math.isfinite(value):
            raise CheckpointError("checkpoint contains a non-finite number")
        return
    if type(value) is list:
        for item in value:
            _validate_json(item, depth=depth + 1)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise CheckpointError("checkpoint object keys must be strings")
            _validate_json(item, depth=depth + 1)
        return
    raise CheckpointError("checkpoint contains a non-JSON value")


def _dump_fixed(strategy: wait_base) -> JSONValue:
    fixed = t.cast("wait_fixed", strategy)
    return {"wait": fixed.wait_fixed}


def _load_fixed(state: JSONValue) -> wait_base:
    data = _strategy_state(state, {"wait"}, "wait_fixed state")
    return wait_fixed(_non_negative_number(data["wait"], "wait"))


def _dump_none(_strategy: wait_base) -> JSONValue:
    return {}


def _load_none(state: JSONValue) -> wait_base:
    _strategy_state(state, set(), "wait_none state")
    return wait_none()


def _dump_random(strategy: wait_base) -> JSONValue:
    random_wait = t.cast("wait_random", strategy)
    return {
        "min": random_wait.wait_random_min,
        "max": random_wait.wait_random_max,
    }


def _load_random(state: JSONValue) -> wait_base:
    data = _strategy_state(state, {"min", "max"}, "wait_random state")
    minimum = _non_negative_number(data["min"], "min")
    maximum = _non_negative_number(data["max"], "max")
    if maximum < minimum:
        raise CheckpointError("wait_random max must be greater than or equal to min")
    return wait_random(minimum, maximum)


def _dump_combine(strategy: wait_base) -> JSONValue:
    combine = t.cast("wait_combine", strategy)
    serialized = [dump_wait(item) for item in combine.wait_funcs]
    return {"strategies": serialized}


def _load_combine(state: JSONValue) -> wait_base:
    data = _strategy_state(state, {"strategies"}, "wait_combine state")
    strategies = data["strategies"]
    if type(strategies) is not list:
        raise CheckpointError("wait_combine strategies must be a list")
    return wait_combine(*(load_wait(item) for item in strategies))


def _dump_chain(strategy: wait_base) -> JSONValue:
    chain = t.cast("wait_chain", strategy)
    serialized = [dump_wait(item) for item in chain.strategies]
    return {"strategies": serialized}


def _load_chain(state: JSONValue) -> wait_base:
    data = _strategy_state(state, {"strategies"}, "wait_chain state")
    strategies = data["strategies"]
    if type(strategies) is not list or not strategies:
        raise CheckpointError("wait_chain requires at least one strategy")
    return wait_chain(*(load_wait(item) for item in strategies))


def _dump_incrementing(strategy: wait_base) -> JSONValue:
    incrementing = t.cast("wait_incrementing", strategy)
    return {
        "start": incrementing.start,
        "increment": incrementing.increment,
        "max": incrementing.max,
    }


def _load_incrementing(state: JSONValue) -> wait_base:
    data = _strategy_state(
        state, {"increment", "max", "start"}, "wait_incrementing state"
    )
    return wait_incrementing(
        start=_non_negative_number(data["start"], "start"),
        increment=_non_negative_number(data["increment"], "increment"),
        max=_non_negative_number(data["max"], "max"),
    )


def _dump_exponential(strategy: wait_base) -> JSONValue:
    exponential = t.cast("wait_exponential", strategy)
    return {
        "exp_base": exponential.exp_base,
        "max": exponential.max,
        "min": exponential.min,
        "multiplier": exponential.multiplier,
    }


def _load_exponential(state: JSONValue) -> wait_base:
    data = _strategy_state(
        state, {"exp_base", "max", "min", "multiplier"}, "wait_exponential state"
    )
    return wait_exponential(
        multiplier=_positive_number(data["multiplier"], "multiplier"),
        max=_non_negative_number(data["max"], "max"),
        exp_base=_positive_number(data["exp_base"], "exp_base"),
        min=_non_negative_number(data["min"], "min"),
    )


def _load_random_exponential(state: JSONValue) -> wait_base:
    data = _strategy_state(
        state,
        {"exp_base", "max", "min", "multiplier"},
        "wait_random_exponential state",
    )
    return wait_random_exponential(
        multiplier=_positive_number(data["multiplier"], "multiplier"),
        max=_non_negative_number(data["max"], "max"),
        exp_base=_positive_number(data["exp_base"], "exp_base"),
        min=_non_negative_number(data["min"], "min"),
    )


def _dump_exponential_jitter(strategy: wait_base) -> JSONValue:
    jitter_wait = t.cast("wait_exponential_jitter", strategy)
    return {
        "exp_base": jitter_wait.exp_base,
        "jitter": jitter_wait.jitter,
        "max": jitter_wait.max,
        "min": jitter_wait.min,
        "multiplier": jitter_wait.multiplier,
    }


def _load_exponential_jitter(state: JSONValue) -> wait_base:
    data = _strategy_state(
        state,
        {"exp_base", "jitter", "max", "min", "multiplier"},
        "wait_exponential_jitter state",
    )
    return wait_exponential_jitter(
        multiplier=_positive_number(data["multiplier"], "multiplier"),
        max=_non_negative_number(data["max"], "max"),
        exp_base=_positive_number(data["exp_base"], "exp_base"),
        jitter=_non_negative_number(data["jitter"], "jitter"),
        min=_non_negative_number(data["min"], "min"),
    )


_register_builtin(wait_none, "wait_none", _dump_none, _load_none)
_register_builtin(wait_fixed, "wait_fixed", _dump_fixed, _load_fixed)
_register_builtin(wait_random, "wait_random", _dump_random, _load_random)
_register_builtin(wait_combine, "wait_combine", _dump_combine, _load_combine)
_register_builtin(wait_chain, "wait_chain", _dump_chain, _load_chain)
_register_builtin(
    wait_incrementing,
    "wait_incrementing",
    _dump_incrementing,
    _load_incrementing,
)
_register_builtin(
    wait_exponential,
    "wait_exponential",
    _dump_exponential,
    _load_exponential,
)
_register_builtin(
    wait_random_exponential,
    "wait_random_exponential",
    _dump_exponential,
    _load_random_exponential,
)
_register_builtin(
    wait_exponential_jitter,
    "wait_exponential_jitter",
    _dump_exponential_jitter,
    _load_exponential_jitter,
)


def _strategy_envelope(
    name: str, version: int, state: JSONValue
) -> dict[str, JSONValue]:
    return {"name": name, "version": version, "state": state}


def dump_wait(strategy: t.Any) -> dict[str, JSONValue]:
    """Serialize a supported wait strategy without using pickle."""

    strategy_type = type(strategy)
    entry = _wait_strategies_by_type.get(strategy_type)
    if entry is None:
        if isinstance(strategy, wait_exception):
            raise CheckpointError(
                "wait_exception cannot be checkpointed because its predicate "
                "is a callable; register an explicit wait strategy extension"
            )
        if callable(strategy):
            raise CheckpointError(
                "plain callable wait strategies cannot be checkpointed; register "
                "an explicit wait strategy extension"
            )
        raise CheckpointError(
            f"wait strategy {strategy_type.__name__!r} is not registered for "
            "checkpointing"
        )
    try:
        state = entry.dump(strategy)
    except CheckpointError:
        raise
    except Exception as exc:
        raise CheckpointError(
            f"wait strategy {strategy_type.__name__!r} produced an invalid "
            "checkpoint state"
        ) from exc
    _validate_json(state)
    return _strategy_envelope(entry.name, entry.version, state)


def load_wait(value: JSONValue) -> wait_base:
    """Reconstruct a registered wait strategy from checkpoint data."""

    data = _exact_mapping(value, "wait strategy")
    _exact_keys(data, {"name", "state", "version"}, "wait strategy")
    name = data["name"]
    version = data["version"]
    if type(name) is not str or not name:
        raise CheckpointError("wait strategy name must be a non-empty string")
    if type(version) is not int or isinstance(version, bool) or version < 1:
        raise CheckpointError("wait strategy version must be a positive integer")
    entry = _wait_strategies_by_key.get((name, version))
    if entry is None:
        raise CheckpointError(
            f"unsupported wait strategy checkpoint {name!r} version {version}"
        )
    try:
        strategy = entry.load(data["state"])
    except CheckpointError:
        raise
    except Exception as exc:
        raise CheckpointError(
            f"invalid wait strategy checkpoint {name!r} version {version}: {exc}"
        ) from exc
    if type(strategy) is not entry.strategy_type:
        raise CheckpointError("wait strategy loader returned an unexpected type")
    return strategy


def _canonical_payload(payload: dict[str, JSONValue]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _digest(payload: dict[str, JSONValue], secret: Secret | None) -> str:
    encoded = _canonical_payload(payload)
    if secret is None:
        return "sha256:" + hashlib.sha256(encoded).hexdigest()
    if isinstance(secret, str):
        secret_bytes = secret.encode("utf-8")
    else:
        secret_bytes = secret
    return "hmac-sha256:" + hmac.new(secret_bytes, encoded, hashlib.sha256).hexdigest()


def _secret_bytes(secret: Secret | None) -> bytes | None:
    if secret is None:
        return None
    if isinstance(secret, str):
        return secret.encode("utf-8")
    if type(secret) is not bytes:
        raise TypeError("checkpoint secret must be bytes, a string, or None")
    return secret


def _as_int(value: JSONValue, field: str) -> int:
    if type(value) is not int or isinstance(value, bool):
        raise CheckpointError(f"checkpoint field {field!r} must be an integer")
    return value


def export_checkpoint(
    retry_state: "RetryCallState", secret: Secret | None = None
) -> dict[str, JSONValue]:
    """Export retry state at the safe between-attempts phase."""

    if not getattr(retry_state, "_checkpoint_allowed", False):
        raise CheckpointError(
            "retry checkpoints can only be saved between attempts, from the "
            "before_sleep callback"
        )
    sleep_for = _non_negative_number(retry_state.upcoming_sleep, "sleep_for")
    completed_attempt_number = _as_int(retry_state.attempt_number, "attempt_number")
    if completed_attempt_number < 1:
        raise CheckpointError(
            "checkpoint attempt_number must describe a completed attempt"
        )
    attempt_number = completed_attempt_number + 1
    elapsed = _non_negative_number(
        retry_state.seconds_since_start or 0.0, "elapsed_seconds"
    )
    saved_at = wall_now()
    wait_state = dump_wait(retry_state.retry_object.wait)
    payload: dict[str, JSONValue] = {
        "schema": CHECKPOINT_SCHEMA,
        "version": CHECKPOINT_VERSION,
        "phase": CHECKPOINT_PHASE_BETWEEN_ATTEMPTS,
        "attempt_number": attempt_number,
        "elapsed_seconds": elapsed,
        "sleep_for": sleep_for,
        "saved_at": saved_at,
        "next_allowed_at": saved_at + sleep_for,
        "wait": wait_state,
    }
    _validate_json(payload)
    envelope = dict(payload)
    envelope["digest"] = _digest(payload, secret)
    return envelope


_PAYLOAD_KEYS = {
    "attempt_number",
    "elapsed_seconds",
    "next_allowed_at",
    "phase",
    "saved_at",
    "schema",
    "sleep_for",
    "version",
    "wait",
}


def load_checkpoint(
    checkpoint: dict[str, t.Any] | str | bytes | bytearray,
    secret: Secret | None = None,
) -> LoadedRetryCheckpoint:
    """Validate a checkpoint and reconstruct its portable retry state."""

    secret_bytes = _secret_bytes(secret)
    if isinstance(checkpoint, str | bytes | bytearray):
        try:
            parsed = json.loads(checkpoint)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise CheckpointError("retry checkpoint is not valid JSON") from exc
        if type(parsed) is not dict:
            raise CheckpointError("retry checkpoint must be a JSON object")
        checkpoint = parsed
    if type(checkpoint) is not dict:
        raise CheckpointError("retry checkpoint must be a JSON object")

    keys = set(checkpoint)
    if keys != _PAYLOAD_KEYS | {"digest"}:
        missing = sorted((_PAYLOAD_KEYS | {"digest"}) - keys)
        unexpected = sorted(keys - (_PAYLOAD_KEYS | {"digest"}))
        details = []
        if missing:
            details.append(f"missing {missing}")
        if unexpected:
            details.append(f"unexpected {unexpected}")
        raise CheckpointError(
            f"retry checkpoint has invalid keys: {'; '.join(details)}"
        )

    digest = checkpoint["digest"]
    if type(digest) is not str:
        raise CheckpointError("checkpoint digest must be a string")
    payload: dict[str, JSONValue] = {key: checkpoint[key] for key in _PAYLOAD_KEYS}
    _validate_json(payload)

    expected_digest = _digest(payload, secret_bytes)
    if not hmac.compare_digest(digest, expected_digest):
        if digest.startswith("hmac-sha256:"):
            raise CheckpointError(
                "checkpoint HMAC does not match; the checkpoint was tampered "
                "with or the secret is wrong"
            )
        raise CheckpointError(
            "checkpoint digest does not match; the checkpoint was tampered with"
        )

    if payload["schema"] != CHECKPOINT_SCHEMA:
        raise CheckpointError("unsupported retry checkpoint schema")
    version = payload["version"]
    if type(version) is not int or isinstance(version, bool) or version < 1:
        raise CheckpointError("retry checkpoint version must be a positive integer")
    if version != CHECKPOINT_VERSION:
        raise CheckpointError(
            f"unsupported retry checkpoint version {version}; expected "
            f"{CHECKPOINT_VERSION}"
        )
    if payload["phase"] != CHECKPOINT_PHASE_BETWEEN_ATTEMPTS:
        raise CheckpointError(
            "checkpoint was not saved in the safe between-attempts phase"
        )

    attempt_number = _as_int(payload["attempt_number"], "attempt_number")
    if attempt_number < 2:
        raise CheckpointError("checkpoint attempt_number must describe a later attempt")
    elapsed = _non_negative_number(payload["elapsed_seconds"], "elapsed_seconds")
    sleep_for = _non_negative_number(payload["sleep_for"], "sleep_for")
    saved_at = _as_number(payload["saved_at"], "saved_at")
    next_allowed_at = _as_number(payload["next_allowed_at"], "next_allowed_at")
    expected_next_allowed = saved_at + sleep_for
    if not math.isclose(
        next_allowed_at,
        expected_next_allowed,
        rel_tol=1e-12,
        abs_tol=1e-9,
    ):
        raise CheckpointError("checkpoint next allowed time is inconsistent")

    now = wall_now()
    if now + 1e-9 < saved_at:
        raise CheckpointError(
            "checkpoint saved_at is in the future; the system clock moved backwards"
        )

    wait = load_wait(payload["wait"])
    return LoadedRetryCheckpoint(
        attempt_number=attempt_number,
        elapsed_seconds=elapsed,
        saved_at=saved_at,
        next_allowed_at=next_allowed_at,
        wait=wait,
    )


def remaining_delay(
    checkpoint: LoadedRetryCheckpoint, now: float | None = None
) -> float:
    """Return the non-negative time left until the next attempt is allowed."""

    current = wall_now() if now is None else now
    return max(0.0, checkpoint.next_allowed_at - current)


def restored_start_time(
    checkpoint: LoadedRetryCheckpoint, now: float | None = None
) -> float:
    """Return a monotonic start time that includes process downtime."""

    current_wall = wall_now() if now is None else now
    downtime = max(0.0, current_wall - checkpoint.saved_at)
    return monotonic_now() - checkpoint.elapsed_seconds - downtime


__all__ = [
    "CHECKPOINT_VERSION",
    "CheckpointError",
    "CheckpointableWait",
    "LoadedRetryCheckpoint",
    "dump_wait",
    "load_checkpoint",
    "load_wait",
    "register_wait_strategy",
    "remaining_delay",
    "restored_start_time",
]
