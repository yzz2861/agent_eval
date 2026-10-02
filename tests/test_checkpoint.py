import copy
import hashlib
import json
import typing

import pytest

import tenacity
from tenacity import (
    AsyncRetrying,
    CheckpointError,
    RetryCallState,
    Retrying,
    load_wait,
    wait_chain,
    wait_combine,
    wait_exponential,
    wait_exponential_jitter,
    wait_fixed,
    wait_incrementing,
    wait_none,
    wait_random,
    wait_random_exponential,
)

if typing.TYPE_CHECKING:
    from tenacity.checkpoint import JSONValue


def _saved_at(checkpoint: dict[str, object]) -> float:
    saved_at = checkpoint["saved_at"]
    assert isinstance(saved_at, int | float) and not isinstance(saved_at, bool)
    return float(saved_at)


def _unkeyed_digest(checkpoint: dict[str, object]) -> str:
    payload = {key: value for key, value in checkpoint.items() if key != "digest"}
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


class CheckpointSaved(Exception):
    pass


def _save_before_sleep(
    storage: dict[str, object], retryer: Retrying
) -> typing.Callable[[RetryCallState], None]:
    def before_sleep(retry_state: RetryCallState) -> None:
        storage["checkpoint"] = retryer.to_checkpoint(retry_state)
        raise CheckpointSaved

    return before_sleep


class _FailUntil:
    def __init__(self, stop_at: int) -> None:
        self.stop_at = stop_at
        self.attempts: list[int] = []

    def __call__(self) -> None:
        self.attempts.append(len(self.attempts) + 1)
        if len(self.attempts) < self.stop_at:
            raise RuntimeError("not ready")


def _fail_until(stop_at: int) -> _FailUntil:
    return _FailUntil(stop_at)


class _AsyncFailUntil:
    def __init__(self, stop_at: int) -> None:
        self.stop_at = stop_at
        self.counter = 0

    async def __call__(self) -> None:
        self.counter += 1
        if self.counter < self.stop_at:
            raise RuntimeError("not ready")


async def _sleep_record(seconds: float, sleeps: list[float]) -> None:
    sleeps.append(seconds)


def run_async(coroutine: typing.Coroutine[typing.Any, typing.Any, None]) -> None:
    import asyncio

    asyncio.run(coroutine)


@tenacity.register_wait_strategy("tests.checkpoint.register_wait")
class RegisteredCheckpointWait(tenacity.CheckpointableWait):
    def __init__(self, offset: float) -> None:
        self.offset = offset

    def __call__(self, retry_state: RetryCallState) -> float:
        del retry_state
        return self.offset

    def to_checkpoint(self) -> "JSONValue":
        return {"offset": self.offset}

    @classmethod
    def from_checkpoint(cls, state: "JSONValue") -> "RegisteredCheckpointWait":
        if type(state) is not dict or set(state) != {"offset"}:
            raise CheckpointError("invalid registered wait state")
        offset = state["offset"]
        if type(offset) not in (int, float) or isinstance(offset, bool):
            raise CheckpointError("offset must be a number")
        return cls(float(offset))


def test_checkpoint_resumes_at_next_attempt_with_remaining_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage: dict[str, object] = {}
    sleeps: list[float] = []
    first = _fail_until(3)
    retryer = Retrying(
        wait=wait_fixed(10),
        stop=tenacity.stop_after_attempt(3),
        sleep=sleeps.append,
        reraise=True,
    )
    retryer.before_sleep = _save_before_sleep(storage, retryer)

    with pytest.raises(CheckpointSaved):
        retryer(first)

    checkpoint = copy.deepcopy(storage["checkpoint"])
    assert isinstance(checkpoint, dict)
    assert checkpoint["attempt_number"] == 2
    assert checkpoint["sleep_for"] == 10
    assert "outcome" not in checkpoint
    assert "fn" not in checkpoint
    assert "coroutine" not in json.dumps(checkpoint)

    monkeypatch.setattr(
        tenacity.checkpoint,
        "wall_now",
        lambda: _saved_at(checkpoint) + 3,
    )

    second = _fail_until(2)
    resumed = Retrying(
        wait=wait_none(),
        stop=tenacity.stop_after_attempt(3),
        sleep=sleeps.append,
    )
    resumed.restore_checkpoint(checkpoint)
    resumed(second)

    assert second.attempts == [1, 2]
    assert resumed.statistics["attempt_number"] == 3
    assert sleeps[0] == pytest.approx(7)
    assert sleeps[1] == pytest.approx(10)

    encoded = json.dumps(copy.deepcopy(storage["checkpoint"]))
    loaded = tenacity.load_checkpoint(encoded)
    assert loaded.attempt_number == 2


def test_restart_downtime_counts_against_delay_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage: dict[str, object] = {}
    retryer = Retrying(
        wait=wait_fixed(10),
        stop=tenacity.stop_after_delay(50),
        reraise=True,
    )
    retryer.before_sleep = _save_before_sleep(storage, retryer)

    with pytest.raises(CheckpointSaved):
        retryer(_fail_until(10**6))

    checkpoint = storage["checkpoint"]
    assert isinstance(checkpoint, dict)
    monkeypatch.setattr(
        tenacity.checkpoint,
        "wall_now",
        lambda: _saved_at(checkpoint) + 100,
    )

    sleeps: list[float] = []
    resumed = Retrying(
        stop=tenacity.stop_after_delay(50),
        sleep=sleeps.append,
        reraise=True,
    )
    resumed.restore_checkpoint(checkpoint)

    with pytest.raises(RuntimeError):
        resumed(_fail_until(10**6))

    assert sleeps == []


def test_checkpoint_rejects_tampering_and_wrong_secret() -> None:
    storage: dict[str, object] = {}
    retryer = Retrying(
        wait=wait_fixed(1),
    )
    retryer.before_sleep = _save_before_sleep(storage, retryer)

    with pytest.raises(CheckpointSaved):
        retryer(_fail_until(10**6))

    checkpoint = storage["checkpoint"]
    assert isinstance(checkpoint, dict)
    tampered = copy.deepcopy(checkpoint)
    tampered["attempt_number"] = 1
    with pytest.raises(CheckpointError, match="tampered"):
        Retrying().restore_checkpoint(tampered)

    with pytest.raises(CheckpointError, match="tampered"):
        Retrying().restore_checkpoint(checkpoint, secret="different")


def test_signed_checkpoint_requires_matching_secret() -> None:
    storage: dict[str, object] = {}
    retryer = Retrying(
        wait=wait_fixed(1),
        stop=tenacity.stop_after_attempt(2),
        before_sleep=lambda state: storage.__setitem__(
            "checkpoint", retryer.to_checkpoint(state, secret="application-secret")
        ),
        sleep=lambda _: None,
    )

    with pytest.raises(tenacity.RetryError):
        retryer(_fail_until(10**6))

    checkpoint = storage["checkpoint"]
    assert isinstance(checkpoint, dict)
    assert checkpoint["digest"].startswith("hmac-sha256:")
    with pytest.raises(CheckpointError):
        Retrying().restore_checkpoint(checkpoint)
    Retrying().restore_checkpoint(checkpoint, secret="application-secret")


def test_checkpoint_only_allowed_in_before_sleep_phase() -> None:
    retryer = Retrying(
        stop=tenacity.stop_after_attempt(1),
        after=lambda state: retryer.to_checkpoint(state),
        reraise=True,
    )

    with pytest.raises(CheckpointError, match="between attempts"):
        retryer(_fail_until(10**6))


def test_unsupported_wait_strategies_are_rejected() -> None:
    storage: dict[str, object] = {}
    retryer = Retrying(
        wait=lambda state: 1,
        reraise=True,
    )
    retryer.before_sleep = _save_before_sleep(storage, retryer)

    with pytest.raises(CheckpointError, match="plain callable"):
        retryer(_fail_until(10**6))


def test_unsupported_nested_wait_callable_is_rejected() -> None:
    with pytest.raises(CheckpointError, match="plain callable"):
        tenacity.dump_wait(wait_fixed(1) + (lambda state: 1))


def test_unsupported_wait_strategy_version_is_rejected() -> None:
    with pytest.raises(CheckpointError, match="unsupported wait strategy"):
        load_wait({"name": "wait_fixed", "version": 999, "state": {"wait": 1}})


def test_unsupported_top_level_checkpoint_version_is_rejected() -> None:
    storage: dict[str, object] = {}
    retryer = Retrying(wait=wait_fixed(1))
    retryer.before_sleep = _save_before_sleep(storage, retryer)

    with pytest.raises(CheckpointSaved):
        retryer(_fail_until(10**6))

    checkpoint = copy.deepcopy(storage["checkpoint"])
    assert isinstance(checkpoint, dict)
    checkpoint["version"] = 999
    checkpoint["digest"] = _unkeyed_digest(checkpoint)

    with pytest.raises(CheckpointError, match="unsupported retry checkpoint version"):
        Retrying().restore_checkpoint(checkpoint)


def test_forged_unsafe_phase_is_rejected() -> None:
    storage: dict[str, object] = {}
    retryer = Retrying(wait=wait_fixed(1))
    retryer.before_sleep = _save_before_sleep(storage, retryer)

    with pytest.raises(CheckpointSaved):
        retryer(_fail_until(10**6))

    checkpoint = copy.deepcopy(storage["checkpoint"])
    assert isinstance(checkpoint, dict)
    checkpoint["phase"] = "attempt_running"
    checkpoint["digest"] = _unkeyed_digest(checkpoint)

    with pytest.raises(CheckpointError, match="safe between-attempts phase"):
        Retrying().restore_checkpoint(checkpoint)


@pytest.mark.parametrize(
    "strategy",
    [
        wait_none(),
        wait_fixed(1),
        wait_random(0.1, 1),
        wait_combine(wait_fixed(1), wait_incrementing(0, 2, 5)),
        wait_chain(wait_fixed(1), wait_fixed(2)),
        wait_incrementing(0, 2, 5),
        wait_exponential(multiplier=1, min=0.1, max=8, exp_base=2),
        wait_random_exponential(multiplier=1, min=0.1, max=8, exp_base=2),
        wait_exponential_jitter(multiplier=1, jitter=0.5, min=0.1, max=8),
        RegisteredCheckpointWait(2.5),
    ],
)
def test_supported_wait_strategies_round_trip(strategy: object) -> None:
    exported = tenacity.dump_wait(strategy)
    json.dumps(exported)
    restored = load_wait(exported)
    assert tenacity.dump_wait(restored) == exported


def test_wait_exception_is_not_implicitly_serializable() -> None:
    strategy = tenacity.wait_exception(lambda exception: 1)
    with pytest.raises(CheckpointError, match="wait_exception"):
        tenacity.dump_wait(strategy)


def test_async_checkpoint_resumes_at_next_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage: dict[str, object] = {}
    sleeps: list[float] = []
    first = _AsyncFailUntil(2)
    second = _AsyncFailUntil(1)

    async def save(retry_state: RetryCallState) -> None:
        storage["checkpoint"] = retryer.to_checkpoint(retry_state)
        raise CheckpointSaved

    retryer = AsyncRetrying(
        wait=wait_fixed(10),
        stop=tenacity.stop_after_attempt(2),
        before_sleep=save,
        sleep=lambda seconds: _sleep_record(seconds, sleeps),
        reraise=True,
    )

    with pytest.raises(CheckpointSaved):
        run_async(retryer(first))

    checkpoint = storage["checkpoint"]
    assert isinstance(checkpoint, dict)
    monkeypatch.setattr(
        tenacity.checkpoint,
        "wall_now",
        lambda: float(checkpoint["saved_at"]) + 4,
    )

    resumed = AsyncRetrying(
        stop=tenacity.stop_after_attempt(2),
        sleep=lambda seconds: _sleep_record(seconds, sleeps),
    )
    resumed.restore_checkpoint(checkpoint)
    run_async(resumed(second))

    assert first.counter == 1
    assert second.counter == 1
    assert resumed.statistics["attempt_number"] == 2
    assert sleeps[0] == pytest.approx(6)


def test_context_checkpoint_restores_without_saving_callable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage: dict[str, object] = {}
    sleeps: list[float] = []

    def persist(retry_state: RetryCallState) -> None:
        storage["checkpoint"] = retryer.to_checkpoint(retry_state)
        raise CheckpointSaved

    retryer = Retrying(
        wait=wait_fixed(10),
        stop=tenacity.stop_after_attempt(2),
        before_sleep=persist,
        sleep=sleeps.append,
        reraise=True,
    )

    with pytest.raises(CheckpointSaved):
        for attempt in retryer:
            with attempt:
                raise RuntimeError("first failure")

    checkpoint = storage["checkpoint"]
    assert isinstance(checkpoint, dict)
    monkeypatch.setattr(
        tenacity.checkpoint,
        "wall_now",
        lambda: _saved_at(checkpoint) + 10,
    )

    outcomes: list[str] = []
    resumed = Retrying(
        wait=wait_none(),
        stop=tenacity.stop_after_attempt(2),
        sleep=sleeps.append,
        reraise=True,
    )
    resumed.restore_checkpoint(checkpoint)
    for attempt in resumed:
        with attempt:
            outcomes.append("resumed")

    assert outcomes == ["resumed"]
    assert sleeps == []


async def _sleep_record(seconds: float, sleeps: list[float]) -> None:
    sleeps.append(seconds)
