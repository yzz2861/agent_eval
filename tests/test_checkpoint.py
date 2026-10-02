import asyncio
import dataclasses
import hashlib
import hmac
import json
import time

import pytest

from tenacity import (
    AsyncRetrying,
    RetryCallState,
    RetryCheckpoint,
    RetryCheckpointError,
    Retrying,
    retry_if_exception_type,
    stop_after_delay,
    wait_chain,
    wait_combine,
    wait_exponential,
    wait_fixed,
)
from tenacity.wait import (
    JsonValue,
    deserialize_wait_strategy,
    register_wait_strategy,
    serialize_wait_strategy,
    unregister_wait_strategy,
    wait_base,
)

SECRET = "checkpoint-secret"


class TemporaryFailure(RuntimeError):
    pass


class CustomWait(wait_base):
    def __init__(self, factor: float) -> None:
        self.factor = factor

    def __call__(self, retry_state: RetryCallState) -> float:
        return self.factor


def _custom_factor(state: dict[str, JsonValue]) -> float:
    factor = state["factor"]
    assert isinstance(factor, (int, float)) and not isinstance(factor, bool)
    return float(factor)


def _register_custom_wait() -> None:
    register_wait_strategy(
        CustomWait,
        name="test.custom",
        version=1,
        dump_state=lambda strategy: {"factor": strategy.factor},
        load_state=lambda state: CustomWait(_custom_factor(state)),
    )


def _capture_checkpoint() -> RetryCheckpoint:
    captured: list[RetryCheckpoint] = []

    def before_sleep(retry_state: RetryCallState) -> None:
        captured.append(RetryCheckpoint.from_retry_state(retry_state))

    def shutdown_sleep(seconds: float) -> None:
        raise RuntimeError("simulated process shutdown")

    retrying = Retrying(
        wait=wait_fixed(0.01),
        retry=retry_if_exception_type(TemporaryFailure),
        before_sleep=before_sleep,
        sleep=shutdown_sleep,
    )

    def fail_once() -> None:
        raise TemporaryFailure("first attempt failed")

    with pytest.raises(RuntimeError, match="simulated process shutdown"):
        retrying(fail_once)

    return captured[0]


def _sign(payload: dict[str, object], secret: str = SECRET) -> bytes:
    payload_bytes = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    signature = hmac.new(
        secret.encode("utf-8"), payload_bytes, hashlib.sha256
    ).hexdigest()
    envelope = {
        "version": 1,
        "payload": json.loads(payload_bytes),
        "signature": signature,
    }
    return json.dumps(
        envelope, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def test_checkpoint_resumes_at_next_attempt_and_next_allowed_time() -> None:
    checkpoint = _capture_checkpoint()
    attempts: list[int] = []
    sleeps: list[float] = []

    def before(retry_state: RetryCallState) -> None:
        attempts.append(retry_state.attempt_number)

    retrying = Retrying(wait=wait_fixed(10), before=before, sleep=sleeps.append)

    result = retrying.resume(checkpoint, lambda: "restarted", secret=None)

    assert result == "restarted"
    assert attempts == [2]
    assert len(sleeps) == 1
    assert 0 <= sleeps[0] <= 0.01


def test_resumed_failure_uses_restored_attempt_backoff() -> None:
    now = time.time()
    checkpoint = dataclasses.replace(
        _capture_checkpoint(),
        elapsed_budget=0.0,
        saved_at=now,
        next_allowed_at=now,
        wait_strategy=wait_exponential(multiplier=1, max=10),
    )
    attempts: list[int] = []
    sleeps: list[float] = []

    def before(retry_state: RetryCallState) -> None:
        attempts.append(retry_state.attempt_number)

    retrying = Retrying(
        wait=wait_exponential(multiplier=1, max=10),
        retry=retry_if_exception_type(TemporaryFailure),
        before=before,
        sleep=sleeps.append,
    )

    def fail_resumed_attempt() -> str:
        if attempts[-1] == 2:
            raise TemporaryFailure("resumed attempt failed")
        return "third attempt"

    assert retrying.resume(checkpoint, fail_resumed_attempt) == "third attempt"
    assert attempts == [2, 3]
    assert sleeps == [pytest.approx(2.0)]


def test_resume_accepts_serialized_checkpoint_and_new_callable_arguments() -> None:
    checkpoint = _capture_checkpoint().to_bytes(SECRET)
    retrying = Retrying(wait=wait_fixed(0.01), sleep=lambda seconds: None)

    assert retrying.resume(checkpoint, lambda value: value, "ok", secret=SECRET) == (
        "ok"
    )


def test_restart_downtime_counts_against_elapsed_budget() -> None:
    now = time.time()
    checkpoint = dataclasses.replace(
        _capture_checkpoint(),
        attempt_number=2,
        elapsed_budget=5.0,
        saved_at=now - 7.0,
        next_allowed_at=now + 0.02,
    )
    attempts: list[int] = []
    sleeps: list[float] = []

    def before(retry_state: RetryCallState) -> None:
        attempts.append(retry_state.attempt_number)

    retrying = Retrying(
        wait=wait_fixed(10),
        stop=stop_after_delay(10),
        retry=retry_if_exception_type(TemporaryFailure),
        before=before,
        sleep=sleeps.append,
        reraise=True,
    )

    with pytest.raises(TemporaryFailure):
        retrying.resume(
            checkpoint,
            lambda: (_ for _ in ()).throw(TemporaryFailure("deadline passed")),
        )

    assert attempts == [2]
    assert len(sleeps) == 1
    assert 0 <= sleeps[0] <= 0.02
    assert retrying.statistics["delay_since_first_attempt"] >= 12.0


def test_checkpoint_contains_no_function_exception_or_coroutine_state() -> None:
    raw = _capture_checkpoint().to_bytes(SECRET)
    envelope = json.loads(raw)

    assert set(envelope) == {"version", "payload", "signature"}
    assert set(envelope["payload"]) == {
        "version",
        "attempt_number",
        "elapsed_budget",
        "saved_at",
        "next_allowed_at",
        "wait_strategy",
    }
    serialized = raw.decode("utf-8")
    assert "fail_once" not in serialized
    assert "TemporaryFailure" not in serialized
    assert "first attempt failed" not in serialized


@pytest.mark.parametrize(
    ("strategy", "expected_type"),
    [
        (wait_fixed(2.5), "fixed"),
        (wait_exponential(multiplier=2, max=10), "exponential"),
        (wait_combine(wait_fixed(1), wait_fixed(2)), "combine"),
        (wait_chain(wait_fixed(1), wait_fixed(2)), "chain"),
    ],
)
def test_builtin_wait_strategies_round_trip(
    strategy: wait_base, expected_type: str
) -> None:
    data = serialize_wait_strategy(strategy)
    restored = deserialize_wait_strategy(data)
    restored_data = serialize_wait_strategy(restored)

    assert data["type"] == expected_type
    assert data["version"] == 1
    assert type(restored) is type(strategy)
    assert restored_data == data


def test_registered_extension_wait_strategy_round_trips() -> None:
    _register_custom_wait()
    try:
        data = serialize_wait_strategy(CustomWait(2.5))
        restored = deserialize_wait_strategy(data)
    finally:
        unregister_wait_strategy(CustomWait)

    assert data == {
        "type": "test.custom",
        "version": 1,
        "state": {"factor": 2.5},
    }
    assert isinstance(restored, CustomWait)
    assert restored.factor == 2.5


def test_future_checkpoint_is_rejected_during_resume() -> None:
    now = time.time()
    checkpoint = dataclasses.replace(
        _capture_checkpoint(),
        saved_at=now + 10,
        next_allowed_at=now + 10.01,
    )
    retrying = Retrying(sleep=lambda seconds: None)

    with pytest.raises(RetryCheckpointError, match="future"):
        retrying.resume(checkpoint, lambda: None)


def test_extension_loader_returning_unexpected_type_is_rejected() -> None:
    register_wait_strategy(
        CustomWait,
        name="test.bad-loader",
        dump_state=lambda strategy: {"factor": strategy.factor},
        load_state=lambda state: wait_fixed(_custom_factor(state)),
    )
    try:
        raw = RetryCheckpoint(
            attempt_number=2,
            elapsed_budget=0.0,
            saved_at=time.time(),
            next_allowed_at=time.time(),
            wait_strategy=CustomWait(1),
        ).to_bytes(SECRET)

        with pytest.raises(RetryCheckpointError, match="unexpected type"):
            RetryCheckpoint.from_bytes(raw, SECRET)
    finally:
        unregister_wait_strategy(CustomWait)


def test_unregistered_strategy_version_is_rejected_on_load() -> None:
    checkpoint = _capture_checkpoint()
    raw = checkpoint.to_bytes(SECRET)
    envelope = json.loads(raw)
    envelope["payload"]["wait_strategy"]["version"] = 999

    with pytest.raises(RetryCheckpointError, match="unsupported wait strategy"):
        RetryCheckpoint.from_bytes(_sign(envelope["payload"]), SECRET)


def test_plain_callable_wait_strategy_is_not_serializable() -> None:
    captured: list[RetryCheckpoint] = []

    def shutdown_sleep(seconds: float) -> None:
        raise AssertionError("retry should not reach sleep")

    retrying = Retrying(
        wait=lambda retry_state: 1,
        retry=retry_if_exception_type(TemporaryFailure),
        before_sleep=lambda retry_state: captured.append(
            RetryCheckpoint.from_retry_state(retry_state)
        ),
        sleep=shutdown_sleep,
    )

    with pytest.raises(RetryCheckpointError, match="wait strategy is unsupported"):
        retrying(lambda: (_ for _ in ()).throw(TemporaryFailure("x")))


def test_tampered_checkpoint_is_rejected() -> None:
    raw = _capture_checkpoint().to_bytes(SECRET)
    tampered = raw.replace(b'"attempt_number":2', b'"attempt_number":3')

    with pytest.raises(RetryCheckpointError, match="signature is invalid"):
        RetryCheckpoint.from_bytes(tampered, SECRET)

    with pytest.raises(RetryCheckpointError, match="signature is invalid"):
        RetryCheckpoint.from_bytes(raw, "wrong-secret")


def test_checkpoint_version_mismatch_is_rejected() -> None:
    raw = _capture_checkpoint().to_bytes(SECRET)
    envelope = json.loads(raw)
    envelope["version"] = 0
    envelope["payload"]["version"] = 0

    with pytest.raises(RetryCheckpointError, match="unsupported checkpoint version"):
        RetryCheckpoint.from_bytes(json.dumps(envelope).encode(), SECRET)


def test_unsafe_checkpoint_phase_is_rejected() -> None:
    retrying = Retrying(wait=wait_fixed(1))
    retry_state = RetryCallState(retrying, lambda: None, (), {})

    with pytest.raises(RetryCheckpointError, match="between retry attempts"):
        RetryCheckpoint.from_retry_state(retry_state)

    retry_state.set_result(None)
    with pytest.raises(RetryCheckpointError, match="unsafe retry phase"):
        RetryCheckpoint.from_retry_state(retry_state)


def test_async_resume_reuses_checkpoint() -> None:
    checkpoint = _capture_checkpoint()
    attempts: list[int] = []

    def before(retry_state: RetryCallState) -> None:
        attempts.append(retry_state.attempt_number)

    async def sleep(seconds: float) -> None:
        return None

    async def succeed() -> str:
        return "async restarted"

    retrying = AsyncRetrying(
        wait=wait_fixed(0.01),
        before=before,
        sleep=sleep,
    )

    result = asyncio.run(retrying.resume(checkpoint, succeed))

    assert result == "async restarted"
    assert attempts == [2]
