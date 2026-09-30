from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from tenacity import (
    AsyncRetrying,
    RetryAfterAction,
    RetryAfterDecision,
    RetryAfterDuplicatePolicy,
    RetryAfterError,
    RetryAfterHeader,
    RetryAfterInvalidPolicy,
    RetryAfterStalePolicy,
    RetryCallState,
    Retrying,
    retry_if_exception_type,
    stop_after_attempt,
    stop_any,
    stop_before_delay,
    wait_fixed,
    wait_retry_after,
)


class ResponseError(RuntimeError):
    def __init__(self, headers: dict[str, str]) -> None:
        super().__init__("response error")
        self.headers = headers


def state(value: object = None) -> RetryCallState:
    retry_state = RetryCallState(None, None, (), {})  # type: ignore[arg-type]
    retry_state.set_result(value)
    return retry_state


def extract_retry_after(retry_state: RetryCallState) -> object:
    return retry_state.outcome.result()  # type: ignore[union-attr]


def test_seconds_are_a_lower_bound_for_local_backoff() -> None:
    retry_state = state("5")
    decisions: list[RetryAfterDecision] = []
    strategy = wait_retry_after(
        extract_retry_after,
        wait_fixed(2),
        on_decision=lambda rs, decision: decisions.append(decision),
    )

    assert strategy(retry_state) == 5.0
    assert decisions == [retry_state.wait_decision]
    assert retry_state.wait_decision == RetryAfterDecision(
        server_wait=5.0,
        local_wait=2.0,
        wait=5.0,
        action=RetryAfterAction.WAIT,
    )


def test_local_backoff_is_used_when_server_says_sooner() -> None:
    retry_state = state(1)
    strategy = wait_retry_after(extract_retry_after, wait_fixed(4))

    assert strategy(retry_state) == 4.0
    assert retry_state.wait_decision is not None
    assert retry_state.wait_decision.wait == 4.0
    assert retry_state.wait_decision.server_wait == 1.0


def test_clock_skew_tolerance_must_be_finite_and_non_negative() -> None:
    with pytest.raises(ValueError):
        wait_retry_after(extract_retry_after, clock_skew_tolerance=-1)


def test_http_date_uses_response_date_to_cancel_clock_offset() -> None:
    retry_state = RetryCallState(None, None, (), {})  # type: ignore[arg-type]
    retry_state.set_result(None)
    server_now = datetime(2030, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    retry_after = server_now + timedelta(seconds=10)
    strategy = wait_retry_after(
        lambda rs: RetryAfterHeader(
            retry_after=retry_after.strftime("%a, %d %b %Y %H:%M:%S GMT"),
            date=server_now.strftime("%a, %d %b %Y %H:%M:%S GMT"),
        )
    )

    retry_state.outcome_timestamp = 100.0
    with mock.patch("tenacity.wait.time.monotonic", return_value=103.0):
        assert strategy(retry_state) == pytest.approx(7.0)


def test_http_date_accepts_non_utc_timezone() -> None:
    retry_state = RetryCallState(None, None, (), {})  # type: ignore[arg-type]
    retry_state.set_result(None)
    retry_state.outcome_timestamp = 100.0
    server_date = datetime(2030, 1, 1, 14, 0, tzinfo=timezone(timedelta(hours=2)))
    retry_after = server_date + timedelta(seconds=10)
    strategy = wait_retry_after(
        lambda rs: RetryAfterHeader(
            retry_after=retry_after,
            date=server_date,
        )
    )

    with mock.patch("tenacity.wait.time.monotonic", return_value=102.5):
        assert strategy(retry_state) == pytest.approx(7.5)


def test_extractor_can_read_response_from_exception() -> None:
    retry_state = RetryCallState(None, None, (), {})  # type: ignore[arg-type]
    exception = ResponseError({"Retry-After": "6"})
    retry_state.set_exception((type(exception), exception, None))
    strategy = wait_retry_after(
        lambda rs: rs.outcome.exception().headers["Retry-After"]  # type: ignore[union-attr]
    )

    assert strategy(retry_state) == 6.0


def test_http_date_without_response_date_adds_clock_skew_tolerance() -> None:
    retry_state = RetryCallState(None, None, (), {})  # type: ignore[arg-type]
    retry_state.set_result(None)
    retry_after = datetime.now(timezone.utc) + timedelta(seconds=10)
    strategy = wait_retry_after(
        lambda rs: retry_after.strftime("%a, %d %b %Y %H:%M:%S GMT"),
        clock_skew_tolerance=2,
    )

    with mock.patch("tenacity.wait.time.time", return_value=0.0):
        retry_after = datetime.fromtimestamp(10, timezone.utc)
        assert strategy(retry_state) == pytest.approx(12.0)


@pytest.mark.parametrize(
    ("values", "policy", "expected"),
    [
        (["10", "3"], RetryAfterDuplicatePolicy.USE_EARLIEST, 3.0),
        (["10", "3"], RetryAfterDuplicatePolicy.USE_LATEST, 10.0),
        (["10", "-1"], RetryAfterStalePolicy.IGNORE, 10.0),
    ],
)
def test_duplicate_and_stale_values(
    values: list[str],
    policy: object,
    expected: float,
) -> None:
    retry_state = state(values)
    strategy = wait_retry_after(
        extract_retry_after,
        duplicate=policy
        if isinstance(policy, RetryAfterDuplicatePolicy)
        else RetryAfterDuplicatePolicy.USE_LATEST,
        stale=policy
        if isinstance(policy, RetryAfterStalePolicy)
        else RetryAfterStalePolicy.IGNORE,
    )

    assert strategy(retry_state) == expected


def test_duplicate_values_can_raise() -> None:
    strategy = wait_retry_after(
        extract_retry_after,
        duplicate=RetryAfterDuplicatePolicy.RAISE,
    )
    with pytest.raises(RetryAfterError):
        strategy(state(["1", "2"]))


@pytest.mark.parametrize(
    ("policy", "action"),
    [
        (RetryAfterInvalidPolicy.IGNORE, RetryAfterAction.WAIT),
        (RetryAfterInvalidPolicy.STOP, RetryAfterAction.STOP),
    ],
)
def test_malformed_values_are_configurable(
    policy: RetryAfterInvalidPolicy, action: RetryAfterAction
) -> None:
    retry_state = state(["bad", "5"])
    strategy = wait_retry_after(
        extract_retry_after,
        wait_fixed(2),
        malformed=policy,
    )

    assert strategy(retry_state) == (
        5.0 if policy is RetryAfterInvalidPolicy.IGNORE else 2.0
    )
    assert retry_state.wait_decision is not None
    assert retry_state.wait_decision.action is action


def test_all_malformed_values_stop_without_short_wait() -> None:
    retry_state = state(["bad"])
    strategy = wait_retry_after(
        extract_retry_after,
        wait_fixed(2),
        malformed=RetryAfterInvalidPolicy.STOP,
    )

    assert strategy(retry_state) == 2.0
    assert retry_state.wait_decision_stop_requested is True


def test_malformed_stop_is_honored_by_retrying_without_sleep() -> None:
    sleeps: list[float] = []
    attempts = 0

    def flaky() -> None:
        nonlocal attempts
        attempts += 1
        raise ResponseError({"Retry-After": "not-a-date"})

    decisions: list[RetryAfterDecision] = []
    retrying = Retrying(
        sleep=sleeps.append,
        retry=retry_if_exception_type(ResponseError),
        wait=wait_retry_after(
            lambda rs: rs.outcome.exception().headers["Retry-After"],  # type: ignore[union-attr]
            wait_fixed(2),
            malformed=RetryAfterInvalidPolicy.STOP,
            on_decision=lambda rs, decision: decisions.append(decision),
        ),
        reraise=True,
    )

    with pytest.raises(ResponseError):
        retrying(flaky)

    assert attempts == 1
    assert sleeps == []
    assert len(decisions) == 1
    assert decisions[0].action is RetryAfterAction.STOP
    assert decisions[0].wait == 2.0


def test_sync_retrying_rejects_async_decision_hook() -> None:
    async def on_decision(
        retry_state: RetryCallState, decision: RetryAfterDecision
    ) -> None:
        pass

    retrying = Retrying(
        stop=stop_after_attempt(1),
        wait=wait_retry_after(lambda rs: "1", on_decision=on_decision),
    )

    def flaky() -> None:
        raise RuntimeError("retry")

    with pytest.raises(TypeError, match="AsyncRetrying"):
        retrying(flaky)


def test_stale_values_are_configurable() -> None:
    retry_state = state(
        RetryAfterHeader(
            datetime.now(timezone.utc) - timedelta(seconds=1),
        )
    )
    strategy = wait_retry_after(
        extract_retry_after,
        wait_fixed(2),
        stale=RetryAfterStalePolicy.STOP,
    )

    assert strategy(retry_state) == 2.0
    assert retry_state.wait_decision_stop_requested is True


def test_deadline_stops_instead_of_truncating_sleep() -> None:
    sleeps: list[float] = []
    attempts = 0

    def flaky() -> None:
        nonlocal attempts
        attempts += 1
        raise RuntimeError("retry")

    decision_hook = mock.Mock()
    retrying = Retrying(
        sleep=sleeps.append,
        stop=stop_before_delay(1),
        wait=wait_retry_after(
            lambda rs: "10",
            on_decision=decision_hook,
        ),
        reraise=True,
    )

    with mock.patch("tenacity.time.monotonic") as monotonic:
        monotonic.side_effect = [0.0, 0.75, 0.75]
        with pytest.raises(RuntimeError):
            retrying(flaky)

    assert attempts == 1
    assert sleeps == []
    decision = decision_hook.call_count
    assert decision == 1
    _, reported = decision_hook.call_args.args
    assert reported.action is RetryAfterAction.STOP
    assert reported.wait == 10.0


def test_deadline_composite_stops_without_sleep() -> None:
    sleeps: list[float] = []
    attempts = 0
    decisions: list[RetryAfterDecision] = []

    def flaky() -> None:
        nonlocal attempts
        attempts += 1
        raise RuntimeError("retry")

    retrying = Retrying(
        sleep=sleeps.append,
        stop=stop_any(stop_before_delay(1), stop_after_attempt(5)),
        reraise=True,
        wait=wait_retry_after(
            lambda rs: "10",
            on_decision=lambda rs, decision: decisions.append(decision),
        ),
    )

    with mock.patch("tenacity.time.monotonic") as monotonic:
        monotonic.side_effect = [0.0, 0.5, 0.5]
        with pytest.raises(RuntimeError):
            retrying(flaky)

    assert attempts == 1
    assert sleeps == []
    assert decisions[0].action is RetryAfterAction.STOP
    assert decisions[0].wait == 10.0


def test_async_path_uses_same_decision_and_hook() -> None:
    asyncio.run(_test_async_path_uses_same_decision_and_hook())


async def _test_async_path_uses_same_decision_and_hook() -> None:
    sleeps: list[float] = []
    decisions: list[RetryAfterDecision] = []
    attempts = 0

    async def flaky() -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("retry")

    async def sleep(value: float) -> None:
        sleeps.append(value)

    async def on_decision(
        retry_state: RetryCallState, decision: RetryAfterDecision
    ) -> None:
        decisions.append(decision)

    await AsyncRetrying(
        sleep=sleep,
        stop=stop_after_attempt(2),
        wait=wait_retry_after(
            lambda rs: "3",
            wait_fixed(1),
            on_decision=on_decision,
        ),
    )(flaky)

    assert sleeps == [3.0]
    assert len(decisions) == 1
    assert decisions[0].server_wait == 3.0
    assert decisions[0].local_wait == 1.0
    assert decisions[0].wait == 3.0
