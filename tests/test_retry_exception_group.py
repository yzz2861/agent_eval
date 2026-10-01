# Copyright 2026 Tenacity contributors
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
"""Tests for :class:`tenacity.retry_if_exception_group`."""

import asyncio
import builtins
import dataclasses
import sys
import typing

import pytest

import tenacity
from tenacity import RetryCallState, retry_if_exception_group
from tenacity.retry import (
    EXCEPTION_GROUP_TYPES,
    LeafDecisionReason,
    retry_if_exception,
)

pytestmark = pytest.mark.skipif(
    not EXCEPTION_GROUP_TYPES,
    reason="exception groups require Python 3.11+ or the exceptiongroup backport",
)

if sys.version_info >= (3, 11):
    _BaseGroup = builtins.__dict__["BaseExceptionGroup"]
    _ErrorGroup = builtins.__dict__["ExceptionGroup"]
else:  # pragma: no cover - exercised only without a 3.11 interpreter
    import exceptiongroup

    _BaseGroup: type[typing.Any] = exceptiongroup.BaseExceptionGroup
    _ErrorGroup: type[typing.Any] = exceptiongroup.ExceptionGroup


def _state_for(exception: BaseException) -> RetryCallState:
    state = RetryCallState(None, None, (), {})  # type: ignore[arg-type]
    state.set_exception((type(exception), exception, exception.__traceback__))
    return state


def _successful_state() -> RetryCallState:
    state = RetryCallState(None, None, (), {})  # type: ignore[arg-type]
    state.set_result(42)
    return state


def _report(strategy: retry_if_exception_group) -> tenacity.ExceptionGroupReport:
    assert strategy.report is not None
    return strategy.report


def test_all_mode_requires_every_leaf() -> None:
    strategy = retry_if_exception_group((ValueError, TypeError))
    group = _ErrorGroup("g", [ValueError(), TypeError()])

    assert strategy(_state_for(group)) is True
    assert strategy.report is not None
    assert [leaf.path for leaf in strategy.report.leaves] == [(0,), (1,)]
    assert all(leaf.retry for leaf in strategy.report.leaves)

    mixed = _ErrorGroup("g", [ValueError(), KeyError()])
    assert strategy(_state_for(mixed)) is False
    report = _report(strategy)
    assert [leaf.path for leaf in report.continue_leaves] == [(0,)]
    assert [leaf.path for leaf in report.stop_leaves] == [(1,)]
    assert report.leaf_at(0).reason is LeafDecisionReason.MATCHED
    assert report.leaf_at(1).reason is LeafDecisionReason.REJECTED


def test_any_mode_retries_when_one_leaf_matches() -> None:
    strategy = retry_if_exception_group(ValueError, mode="any")
    group = _ErrorGroup("g", [KeyError(), TypeError(), ValueError()])

    assert strategy(_state_for(group)) is True
    report = _report(strategy)
    assert report.mode == "any"
    assert [leaf.path for leaf in report.continue_leaves] == [(2,)]
    assert {leaf.path for leaf in report.stop_leaves} == {(0,), (1,)}


def test_invalid_mode() -> None:
    with pytest.raises(ValueError, match="mode must be 'all' or 'any'"):
        retry_if_exception_group(mode="at-least-some")


def test_nested_groups_preserve_paths() -> None:
    strategy = retry_if_exception_group((ValueError, TypeError))
    group = _ErrorGroup(
        "outer",
        [
            ValueError("v"),
            _ErrorGroup(
                "inner", [TypeError("t"), _ErrorGroup("deep", [KeyError("k")])]
            ),
        ],
    )

    assert strategy(_state_for(group)) is False
    report = _report(strategy)
    assert [leaf.path for leaf in report.leaves] == [(0,), (1, 0), (1, 1, 0)]
    assert report.leaf_at(1, 1, 0).exception.args == ("k",)
    assert report.root is group
    with pytest.raises(KeyError):
        report.leaf_at(2)


def test_predicate_and_existing_strategy_inputs() -> None:
    by_predicate = retry_if_exception_group(
        lambda exc: getattr(exc, "errno", None) == 5
    )
    group = _ErrorGroup("g", [OSError(5), OSError(6)])
    assert by_predicate(_state_for(group)) is False

    wrapped = retry_if_exception_group(
        retry_if_exception(lambda exc: isinstance(exc, OSError))
    )
    assert wrapped(_state_for(group)) is True


def test_plain_exception_is_single_leaf() -> None:
    strategy = retry_if_exception_group(ValueError)
    assert strategy(_state_for(ValueError())) is True
    report = _report(strategy)
    assert len(report.leaves) == 1
    assert report.leaves[0].path == ()

    assert strategy(_state_for(KeyError())) is False
    assert strategy(_successful_state()) is False
    assert strategy.report is None


def test_excluded_type_is_never_retried() -> None:
    group = _ErrorGroup("g", [ValueError("retry-me"), KeyError("no")])
    strategy = retry_if_exception_group(Exception, exclude=(ValueError,))

    assert strategy(_state_for(group)) is False
    report = _report(strategy)
    excluded = report.leaf_at(0)
    assert excluded.retry is False
    assert excluded.reason is LeafDecisionReason.EXCLUDED


def test_excluded_type_vetoes_any_mode() -> None:
    group = _ErrorGroup("g", [ValueError(), KeyError()])
    strategy = retry_if_exception_group(ValueError, mode="any", exclude=(KeyError,))
    assert strategy(_state_for(group)) is False


@pytest.mark.parametrize(
    "control",
    [
        KeyboardInterrupt(),
        SystemExit(1),
        GeneratorExit(),
        asyncio.CancelledError(),
    ],
)
def test_control_flow_exceptions_are_not_retried(control: BaseException) -> None:
    group = _BaseGroup("g", [ValueError(), control])
    strategy = retry_if_exception_group(BaseException, mode="any")

    assert strategy(_state_for(group)) is False
    report = _report(strategy)
    decision = report.leaf_at(1)
    assert decision.retry is False
    assert decision.reason is LeafDecisionReason.CONTROL_FLOW


def test_control_flow_in_cause_chain_is_not_retried() -> None:
    try:
        raise ValueError("root") from KeyboardInterrupt()
    except ValueError as exc:
        group = _BaseGroup("g", [exc])
    strategy = retry_if_exception_group(BaseException)
    assert strategy(_state_for(group)) is False
    report = _report(strategy)
    assert report.leaf_at(0).reason is LeafDecisionReason.CONTROL_FLOW


def test_non_retryable_can_be_customised() -> None:
    strategy = retry_if_exception_group(Exception, non_retryable=(LookupError,))
    group = _ErrorGroup("g", [ValueError(), KeyError()])
    assert strategy(_state_for(group)) is False
    report = _report(strategy)
    assert report.leaf_at(1).reason is LeafDecisionReason.CONTROL_FLOW

    opt_out = retry_if_exception_group(BaseException, non_retryable=())
    assert opt_out(_state_for(_BaseGroup("g", [KeyboardInterrupt()]))) is True


def test_matching_exception_in_cause_chain() -> None:
    try:
        raise KeyError("key")
    except KeyError:
        try:
            raise RuntimeError("wrapper")
        except RuntimeError as wrapper:
            group = _ErrorGroup("g", [wrapper])

    strategy = retry_if_exception_group(KeyError)
    assert strategy(_state_for(group)) is True
    report = _report(strategy)
    leaf = report.leaves[0]
    assert leaf.retry is True
    assert leaf.reason is LeafDecisionReason.MATCHED
    assert isinstance(leaf.exception, KeyError)


def test_matching_exception_in_context_chain() -> None:
    try:
        raise KeyError("key")
    except KeyError:
        try:
            raise ValueError("value") from RuntimeError("cause")
        except ValueError as wrapper:
            group = _ErrorGroup("g", [wrapper])

    strategy = retry_if_exception_group(KeyError)
    assert strategy(_state_for(group)) is True


def test_self_referential_cause_chain_terminates() -> None:
    exc = ValueError("self")
    exc.__cause__ = exc
    group = _ErrorGroup("g", [exc])
    strategy = retry_if_exception_group(KeyError)

    assert strategy(_state_for(group)) is False


def test_two_node_cycle_terminates() -> None:
    first = RuntimeError("a")
    second = ValueError("b")
    first.__cause__ = second
    second.__context__ = first
    group = _ErrorGroup("g", [first, second])
    strategy = retry_if_exception_group(KeyError)

    assert strategy(_state_for(group)) is False


def test_report_is_frozen_and_navigable() -> None:
    strategy = retry_if_exception_group(ValueError, mode="any")
    group = _ErrorGroup("g", [ValueError(), KeyError()])
    strategy(_state_for(group))
    report = _report(strategy)

    with pytest.raises(dataclasses.FrozenInstanceError):
        report.retry = False  # type: ignore[misc]
    leaf = report.leaf_at(1)
    with pytest.raises(dataclasses.FrozenInstanceError):
        leaf.retry = True  # type: ignore[misc]
    assert leaf.decided_continue is False
    assert leaf.decided_stop is True


def test_missing_outcome_raises() -> None:
    strategy = retry_if_exception_group()
    state = RetryCallState(None, None, (), {})  # type: ignore[arg-type]
    with pytest.raises(RuntimeError, match="before outcome was set"):
        strategy(state)


def test_retries_until_success_with_original_group_reraised() -> None:
    attempts = 0

    def flaky() -> str:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise _ErrorGroup(
                "flaky", [ValueError("transient"), TypeError("also transient")]
            )
        return "done"

    retrying = tenacity.Retrying(
        retry=retry_if_exception_group((ValueError, TypeError)),
        stop=tenacity.stop_after_attempt(5),
        wait=tenacity.wait_none(),
    )
    assert retrying(flaky) == "done"
    assert attempts == 3


def test_reraise_keeps_original_exception_group() -> None:
    original = _ErrorGroup("final", [ValueError("still failing")])

    def always_fails() -> typing.NoReturn:
        raise original

    retrying = tenacity.Retrying(
        retry=retry_if_exception_group(ValueError),
        stop=tenacity.stop_after_attempt(3),
        wait=tenacity.wait_none(),
        reraise=True,
    )
    with pytest.raises(_ErrorGroup) as exc_info:
        retrying(always_fails)
    assert exc_info.value is original


def test_non_reraise_wraps_original_failure() -> None:
    def always_fails() -> typing.NoReturn:
        raise _ErrorGroup("final", [ValueError()])

    retrying = tenacity.Retrying(
        retry=retry_if_exception_group(ValueError),
        stop=tenacity.stop_after_attempt(2),
        wait=tenacity.wait_none(),
    )
    with pytest.raises(tenacity.RetryError) as exc_info:
        retrying(always_fails)
    assert isinstance(exc_info.value.last_attempt.exception(), _ErrorGroup)


def test_combines_with_existing_strategies() -> None:
    message_match = retry_if_exception_group(
        lambda exc: isinstance(exc, ValueError) and "yes" in str(exc)
    )
    strategy = retry_if_exception_group(ValueError) & message_match
    assert strategy(_state_for(_ErrorGroup("g", [ValueError("yes")]))) is True
    assert strategy(_state_for(_ErrorGroup("g", [ValueError("no")]))) is False
    assert strategy(_state_for(_ErrorGroup("g", [KeyError("yes")]))) is False

    # Plain exceptions keep working through the same composition.
    assert strategy(_state_for(ValueError("yes"))) is True


class _LoopyGroup(_BaseGroup):  # type: ignore[misc]
    """Group whose member list references itself (defensive cycle guard)."""

    __slots__ = ()

    @property
    def exceptions(self) -> tuple[BaseException, ...]:
        return (self, ValueError("leaf"))


def test_structural_group_cycle_terminates() -> None:
    group = _LoopyGroup("loop", [ValueError("seed")])
    strategy = retry_if_exception_group(ValueError)

    assert strategy(_state_for(group)) is True
    report = _report(strategy)
    # The self-reference is skipped; the real leaf is reached via index 1.
    assert [decision.path for decision in report.leaves] == [(1,)]
