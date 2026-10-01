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
import re
import sys
import typing
from asyncio import CancelledError as AsyncioCancelledError
from concurrent.futures import CancelledError as FuturesCancelledError

from tenacity._utils import override

if typing.TYPE_CHECKING:
    from tenacity import RetryCallState


class retry_base(abc.ABC):
    """Abstract base class for retry strategies."""

    @abc.abstractmethod
    def __call__(self, retry_state: "RetryCallState") -> bool:
        pass

    def __and__(self, other: "RetryBaseT") -> "retry_all":
        if isinstance(other, retry_base):
            return other.__rand__(self)
        # Plain callable: flatten if self is already a retry_all
        if isinstance(self, retry_all):
            return retry_all(*self.retries, other)
        return retry_all(self, other)

    def __rand__(self, other: "RetryBaseT") -> "retry_all":
        # Flatten if other is already a retry_all
        if isinstance(other, retry_all):
            return retry_all(*other.retries, self)
        return retry_all(other, self)

    def __or__(self, other: "RetryBaseT") -> "retry_any":
        if isinstance(other, retry_base):
            return other.__ror__(self)
        # Plain callable: flatten if self is already a retry_any
        if isinstance(self, retry_any):
            return retry_any(*self.retries, other)
        return retry_any(self, other)

    def __ror__(self, other: "RetryBaseT") -> "retry_any":
        # Flatten if other is already a retry_any
        if isinstance(other, retry_any):
            return retry_any(*other.retries, self)
        return retry_any(other, self)


RetryBaseT = retry_base | typing.Callable[["RetryCallState"], bool]


class _retry_never(retry_base):
    """Retry strategy that never rejects any result."""

    @override
    def __call__(self, retry_state: "RetryCallState") -> bool:
        return False


retry_never = _retry_never()


class _retry_always(retry_base):
    """Retry strategy that always rejects any result."""

    @override
    def __call__(self, retry_state: "RetryCallState") -> bool:
        return True


retry_always = _retry_always()


class retry_if_exception(retry_base):
    """Retry strategy that retries if an exception verifies a predicate."""

    def __init__(self, predicate: typing.Callable[[BaseException], bool]) -> None:
        self.predicate = predicate

    @override
    def __call__(self, retry_state: "RetryCallState") -> bool:
        if retry_state.outcome is None:
            raise RuntimeError("__call__() called before outcome was set")

        if retry_state.outcome.failed:
            exception = retry_state.outcome.exception()
            if exception is None:
                raise RuntimeError("outcome failed but the exception is None")
            return self.predicate(exception)
        return False


class retry_if_exception_type(retry_if_exception):
    """Retries if an exception has been raised of one or more types."""

    def __init__(
        self,
        exception_types: type[BaseException]
        | tuple[type[BaseException], ...] = Exception,
    ) -> None:
        self.exception_types = exception_types
        super().__init__(self._check)

    def _check(self, e: BaseException) -> bool:
        return isinstance(e, self.exception_types)


class retry_if_not_exception_type(retry_if_exception):
    """Retries except an exception has been raised of one or more types."""

    def __init__(
        self,
        exception_types: type[BaseException]
        | tuple[type[BaseException], ...] = Exception,
    ) -> None:
        self.exception_types = exception_types
        super().__init__(self._check)

    def _check(self, e: BaseException) -> bool:
        return not isinstance(e, self.exception_types)


class retry_unless_exception_type(retry_if_exception):
    """Retries until an exception is raised of one or more types."""

    def __init__(
        self,
        exception_types: type[BaseException]
        | tuple[type[BaseException], ...] = Exception,
    ) -> None:
        self.exception_types = exception_types
        super().__init__(self._check)

    def _check(self, e: BaseException) -> bool:
        return not isinstance(e, self.exception_types)

    @override
    def __call__(self, retry_state: "RetryCallState") -> bool:
        if retry_state.outcome is None:
            raise RuntimeError("__call__() called before outcome was set")

        # always retry if no exception was raised
        if not retry_state.outcome.failed:
            return True

        exception = retry_state.outcome.exception()
        if exception is None:
            raise RuntimeError("outcome failed but the exception is None")
        return self.predicate(exception)


class retry_if_exception_cause_type(retry_base):
    """Retries if any of the causes of the raised exception is of one or more types.

    The check on the type of the cause of the exception is done recursively (until finding
    an exception in the chain that has no ``__cause__``, or a cycle is detected).
    """

    def __init__(
        self,
        exception_types: type[BaseException]
        | tuple[type[BaseException], ...] = Exception,
    ) -> None:
        self.exception_cause_types = exception_types

    @override
    def __call__(self, retry_state: "RetryCallState") -> bool:
        if retry_state.outcome is None:
            raise RuntimeError("__call__ called before outcome was set")

        if retry_state.outcome.failed:
            exc = retry_state.outcome.exception()
            # Guard against cyclic __cause__ chains (e.g. ``raise e from e``),
            # which would otherwise spin forever inside the predicate and
            # prevent stop conditions from ever running (see #658).
            seen: set[int] = set()
            while exc is not None and id(exc) not in seen:
                seen.add(id(exc))
                if isinstance(exc.__cause__, self.exception_cause_types):
                    return True
                exc = exc.__cause__

        return False


if sys.version_info >= (3, 11):
    _EXCEPTION_GROUP_TYPES: tuple[type[BaseException], ...] = (BaseExceptionGroup,)
else:  # pragma: no cover
    try:
        from exceptiongroup import BaseExceptionGroup as _BackportBaseExceptionGroup
    except ImportError:
        _EXCEPTION_GROUP_TYPES = ()
    else:
        _EXCEPTION_GROUP_TYPES = (_BackportBaseExceptionGroup,)

# Control-flow exceptions that must never be retried by default: they signal
# that the surrounding runtime (event loop, interpreter, user) wants the
# operation to stop, not to be attempted again.
CONTROL_FLOW_EXCEPTION_TYPES: tuple[type[BaseException], ...] = (
    AsyncioCancelledError,
    FuturesCancelledError,
    KeyboardInterrupt,
    SystemExit,
    GeneratorExit,
)

# Markers used in ExceptionLeaf.path when the traversal follows
# __cause__ / __context__ instead of a group child index.
CAUSE_PATH_STEP = "cause"
CONTEXT_PATH_STEP = "context"


@dataclasses.dataclass(frozen=True)
class ExceptionLeaf:
    """A non-group exception reached while traversing an exception tree.

    The path locates the leaf structurally, without any string parsing:
    integers index into BaseExceptionGroup.exceptions and the markers
    CAUSE_PATH_STEP / CONTEXT_PATH_STEP hop along __cause__ / __context__.
    A plain (non-group) exception has the empty path ().
    """

    path: tuple[int | str, ...]
    exception: BaseException


def iter_exception_leaves(
    exception: BaseException,
    *,
    include_cause: bool = True,
    include_context: bool = True,
) -> typing.Iterator[ExceptionLeaf]:
    """Yield every non-group exception reachable from the exception.

    BaseExceptionGroup instances are traversed recursively (preserving
    the nested structure through each leaf's path); every other exception
    is yielded as a leaf. __cause__ and (unless explicitly suppressed)
    __context__ chains are followed too, so groups wrapped via
    raise ... from ... are still found. Cyclic cause/context chains are
    detected by identity and terminate the traversal instead of hanging.
    """
    seen: set[int] = set()

    def walk(
        exc: BaseException, path: tuple[int | str, ...]
    ) -> typing.Iterator[ExceptionLeaf]:
        if id(exc) in seen:
            return
        seen.add(id(exc))
        if _EXCEPTION_GROUP_TYPES and isinstance(exc, _EXCEPTION_GROUP_TYPES):
            for index, sub_exception in enumerate(exc.exceptions):
                yield from walk(sub_exception, path + (index,))
        else:
            yield ExceptionLeaf(path=path, exception=exc)
        if include_cause and exc.__cause__ is not None:
            yield from walk(exc.__cause__, path + (CAUSE_PATH_STEP,))
        if (
            include_context
            and not exc.__suppress_context__
            and exc.__context__ is not None
        ):
            yield from walk(exc.__context__, path + (CONTEXT_PATH_STEP,))

    yield from walk(exception, ())


class _retry_if_exception_group_base(retry_base):
    """Base class for retry strategies inspecting exception group leaves."""

    def __init__(
        self,
        exception_types: type[BaseException]
        | tuple[type[BaseException], ...] = Exception,
        *,
        exclude_types: type[BaseException]
        | tuple[type[BaseException], ...] = (),
        include_cause: bool = True,
        include_context: bool = True,
        allow_control_flow: bool = False,
    ) -> None:
        self.exception_types = exception_types
        self.exclude_types = exclude_types
        self.include_cause = include_cause
        self.include_context = include_context
        self.allow_control_flow = allow_control_flow
        # Reporting, refreshed on every __call__: all leaves that were found
        # and the subset that decided whether to continue or stop.
        self.last_leaves: tuple[ExceptionLeaf, ...] = ()
        self.deciding_leaves: tuple[ExceptionLeaf, ...] = ()

    def _is_control_flow(self, leaf: ExceptionLeaf) -> bool:
        return isinstance(leaf.exception, CONTROL_FLOW_EXCEPTION_TYPES)

    def _is_retryable_leaf(self, leaf: ExceptionLeaf) -> bool:
        if not self.allow_control_flow and self._is_control_flow(leaf):
            return False
        return isinstance(leaf.exception, self.exception_types) and not isinstance(
            leaf.exception, self.exclude_types
        )

    def _decide(
        self,
        retryable: tuple[ExceptionLeaf, ...],
        non_retryable: tuple[ExceptionLeaf, ...],
    ) -> bool:
        raise NotImplementedError

    @override
    def __call__(self, retry_state: "RetryCallState") -> bool:
        if retry_state.outcome is None:
            raise RuntimeError("__call__() called before outcome was set")

        self.last_leaves = ()
        self.deciding_leaves = ()
        if not retry_state.outcome.failed:
            return False

        exception = retry_state.outcome.exception()
        if exception is None:
            raise RuntimeError("outcome failed but the exception is None")

        leaves = tuple(
            iter_exception_leaves(
                exception,
                include_cause=self.include_cause,
                include_context=self.include_context,
            )
        )
        self.last_leaves = leaves
        if not leaves:
            return False

        if not self.allow_control_flow:
            control_flow = tuple(lf for lf in leaves if self._is_control_flow(lf))
            if control_flow:
                self.deciding_leaves = control_flow
                return False

        retryable = tuple(lf for lf in leaves if self._is_retryable_leaf(lf))
        non_retryable = tuple(lf for lf in leaves if not self._is_retryable_leaf(lf))
        return self._decide(retryable, non_retryable)


class retry_if_exception_group_all(_retry_if_exception_group_base):
    """Retries only if every leaf of the exception (group) is retryable.

    A leaf is retryable when it matches exception_types and does not
    match exclude_types. Plain (non-group) exceptions are treated as a
    single leaf, so this degrades gracefully to retry_if_exception_type
    semantics. Control-flow exceptions (CancelledError, KeyboardInterrupt,
    SystemExit, GeneratorExit) stop the retry by default, even if they
    would match exception_types; pass allow_control_flow=True to judge
    them like any other leaf.

    After each call, last_leaves holds every leaf found and
    deciding_leaves the leaves that determined the outcome: the
    non-retryable ones when stopping, all of them when continuing.
    """

    @override
    def _decide(
        self,
        retryable: tuple[ExceptionLeaf, ...],
        non_retryable: tuple[ExceptionLeaf, ...],
    ) -> bool:
        if non_retryable:
            self.deciding_leaves = non_retryable
            return False
        self.deciding_leaves = retryable
        return True


class retry_if_exception_group_any(_retry_if_exception_group_base):
    """Retries if at least one leaf of the exception (group) is retryable.

    Accepts the same parameters and reports the same leaf information as
    retry_if_exception_group_all. deciding_leaves holds the retryable
    leaves that kept the retry going, or every leaf when none matched
    and the retry stopped.
    """

    @override
    def _decide(
        self,
        retryable: tuple[ExceptionLeaf, ...],
        non_retryable: tuple[ExceptionLeaf, ...],
    ) -> bool:
        if retryable:
            self.deciding_leaves = retryable
            return True
        self.deciding_leaves = non_retryable
        return False


class retry_if_result(retry_base):
    """Retries if the result verifies a predicate."""

    def __init__(self, predicate: typing.Callable[[typing.Any], bool]) -> None:
        self.predicate = predicate

    @override
    def __call__(self, retry_state: "RetryCallState") -> bool:
        if retry_state.outcome is None:
            raise RuntimeError("__call__() called before outcome was set")

        if not retry_state.outcome.failed:
            return self.predicate(retry_state.outcome.result())
        return False


class retry_if_not_result(retry_base):
    """Retries if the result refutes a predicate."""

    def __init__(self, predicate: typing.Callable[[typing.Any], bool]) -> None:
        self.predicate = predicate

    @override
    def __call__(self, retry_state: "RetryCallState") -> bool:
        if retry_state.outcome is None:
            raise RuntimeError("__call__() called before outcome was set")

        if not retry_state.outcome.failed:
            return not self.predicate(retry_state.outcome.result())
        return False


class retry_if_exception_message(retry_if_exception):
    """Retries if an exception message equals or matches."""

    def __init__(
        self,
        message: str | None = None,
        match: str | re.Pattern[str] | None = None,
    ) -> None:
        if message is not None and match is not None:
            raise TypeError(
                f"{self.__class__.__name__}() takes either 'message' or 'match', not both"
            )

        if message is None and match is None:
            raise TypeError(
                f"{self.__class__.__name__}() missing 1 required argument 'message' or 'match'"
            )

        self.message = message
        self.match: re.Pattern[str] | None = (
            re.compile(match) if match is not None else None
        )
        super().__init__(self._check)

    def _check(self, exception: BaseException) -> bool:
        if self.message is not None:
            return self.message == str(exception)
        assert self.match is not None
        return bool(self.match.match(str(exception)))


class retry_if_not_exception_message(retry_if_exception_message):
    """Retries until an exception message equals or matches."""

    @override
    def _check(self, exception: BaseException) -> bool:
        return not super()._check(exception)

    @override
    def __call__(self, retry_state: "RetryCallState") -> bool:
        if retry_state.outcome is None:
            raise RuntimeError("__call__() called before outcome was set")

        if not retry_state.outcome.failed:
            return True

        exception = retry_state.outcome.exception()
        if exception is None:
            raise RuntimeError("outcome failed but the exception is None")
        return self.predicate(exception)


class retry_any(retry_base):
    """Retries if any of the retries condition is valid."""

    def __init__(self, *retries: "RetryBaseT") -> None:
        self.retries = retries

    @override
    def __call__(self, retry_state: "RetryCallState") -> bool:
        return any(r(retry_state) for r in self.retries)

    @override
    def __ror__(self, other: "RetryBaseT") -> "retry_any":
        if isinstance(other, retry_any):
            return retry_any(*other.retries, *self.retries)
        return retry_any(other, *self.retries)


class retry_all(retry_base):
    """Retries if all the retries condition are valid."""

    def __init__(self, *retries: "RetryBaseT") -> None:
        self.retries = retries

    @override
    def __call__(self, retry_state: "RetryCallState") -> bool:
        return all(r(retry_state) for r in self.retries)

    @override
    def __rand__(self, other: "RetryBaseT") -> "retry_all":
        if isinstance(other, retry_all):
            return retry_all(*other.retries, *self.retries)
        return retry_all(other, *self.retries)
