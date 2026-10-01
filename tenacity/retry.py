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
import asyncio
import builtins
import dataclasses
import enum
import importlib
import re
import sys
import typing

from tenacity._utils import override

if typing.TYPE_CHECKING:
    from tenacity import RetryCallState


if typing.TYPE_CHECKING:

    class _ExceptionGroupLike(typing.Protocol):
        message: str
        exceptions: tuple[BaseException, ...]


def _resolve_exception_group_types() -> tuple[type[BaseException], ...]:
    """Return the available exception-group types.

    ``BaseExceptionGroup`` is a builtin since Python 3.11. On older
    interpreters the ``exceptiongroup`` backport is used when installed.
    Importing the backport lazily keeps it an optional dependency.
    """
    if sys.version_info >= (3, 11):
        group_type = getattr(builtins, "BaseExceptionGroup", None)
        if isinstance(group_type, type):
            return (group_type,)
        return ()
    try:
        backport = importlib.import_module("exceptiongroup")
    except ImportError:
        return ()
    group_type = getattr(backport, "BaseExceptionGroup", None)
    if isinstance(group_type, type):
        return (group_type,)
    return ()


EXCEPTION_GROUP_TYPES: typing.Final = _resolve_exception_group_types()


class LeafDecisionReason(enum.Enum):
    """Why a leaf exception was decided to be retried or not."""

    #: An exception in the leaf's cause/context chain matched the predicate.
    MATCHED = "matched"
    #: No exception in the leaf's cause/context chain matched the predicate.
    REJECTED = "rejected"
    #: A control-flow exception (cancellation/exit) was found in the chain.
    CONTROL_FLOW = "control-flow"
    #: An explicitly excluded exception type was found in the chain.
    EXCLUDED = "excluded"


@dataclasses.dataclass(frozen=True, slots=True)
class ExceptionLeafDecision:
    """The retry decision for a single leaf of an :class:`ExceptionGroup`.

    ``path`` locates the leaf inside the (possibly nested) group tree using a
    tuple of child indexes, e.g. ``(0, 2)`` means ``group.exceptions[0]`` is a
    nested group whose third member is this leaf. The path is structural, so
    it never depends on parsing the group message or any other string.
    """

    path: tuple[int, ...]
    exception: BaseException
    retry: bool
    reason: LeafDecisionReason

    @property
    def decided_continue(self) -> bool:
        """Whether this leaf decided in favour of another attempt."""
        return self.retry

    @property
    def decided_stop(self) -> bool:
        """Whether this leaf decided against another attempt."""
        return not self.retry


@dataclasses.dataclass(frozen=True, slots=True)
class ExceptionGroupReport:
    """Structured outcome of an exception-group retry evaluation.

    The nested group structure is preserved in :attr:`leaves` through their
    :attr:`ExceptionLeafDecision.path` values; the original exception is left
    untouched and is available as :attr:`root`.
    """

    mode: str
    root: BaseException
    leaves: tuple[ExceptionLeafDecision, ...]
    retry: bool

    @property
    def continue_leaves(self) -> tuple[ExceptionLeafDecision, ...]:
        """Leaves that voted for retrying."""
        return tuple(leaf for leaf in self.leaves if leaf.retry)

    @property
    def stop_leaves(self) -> tuple[ExceptionLeafDecision, ...]:
        """Leaves that voted to stop retrying."""
        return tuple(leaf for leaf in self.leaves if not leaf.retry)

    def leaf_at(self, *path: int) -> ExceptionLeafDecision:
        """Return the decision of the leaf located at ``path``.

        :param path: child indexes into the nested group tree.
        :raises KeyError: if no leaf exists at that path.
        """
        key = tuple(path)
        for leaf in self.leaves:
            if leaf.path == key:
                return leaf
        raise KeyError(key)


#: Control-flow exceptions must not be swallowed by retries: cancelling a task
#: or interrupting the process should always propagate immediately.
DEFAULT_NON_RETRYABLE_EXCEPTIONS: typing.Final = (
    asyncio.CancelledError,
    KeyboardInterrupt,
    SystemExit,
    GeneratorExit,
)


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


def _group_children(exc: BaseException) -> tuple[BaseException, ...] | None:
    if EXCEPTION_GROUP_TYPES and isinstance(exc, EXCEPTION_GROUP_TYPES):
        return typing.cast("_ExceptionGroupLike", exc).exceptions
    return None


def _collect_group_leaves(
    root: BaseException,
) -> list[tuple[tuple[int, ...], BaseException]]:
    """Flatten an exception group into ``(path, leaf)`` pairs.

    Nested groups keep their position in the tree: each path is a tuple of
    indexes into ``ExceptionGroup.exceptions``. Object identity guards the
    traversal against groups whose member lists have been mutated to share a
    child or to form a structural cycle.
    """
    leaves: list[tuple[tuple[int, ...], BaseException]] = []
    visited: set[int] = set()
    stack: list[tuple[tuple[int, ...], BaseException]] = [((), root)]
    while stack:
        path, node = stack.pop()
        if id(node) in visited:
            continue
        visited.add(id(node))
        children = _group_children(node)
        if children is None:
            leaves.append((path, node))
            continue
        # Push in reverse so members are visited left-to-right.
        stack.extend(
            (path + (index,), children[index])
            for index in range(len(children) - 1, -1, -1)
        )
    leaves.sort(key=lambda item: item[0])
    return leaves


class retry_if_exception_group(retry_base):
    """Retry strategy aware of :class:`ExceptionGroup` trees.

    The strategy walks the nested group structure and asks every **leaf**
    exception whether it should be retried. Each leaf is inspected together
    with its ``__cause__`` and ``__context__`` chains (cycles terminate the
    traversal safely), so errors raised ``from`` another error are handled
    just like by the non-group strategies.

    :param retry_on: Which leaf exceptions are retryable. Either one or
        several exception types (the default is :class:`Exception`), a
        predicate taking an exception and returning a boolean, or an
        existing :class:`retry_if_exception` strategy whose predicate is
        reused.
    :param mode: ``"all"`` (the default) retries only when **every** leaf is
        retryable; ``"any"`` retries when **at least one** leaf is retryable.
        Control-flow and excluded leaves always veto a retry, in both modes.
    :param exclude: Exception types that must never be retried, even when
        they match ``retry_on`` or appear in a cause/context chain.
    :param non_retryable: Control-flow exception types that are never
        retried. Defaults to :data:`DEFAULT_NON_RETRYABLE_EXCEPTIONS`
        (``CancelledError``, ``KeyboardInterrupt``, ``SystemExit`` and
        ``GeneratorExit``). Pass an empty tuple to opt out.

    The structured result of the latest evaluation (which leaf voted to
    continue or stop, and why) is available as :attr:`report`. Plain, i.e.
    non-group, exceptions are handled as a group with a single leaf, so this
    strategy can be used as a drop-in replacement for the type-based
    strategies. Like every :class:`retry_base`, it can be combined with
    other strategies using ``&`` and ``|``.
    """

    def __init__(
        self,
        retry_on: (
            type[BaseException]
            | tuple[type[BaseException], ...]
            | typing.Callable[[BaseException], bool]
            | retry_if_exception
        ) = Exception,
        *,
        mode: str = "all",
        exclude: type[BaseException] | tuple[type[BaseException], ...] = (),
        non_retryable: type[BaseException] | tuple[type[BaseException], ...] = (
            DEFAULT_NON_RETRYABLE_EXCEPTIONS
        ),
    ) -> None:
        if mode not in ("all", "any"):
            raise ValueError(f"mode must be 'all' or 'any', got {mode!r}")
        self.mode = mode
        self.excluded_types = exclude if isinstance(exclude, tuple) else (exclude,)
        self.non_retryable_types = (
            non_retryable if isinstance(non_retryable, tuple) else (non_retryable,)
        )
        if isinstance(retry_on, retry_if_exception):
            self.predicate: typing.Callable[[BaseException], bool] = retry_on.predicate
        elif isinstance(retry_on, (type, tuple)):
            self.predicate = self._type_predicate(retry_on)
        elif callable(retry_on):
            self.predicate = retry_on
        else:
            raise TypeError(
                "retry_on must be an exception type, a tuple of exception "
                f"types, or a predicate, got {type(retry_on).__name__}"
            )
        #: Structured report of the most recent evaluation, or ``None``.
        self.report: ExceptionGroupReport | None = None

    @staticmethod
    def _type_predicate(
        exception_types: type[BaseException] | tuple[type[BaseException], ...],
    ) -> typing.Callable[[BaseException], bool]:
        return lambda exception: isinstance(exception, exception_types)

    def _classify_leaf(
        self, path: tuple[int, ...], leaf: BaseException
    ) -> ExceptionLeafDecision:
        """Decide one leaf, walking its cause/context chains.

        Precedence is: non-retryable control-flow types (anywhere in the
        chain) > explicitly excluded types (anywhere) > a predicate match
        (anywhere) > reject. The identity-based ``visited`` set guarantees
        termination when ``__cause__``/``__context__`` form a cycle.
        """
        visited: set[int] = set()
        stack: list[BaseException] = [leaf]
        excluded: BaseException | None = None
        matched: BaseException | None = None
        while stack:
            exc = stack.pop()
            if id(exc) in visited:
                continue
            visited.add(id(exc))
            if isinstance(exc, self.non_retryable_types):
                return ExceptionLeafDecision(
                    path, exc, False, LeafDecisionReason.CONTROL_FLOW
                )
            if excluded is None and isinstance(exc, self.excluded_types):
                excluded = exc
            if matched is None and self.predicate(exc):
                matched = exc
            # Both chains are considered: a matching error may live in the
            # implicit context even when an explicit cause is present.
            if exc.__context__ is not None:
                stack.append(exc.__context__)
            if exc.__cause__ is not None:
                stack.append(exc.__cause__)
        if excluded is not None:
            return ExceptionLeafDecision(
                path, excluded, False, LeafDecisionReason.EXCLUDED
            )
        if matched is not None:
            return ExceptionLeafDecision(
                path, matched, True, LeafDecisionReason.MATCHED
            )
        return ExceptionLeafDecision(path, leaf, False, LeafDecisionReason.REJECTED)

    @override
    def __call__(self, retry_state: "RetryCallState") -> bool:
        if retry_state.outcome is None:
            raise RuntimeError("__call__() called before outcome was set")
        if not retry_state.outcome.failed:
            self.report = None
            return False

        exception = retry_state.outcome.exception()
        if exception is None:
            raise RuntimeError("outcome failed but the exception is None")

        if _group_children(exception) is not None:
            leaves = tuple(
                self._classify_leaf(path, leaf)
                for path, leaf in _collect_group_leaves(exception)
            )
        else:
            # A plain exception is a tree with exactly one leaf at the root;
            # cause/context, exclusion and control-flow rules still apply.
            leaves = (self._classify_leaf((), exception),)

        # Control-flow and explicitly excluded leaves veto the decision in
        # every mode: otherwise an "any" retry could hide a cancellation or
        # an excluded error by re-running the whole group. Ignoring empty
        # groups likewise avoids retrying a call that produced no leaf.
        vetoed = any(
            leaf.reason
            in (LeafDecisionReason.CONTROL_FLOW, LeafDecisionReason.EXCLUDED)
            for leaf in leaves
        )
        if not vetoed and leaves:
            if self.mode == "all":
                retry = all(leaf.retry for leaf in leaves)
            else:
                retry = any(leaf.retry for leaf in leaves)
        else:
            retry = False
        self.report = ExceptionGroupReport(self.mode, exception, leaves, retry)
        return retry
