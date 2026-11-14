#
# Copyright (C) 2009-2020 the sqlparse authors and contributors
# <see AUTHORS file>
#
# This module is part of python-sqlparse and is released under
# the BSD License: https://opensource.org/licenses/BSD-3-Clause

"""Per-invocation resource budgets for parsing untrusted SQL.

A :class:`ParseLimits` value describes how much work a single ``parse()``,
``format()`` or ``split()`` call may perform.  Limits are attached to the
call instead of to the lexer singleton, so repeated calls never share or
accumulate state.

The :class:`ParseBudget` is carried through lexing, statement splitting and
grouping via a :class:`contextvars.ContextVar` and is checked *before*
descending into the next nesting or grouping level.
"""

from __future__ import annotations

import dataclasses
import time
from contextlib import contextmanager
from contextvars import ContextVar

from sqlparse.exceptions import SQLParseLimitError

# Limit names reported on :class:`SQLParseLimitError`.
TOKENS = "tokens"
TOKEN_LENGTH = "token_length"
NESTING_DEPTH = "nesting_depth"
GROUPING_DEPTH = "grouping_depth"
GROUPING_CALLS = "grouping_calls"
TIMEOUT = "timeout"

_LIMIT_FIELDS = (
    "max_tokens",
    "max_nesting_depth",
    "max_grouping_depth",
    "max_grouping_calls",
    "max_token_length",
    "timeout",
)

# monotonic() is cheap but calling it for every token/group on multi-million
# token inputs would dominate the runtime, so time checks are throttled.
_TIME_CHECK_INTERVAL = 64


def _positive_integer(name, value):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer or None")
    return value


@dataclasses.dataclass(frozen=True)
class ParseLimits:
    """Resource limits for a single parse/format/split invocation.

    A value of ``None`` means the engine fallback (the module-level
    constants in :mod:`sqlparse.engine.grouping`) applies.  Those constants
    keep the historical defaults of 10,000 tokens and 100 grouping levels
    and can still be set to ``None`` to disable the corresponding guard.
    """

    max_tokens: int | None = None
    max_nesting_depth: int | None = None
    max_grouping_depth: int | None = None
    max_grouping_calls: int | None = None
    max_token_length: int | None = None
    timeout: float | None = None

    def __post_init__(self):
        for field_name in _LIMIT_FIELDS:
            value = getattr(self, field_name)
            if field_name == "timeout":
                if value is not None and (
                    isinstance(value, bool)
                    or not isinstance(value, (int, float))
                    or value <= 0
                ):
                    raise ValueError(
                        "timeout must be a positive number of seconds or None"
                    )
            else:
                object.__setattr__(
                    self,
                    field_name,
                    _positive_integer(field_name, value),
                )


def coerce_limits(limits=None, **overrides):
    """Build a :class:`ParseLimits` from an instance and keyword overrides.

    Keyword arguments set to ``None`` are ignored so that entry points can
    forward their keyword defaults without overriding an explicit instance.
    """
    if limits is None:
        resolved = ParseLimits()
    elif isinstance(limits, ParseLimits):
        resolved = limits
    else:
        raise TypeError(
            "limits must be a ParseLimits instance or None, got "
            f"{type(limits)!r}"
        )

    active = {
        name: value
        for name, value in overrides.items()
        if name in _LIMIT_FIELDS and value is not None
    }
    unknown = set(overrides) - set(_LIMIT_FIELDS)
    if unknown:
        raise TypeError(f"Unknown resource limit(s): {sorted(unknown)!r}")
    if active:
        resolved = dataclasses.replace(resolved, **active)
    return resolved


class ParseBudget:
    """Mutable bookkeeping for the resource usage of one invocation."""

    def __init__(self, limits):
        self.limits = limits
        self.tokens = 0
        # Character offset reached in the input.  Updated by the lexer before
        # each token is emitted and retained on failure for error reporting.
        self.consumed = 0
        self.nesting_depth = 0
        self.peak_nesting_depth = 0
        self.peak_grouping_depth = 0
        self.grouping_calls = 0
        self._time_checks = 0
        self.deadline = (
            time.monotonic() + limits.timeout
            if limits.timeout is not None
            else None
        )

    def fail(self, limit, message):
        error = SQLParseLimitError(message, limit=limit, consumed=self.consumed)
        error.budget = self
        raise error

    def check_time(self, force=False):
        if self.deadline is None:
            return
        self._time_checks += 1
        if not force and self._time_checks % _TIME_CHECK_INTERVAL:
            return
        if time.monotonic() >= self.deadline:
            timeout = self.limits.timeout
            self.fail(
                TIMEOUT,
                f"Processing time limit exceeded ({timeout} seconds).",
            )

    def count_token(self, value):
        """Account for one lexer token before it is yielded."""
        max_length = self.limits.max_token_length
        if max_length is not None and len(value) > max_length:
            self.fail(
                TOKEN_LENGTH,
                f"Maximum token length exceeded ({max_length}).",
            )
        self.tokens += 1
        max_tokens = self.limits.max_tokens
        if max_tokens is not None and self.tokens > max_tokens:
            self.fail(
                TOKENS,
                f"Maximum number of tokens exceeded ({max_tokens}).",
            )
        self.check_time()

    def enter_nesting(self):
        """Account for an opening parenthesis or CASE/IF/FOR/BEGIN block."""
        self.nesting_depth += 1
        if self.nesting_depth > self.peak_nesting_depth:
            self.peak_nesting_depth = self.nesting_depth
        limit = self.limits.max_nesting_depth
        if limit is not None and self.nesting_depth > limit:
            self.fail(
                NESTING_DEPTH,
                f"Maximum nesting depth exceeded ({limit}).",
            )
        self.check_time()

    def leave_nesting(self):
        if self.nesting_depth > 0:
            self.nesting_depth -= 1

    def check_grouping_entry(self, depth):
        """Validate a grouping recursion level before it does any work."""
        self.grouping_calls += 1
        if depth > self.peak_grouping_depth:
            self.peak_grouping_depth = depth
        limit = self.limits.max_grouping_depth
        if limit is not None and depth > limit:
            self.fail(
                GROUPING_DEPTH,
                f"Maximum grouping depth exceeded ({limit}).",
            )
        call_limit = self.limits.max_grouping_calls
        if call_limit is not None and self.grouping_calls > call_limit:
            self.fail(
                GROUPING_CALLS,
                "Maximum number of grouping operations exceeded "
                f"({call_limit}).",
            )
        self.check_time()


_CURRENT_BUDGET: ContextVar[ParseBudget | None] = ContextVar(
    "sqlparse_parse_budget", default=None
)


def current_budget():
    return _CURRENT_BUDGET.get()


@contextmanager
def use_budget(budget):
    token = _CURRENT_BUDGET.set(budget)
    try:
        yield budget
    finally:
        _CURRENT_BUDGET.reset(token)


def build_budget(limits=None):
    """Resolve ``None`` fields against the grouping module's fallbacks."""
    if limits is None:
        limits = ParseLimits()
    # Imported lazily to avoid importing the engine while this module is
    # imported during package initialisation.
    from sqlparse.engine import grouping

    resolved = dataclasses.replace(
        limits,
        max_tokens=(
            grouping.MAX_GROUPING_TOKENS
            if limits.max_tokens is None
            else limits.max_tokens
        ),
        max_grouping_depth=(
            grouping.MAX_GROUPING_DEPTH
            if limits.max_grouping_depth is None
            else limits.max_grouping_depth
        ),
    )
    return ParseBudget(resolved)
