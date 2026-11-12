# Copyright 2021 The casbin Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import ast
import multiprocessing
import re
import signal
import threading
import time
import warnings
from contextvars import ContextVar
from dataclasses import dataclass
from functools import lru_cache

from simpleeval import EvalWithCompoundTypes, NameNotDefined


class MatcherError(Exception):
    """Base class for every failure that makes a matcher evaluation unsafe.

    A MatcherError always means the request must be denied. It carries a stable
    ``reason`` string so callers can tell budget-driven denials apart from ordinary
    policy denials without parsing messages.
    """

    def __init__(self, reason, message=None):
        self.reason = reason
        super().__init__(message if message is not None else reason)


class MatcherBudgetExceeded(MatcherError):
    """Raised when a configured matcher budget (time, evaluations, calls, regex) is hit."""


class MatcherTimeout(MatcherBudgetExceeded):
    """Raised when an enforce call or a regex runs longer than its wall-clock budget."""


class MatcherFunctionError(MatcherError):
    """Raised for unknown, recursive, failing or non-boolean matcher functions."""


# Reason codes are part of the public contract: tests and callers match on them.
REASON_ENFORCE_TIMEOUT = "enforce_wall_time_exceeded"
REASON_POLICY_LIMIT = "policy_evaluation_limit_exceeded"
REASON_FUNCTION_LIMIT = "function_call_limit_exceeded"
REASON_REGEX_LENGTH = "regex_pattern_length_exceeded"
REASON_REGEX_TIMEOUT = "regex_execution_time_exceeded"
REASON_UNKNOWN_FUNCTION = "unknown_function"
REASON_RECURSIVE_ENFORCER = "recursive_enforcer_call"
REASON_FUNCTION_EXCEPTION = "function_exception"
REASON_NON_BOOLEAN = "non_boolean_function_result"


@dataclass(frozen=True)
class MatcherBudget:
    """Configurable execution budget for a single enforce() call.

    Every limit is opt-in: a ``None`` limit (the default) keeps the historical
    unbounded behaviour. The budget only starts enforcing once at least one limit
    is configured.

    - ``wall_time``: wall-clock seconds the whole enforce call may spend.
    - ``max_policy_evaluations``: number of policy rules whose matcher is evaluated.
    - ``max_function_calls``: number of calls to tenant-registered custom functions.
    - ``max_regex_pattern_length``: maximum length of a regexMatch pattern.
    - ``regex_timeout``: wall-clock seconds a single regexMatch call may spend.
    """

    wall_time: float = None
    max_policy_evaluations: int = None
    max_function_calls: int = None
    max_regex_pattern_length: int = None
    regex_timeout: float = None

    def enabled(self):
        return any(
            limit is not None
            for limit in (
                self.wall_time,
                self.max_policy_evaluations,
                self.max_function_calls,
                self.max_regex_pattern_length,
                self.regex_timeout,
            )
        )

    def __post_init__(self):
        for name in ("wall_time", "regex_timeout"):
            value = getattr(self, name)
            if value is not None and value <= 0:
                raise ValueError(f"{name} must be a positive number of seconds")
        for name in ("max_policy_evaluations", "max_function_calls", "max_regex_pattern_length"):
            value = getattr(self, name)
            if value is not None and value <= 0:
                raise ValueError(f"{name} must be a positive integer")


class BudgetState:
    """Mutable per-enforce-call counters and limit checks, bound to one thread/task.

    ContextVars give each thread (and each asyncio task) its own counters, so
    concurrent enforce calls never share or corrupt each other's budget.
    """

    def __init__(self, budget):
        self.budget = budget
        self.policy_evaluations = 0
        self.function_calls = 0
        self.started_at = time.monotonic()

    def check_wall_time(self):
        if self.budget.wall_time is not None:
            if time.monotonic() - self.started_at >= self.budget.wall_time:
                raise MatcherTimeout(
                    REASON_ENFORCE_TIMEOUT,
                    f"enforce exceeded its wall-time budget of {self.budget.wall_time}s",
                )

    def count_policy_evaluation(self):
        self.policy_evaluations += 1
        if (
            self.budget.max_policy_evaluations is not None
            and self.policy_evaluations > self.budget.max_policy_evaluations
        ):
            raise MatcherBudgetExceeded(
                REASON_POLICY_LIMIT,
                f"policy evaluation limit of {self.budget.max_policy_evaluations} exceeded",
            )
        self.check_wall_time()

    def count_function_call(self):
        self.function_calls += 1
        if (
            self.budget.max_function_calls is not None
            and self.function_calls > self.budget.max_function_calls
        ):
            raise MatcherBudgetExceeded(
                REASON_FUNCTION_LIMIT,
                f"custom function call limit of {self.budget.max_function_calls} exceeded",
            )
        self.check_wall_time()

    def check_regex_pattern(self, pattern):
        limit = self.budget.max_regex_pattern_length
        if limit is not None and len(pattern) > limit:
            raise MatcherBudgetExceeded(
                REASON_REGEX_LENGTH,
                f"regex pattern length {len(pattern)} exceeds limit of {limit}",
            )


# The active budget for the current enforce call. None means budgets are disabled.
current_budget = ContextVar("casbin_matcher_budget", default=None)
# Depth of in-flight enforce calls on this context; used to detect recursive
# matcher functions that call back into the enforcer.
enforce_depth = ContextVar("casbin_enforce_depth", default=0)


def bounded_re_search(pattern, text):
    """re.search() guarded by the active regex pattern-length and time budgets.

    With no active regex budget this is plain re.search(), so built-in matching is
    byte-for-byte unchanged. Time-limited searches are interrupted with SIGALRM
    on the main thread or isolated in a killable child process on worker threads,
    because CPython's C regex engine does not release the GIL while backtracking.
    """
    state = current_budget.get()
    if state is None:
        return re.search(pattern, text)

    state.check_regex_pattern(pattern)
    timeout = state.budget.regex_timeout
    if timeout is None:
        return re.search(pattern, text)

    if threading.current_thread() is threading.main_thread():
        return _re_search_with_alarm(pattern, text, timeout)
    return _re_search_in_process(pattern, text, timeout)


def _re_search_with_alarm(pattern, text, timeout):
    """time-limited re.search for the main thread.

    SIGALRM is delivered to the main thread even while CPython's C regex engine
    backtracks, so catastrophic patterns are interrupted on schedule.
    """

    def on_alarm(signum, frame):
        raise MatcherTimeout(
            REASON_REGEX_TIMEOUT,
            f"regex execution exceeded its time budget of {timeout}s",
        )

    previous_handler = signal.signal(signal.SIGALRM, on_alarm)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, timeout)[0]
    try:
        return re.search(pattern, text)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer:
            signal.setitimer(signal.ITIMER_REAL, previous_timer, 0)


def _re_search_worker(conn, pattern, text):
    try:
        match = re.search(pattern, text)
        conn.send((True, bool(match)))
    except Exception as exc:
        conn.send((False, f"{type(exc).__name__}: {exc}"))
    finally:
        conn.close()


def _re_search_in_process(pattern, text, timeout):
    """time-limited re.search for worker threads, where signals cannot be used.

    A short-lived forked child runs the (potentially catastrophic) search. On
    timeout it is terminated outright, so runaway C backtracking never reaches
    the enforcer's worker thread.
    """
    # fork is preferred for speed on POSIX; spawn keeps the guard available on
    # Windows (where fork does not exist) at the cost of importing the worker module.
    start_method = "fork" if "fork" in multiprocessing.get_all_start_methods() else None
    ctx = multiprocessing.get_context(start_method)
    parent_conn, child_conn = ctx.Pipe(duplex=False)
    with warnings.catch_warnings():
        # fork in a threaded process warns about potential child deadlocks; the
        # child only ever runs re.search and writes one pipe message, so it
        # takes no interpreter locks the parent might hold.
        warnings.simplefilter("ignore", DeprecationWarning)
        process = ctx.Process(target=_re_search_worker, args=(child_conn, pattern, text), daemon=True)
        process.start()
    child_conn.close()
    if parent_conn.poll(timeout):
        succeeded, payload = parent_conn.recv()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            process.join()
        parent_conn.close()
        if not succeeded:
            raise re.error(payload)
        # Only truthiness matters to regexMatch; avoid shipping a match object.
        return object() if payload else None

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        process.terminate()
        process.join()
    parent_conn.close()
    raise MatcherTimeout(
        REASON_REGEX_TIMEOUT,
        f"regex execution exceeded its time budget of {timeout}s",
    )


@lru_cache(maxsize=8192)
def parse_expression(expr):
    return ast.parse(expr.strip()).body[0].value


class SimpleEval(EvalWithCompoundTypes):
    """Rewrite SimpleEval.
    >>> s = SimpleEval("20 + 30 - ( 10 * 5)")
    >>> s.eval()
    0
    """

    ast_parsed_value = None

    def __init__(self, expr, functions=None, custom_functions=None):
        """Create the evaluator instance.  Set up valid operators (+,-, etc)
        functions (add, random, get_val, whatever) and names."""
        super(SimpleEval, self).__init__(functions=self._wrap_functions(functions, custom_functions))
        self.set_expr(expr)

    @staticmethod
    def _wrap_functions(functions, custom_functions):
        """Wraps tenant-registered functions so call counting, recursion and result
        checks are enforced while the built-in functions keep their exact behaviour."""
        if not functions:
            return functions

        custom_functions = custom_functions or frozenset()
        wrapped = dict(functions)
        for name in custom_functions:
            func = wrapped.get(name)
            if func is None:
                continue

            def make_wrapper(func_name, func):
                def wrapper(*args, **kwargs):
                    state = current_budget.get()
                    if state is None:
                        return func(*args, **kwargs)

                    state.count_function_call()
                    if enforce_depth.get() > 1:
                        raise MatcherFunctionError(
                            REASON_RECURSIVE_ENFORCER,
                            f"custom function {func_name!r} recursively invoked the enforcer",
                        )
                    try:
                        value = func(*args, **kwargs)
                    except MatcherError:
                        raise
                    except Exception as exc:
                        raise MatcherFunctionError(
                            REASON_FUNCTION_EXCEPTION,
                            f"custom function {func_name!r} raised {type(exc).__name__}: {exc}",
                        ) from exc
                    if not isinstance(value, bool):
                        raise MatcherFunctionError(
                            REASON_NON_BOOLEAN,
                            f"custom function {func_name!r} returned {type(value).__name__}, expected bool",
                        )
                    # A single slow custom call must also respect the enforce
                    # wall-clock budget, not just the per-call regex budget.
                    state.check_wall_time()
                    return value

                return wrapper

            wrapped[name] = make_wrapper(name, func)
        return wrapped

    def _eval_call(self, node):
        state = current_budget.get()
        if state is not None and not isinstance(node.func, ast.Attribute) and node.func.id not in self.functions:
            raise MatcherFunctionError(
                REASON_UNKNOWN_FUNCTION,
                f"function {node.func.id!r} is not registered on the function whitelist",
            )
        if state is not None:
            state.check_wall_time()
        return super(SimpleEval, self)._eval_call(node)

    def set_expr(self, expr):
        """replace the expression to evaluate, keeping the functions."""
        if expr != "":
            self.expr = expr
            self.ast_parsed_value = parse_expression(expr)

    def eval(self, names=None):
        """evaluate an expression, using the operators, functions and
        names previously set up."""

        if names:
            self.names = names

        return self._eval(self.ast_parsed_value)

    def _eval_name(self, node):
        try:
            return super(SimpleEval, self)._eval_name(node)
        except NameNotDefined:
            if node.id == "true":
                return True
            if node.id == "false":
                return False
            raise
