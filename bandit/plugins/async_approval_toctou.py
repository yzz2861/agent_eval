#
# SPDX-License-Identifier: Apache-2.0
r"""
=====================================================
B705: Test for stale approval decisions across awaits
=====================================================

Async business code frequently checks a short-term approval (a shared,
externally managed decision) and then, after one or more ``await``
points, publishes based on the result of that check.  While the
coroutine is suspended at an ``await``, another task may update or
revoke the shared approval state, so the decision made before the
suspension may no longer be valid when the coroutine resumes.  This is
a time-of-check to time-of-use (TOCTOU) pattern.

The synthetic approval runtime provides three kinds of APIs:

- **check APIs** (e.g. ``check_approval``) read the shared approval
  state.
- **freeze APIs** (e.g. ``freeze_approval``) pin a decision into a
  local snapshot that is immune to later updates of the shared state.
- **publish APIs** (e.g. ``publish``) perform the real side effect.

This plugin reports publish calls that depend on an approval checked
*before* an ``await`` without being frozen, and points back to the
await where the check result may have been invalidated.  Decisions
that were frozen locally before the suspension are not reported.  When
the scheduling cannot be analyzed statically (for example an ``await``
inside a loop, or functions exceeding the statement budget), a low
severity boundary note is reported instead of a definitive finding.

**Config Options:**

.. code-block:: yaml

    async_approval_toctou:
      check_apis: ["check_approval"]
      freeze_apis: ["freeze_approval"]
      publish_apis: ["publish"]
      max_statements: 200

:Example:

.. code-block:: none

    >> Issue: [B705:async_approval_toctou] Publish depends on approval
       'approved' checked at line 8; the check result may have been
       invalidated by a coroutine switch at line 9 (await) before this
       publish.
       Severity: Medium   Confidence: High
       CWE: CWE-367 (https://cwe.mitre.org/data/definitions/367.html)
       Location: examples/async_approval_unfrozen.py:11:8

.. seealso::

 - https://cwe.mitre.org/data/definitions/367.html

.. versionadded:: 1.9.0

"""
import ast

import bandit
from bandit.core import issue
from bandit.core import test_properties as test


def gen_config(name):
    if name == "async_approval_toctou":
        return {
            "check_apis": ["check_approval"],
            "freeze_apis": ["freeze_approval"],
            "publish_apis": ["publish"],
            "max_statements": 200,
        }


class _BudgetExceeded(Exception):
    """Raised when the per-function statement budget is exhausted."""


class _Token:
    """Tracks one approval decision stored in a local variable."""

    def __init__(self, name, lineno):
        self.name = name
        self.check_lineno = lineno
        self.frozen = False
        self.freeze_lineno = None
        self.stale_lineno = None
        self.stale_definite = False


def _terminal(name):
    return name.rsplit(".", 1)[-1] if name else ""


def _call_name(call):
    """Dotted name of a call target, without import alias resolution."""
    parts = []
    func = call.func
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
    return ".".join(reversed(parts))


def _enclosing_async_func(node):
    current = node
    while current is not None:
        if isinstance(current, ast.AsyncFunctionDef):
            return current
        if isinstance(current, (ast.FunctionDef, ast.Lambda, ast.ClassDef)):
            return None
        current = getattr(current, "_bandit_parent", None)
    return None


class _Analyzer:
    """Path-sensitive forward walk from function entry to the publish.

    Only the path leading to the publish call is followed precisely;
    sibling branches contribute "maybe" events.  Awaits invalidate
    (make stale) every unfrozen approval token seen so far; frozen
    tokens are local snapshots and stay valid.
    """

    def __init__(self, publish_node, config):
        self.publish_node = publish_node
        self.check_apis = set(config["check_apis"])
        self.freeze_apis = set(config["freeze_apis"])
        self.tokens = {}
        self.guards = []
        self.boundaries = []
        self.budget = config["max_statements"]

    def run(self, func_node):
        try:
            self._walk_path(func_node.body, definite=True)
        except _BudgetExceeded:
            self.boundaries.append(
                (func_node.lineno, "statement budget exceeded")
            )

    # -- path walking ------------------------------------------------

    def _spend(self):
        self.budget -= 1
        if self.budget <= 0:
            raise _BudgetExceeded

    def _contains_publish(self, node):
        for child in ast.walk(node):
            if child is self.publish_node:
                return True
        return False

    def _contains_publish_list(self, stmts):
        return any(self._contains_publish(stmt) for stmt in stmts)

    def _walk_path(self, stmts, definite):
        """Walk statements on the path leading to the publish call."""
        for stmt in stmts:
            self._spend()
            if self._contains_publish(stmt):
                self._descend(stmt, definite)
                return
            self._apply_stmt(stmt, definite)

    def _walk_maybe(self, stmts):
        """Walk statements that may or may not execute."""
        for stmt in stmts:
            self._spend()
            self._apply_stmt(stmt, definite=False)

    def _descend(self, stmt, definite):
        """Descend into the container statement holding the publish."""
        if isinstance(stmt, ast.If):
            self._apply_test(stmt.test, record_guards=True)
            if self._contains_publish_list(stmt.body):
                self._walk_maybe(stmt.orelse)
                self._walk_path(stmt.body, definite)
            else:
                self._walk_maybe(stmt.body)
                self._walk_path(stmt.orelse, definite)
        elif isinstance(stmt, ast.Try):
            if self._contains_publish_list(stmt.body):
                self._walk_path(stmt.body, definite)
            elif any(
                self._contains_publish_list(h.body) for h in stmt.handlers
            ):
                # exceptional path: try body may have partially executed
                self._walk_maybe(stmt.body)
                for handler in stmt.handlers:
                    if self._contains_publish_list(handler.body):
                        self._walk_path(handler.body, definite)
            elif self._contains_publish_list(stmt.finalbody):
                # finally always runs after the try body
                self._walk_path(stmt.body, definite)
                for handler in stmt.handlers:
                    self._walk_maybe(handler.body)
                self._walk_path(stmt.finalbody, definite)
            else:
                self._walk_path(stmt.orelse, definite)
        elif isinstance(stmt, (ast.For, ast.While, ast.AsyncFor)):
            self.boundaries.append(
                (
                    stmt.lineno,
                    "publish inside a loop; per-iteration coroutine "
                    "scheduling is not analyzable",
                )
            )
            if isinstance(stmt, ast.While):
                self._apply_test(stmt.test, record_guards=True)
            self._walk_path(stmt.body, definite)
        elif isinstance(stmt, ast.AsyncWith):
            self._mark_stale(stmt.lineno, definite=False)
            self._walk_path(stmt.body, definite)
        elif isinstance(stmt, ast.With):
            self._walk_path(stmt.body, definite)
        else:
            # simple statement directly containing the publish call
            self._apply_simple(stmt, definite)

    # -- statements not on the publish path --------------------------

    def _apply_stmt(self, stmt, definite):
        if isinstance(
            stmt,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
        ):
            return
        if isinstance(stmt, ast.If):
            self._apply_test(stmt.test, record_guards=False)
            self._walk_maybe(stmt.body)
            self._walk_maybe(stmt.orelse)
            return
        if isinstance(stmt, ast.Try):
            for sub in stmt.body:
                self._spend()
                self._apply_stmt(sub, definite)
            for handler in stmt.handlers:
                self._walk_maybe(handler.body)
            for sub in stmt.orelse:
                self._spend()
                self._apply_stmt(sub, definite)
            for sub in stmt.finalbody:
                self._spend()
                self._apply_stmt(sub, definite)
            return
        if isinstance(stmt, (ast.For, ast.While, ast.AsyncFor)):
            if any(isinstance(n, ast.Await) for n in ast.walk(stmt)):
                self.boundaries.append(
                    (
                        stmt.lineno,
                        "await inside a loop; iteration scheduling is "
                        "not analyzable",
                    )
                )
                self._mark_stale(stmt.lineno, definite=False)
            self._walk_maybe(stmt.body)
            return
        if isinstance(stmt, ast.AsyncWith):
            # __aenter__ may suspend the coroutine
            self._mark_stale(stmt.lineno, definite=False)
            for sub in stmt.body:
                self._spend()
                self._apply_stmt(sub, definite)
            return
        if isinstance(stmt, ast.With):
            for sub in stmt.body:
                self._spend()
                self._apply_stmt(sub, definite)
            return
        self._apply_simple(stmt, definite)

    def _apply_simple(self, stmt, definite):
        if isinstance(stmt, ast.Assign):
            self._apply_assignment(stmt.targets, stmt.value)
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            self._apply_assignment([stmt.target], stmt.value)
        for call in (c for c in ast.walk(stmt) if isinstance(c, ast.Call)):
            if self._match(call, self.freeze_apis) and call.args:
                arg = call.args[0]
                if (
                    definite
                    and isinstance(arg, ast.Name)
                    and arg.id in self.tokens
                ):
                    token = self.tokens[arg.id]
                    token.frozen = True
                    token.freeze_lineno = call.lineno
        for node in ast.walk(stmt):
            if isinstance(node, ast.Await):
                self._mark_stale(node.lineno, definite)

    def _apply_assignment(self, targets, value):
        names = [t.id for t in targets if isinstance(t, ast.Name)]
        if not names or not isinstance(value, ast.Call):
            return
        if self._match(value, self.check_apis):
            for name in names:
                self.tokens[name] = _Token(name, value.lineno)
        elif self._match(value, self.freeze_apis) and value.args:
            arg = value.args[0]
            if isinstance(arg, ast.Call) and self._match(
                arg, self.check_apis
            ):
                for name in names:
                    token = _Token(name, value.lineno)
                    token.frozen = True
                    token.freeze_lineno = value.lineno
                    self.tokens[name] = token
            elif isinstance(arg, ast.Name) and arg.id in self.tokens:
                source = self.tokens[arg.id]
                for name in names:
                    token = _Token(name, source.check_lineno)
                    token.frozen = True
                    token.freeze_lineno = value.lineno
                    self.tokens[name] = token

    def _apply_test(self, test_expr, record_guards):
        for node in ast.walk(test_expr):
            if isinstance(node, ast.Call):
                if record_guards and self._match(node, self.check_apis):
                    anon = "__approval_at_%d" % node.lineno
                    self.tokens[anon] = _Token(anon, node.lineno)
                    self.guards.append(anon)
                elif record_guards and self._match(node, self.freeze_apis):
                    anon = "__approval_at_%d" % node.lineno
                    token = _Token(anon, node.lineno)
                    token.frozen = True
                    token.freeze_lineno = node.lineno
                    self.tokens[anon] = token
                    self.guards.append(anon)
            elif (
                record_guards
                and isinstance(node, ast.Name)
                and node.id in self.tokens
            ):
                self.guards.append(node.id)

    # -- state transitions -------------------------------------------

    def _match(self, call, apis):
        name = _call_name(call)
        return name in apis or _terminal(name) in apis

    def _mark_stale(self, lineno, definite):
        for token in self.tokens.values():
            if token.frozen:
                continue
            if token.stale_lineno is None:
                token.stale_lineno = lineno
                token.stale_definite = definite
            elif definite:
                token.stale_definite = True

    # -- evaluation --------------------------------------------------

    def dependencies(self):
        deps = []
        for node in ast.walk(self.publish_node):
            if isinstance(node, ast.Name) and node.id in self.tokens:
                deps.append(node.id)
        deps.extend(g for g in self.guards if g in self.tokens)
        seen = set()
        deps = [d for d in deps if not (d in seen or seen.add(d))]
        if not deps:
            deps = list(self.tokens)
        return [self.tokens[name] for name in deps]

    def evaluate(self):
        deps = self.dependencies()
        stale = [t for t in deps if not t.frozen and t.stale_lineno]
        definite = any(t.stale_definite for t in stale)
        if stale and (definite or not self.boundaries):
            return ("stale", stale[0], definite)
        if self.boundaries:
            return ("boundary", stale[0] if stale else None, False)
        if stale:
            return ("stale", stale[0], False)
        return None


@test.takes_config
@test.checks("Call")
@test.test_id("B705")
def async_approval_toctou(context, config):
    """**B705: Test for stale approval decisions across awaits**"""
    qual = context.call_function_name_qual or ""
    publish_apis = set(config["publish_apis"])
    if qual not in publish_apis and _terminal(qual) not in publish_apis:
        return None

    func = _enclosing_async_func(context.node)
    if func is None:
        return None

    analyzer = _Analyzer(context.node, config)
    analyzer.run(func)
    outcome = analyzer.evaluate()
    if outcome is None:
        return None

    kind, token, definite = outcome
    if kind == "stale":
        if token.name.startswith("__approval_at_"):
            subject = "an inline approval check made at line %d" % (
                token.check_lineno
            )
        else:
            subject = "approval '%s' checked at line %d" % (
                token.name,
                token.check_lineno,
            )
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.HIGH if definite else bandit.MEDIUM,
            cwe=issue.Cwe.TOCTOU_RACE_CONDITION,
            text=(
                "Publish depends on %s; "
                "the check result may have been invalidated by a "
                "coroutine switch at line %d (await) before this "
                "publish. Freeze the approval decision before awaiting."
                % (subject, token.stale_lineno)
            ),
        )

    lineno, reason = analyzer.boundaries[0]
    text = (
        "Unable to fully analyze coroutine scheduling (%s, line %d); "
        "the validity of the approval at this publish cannot be "
        "determined." % (reason, lineno)
    )
    if token is not None:
        text += (
            " Approval '%s' checked at line %d may be stale."
            % (token.name, token.check_lineno)
        )
    return bandit.Issue(
        severity=bandit.LOW,
        confidence=bandit.MEDIUM,
        cwe=issue.Cwe.TOCTOU_RACE_CONDITION,
        text=text,
    )
