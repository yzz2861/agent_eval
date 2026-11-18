"""Run lint rules against bounded programs, keeping alerts and errors apart.

Two disjoint outcomes are tracked:

* Alert -- a rule positively reported a finding ("a warning").
* RuleError -- a rule raised an exception while visiting the tree.

"No warning" is always an empty alert list, never an exception, so counting
and diffing never conflate a silent rule with a crashing one.
"""

from __future__ import annotations

import ast
import inspect
import textwrap
import traceback
from dataclasses import dataclass, field
from typing import List, Sequence, Tuple


@dataclass(frozen=True)
class Alert:
    """A single positive finding produced by one rule."""

    rule_name: str
    code: str
    message: str
    lineno: int
    col_offset: int
    node_type: str
    snippet: str
    rule_location: str

    def identity(self):
        """Position-independent identity used for alert-set comparison."""
        return (
            self.rule_name, self.code, self.message,
            self.node_type, self.snippet,
        )

    def to_dict(self):
        return {
            "rule_name": self.rule_name, "code": self.code,
            "message": self.message, "lineno": self.lineno,
            "col_offset": self.col_offset, "node_type": self.node_type,
            "snippet": self.snippet, "rule_location": self.rule_location,
        }


@dataclass(frozen=True)
class RuleError:
    """A rule that crashed instead of returning findings."""

    rule_name: str
    exception_type: str
    message: str
    location: str
    rule_location: str

    def identity(self):
        return (self.rule_name, self.exception_type, self.message, self.location)

    def to_dict(self):
        return {
            "rule_name": self.rule_name,
            "exception_type": self.exception_type,
            "message": self.message,
            "location": self.location,
            "rule_location": self.rule_location,
        }


@dataclass
class RunResult:
    """Outcome of running one rule set on one program."""

    alerts: List[Alert] = field(default_factory=list)
    errors: List[RuleError] = field(default_factory=list)

    def alert_identities(self):
        return {alert.identity() for alert in self.alerts}

    def error_identities(self):
        return {error.identity() for error in self.errors}

    def to_dict(self):
        return {
            "alerts": [alert.to_dict() for alert in self.alerts],
            "errors": [error.to_dict() for error in self.errors],
            "alert_count": len(self.alerts),
            "error_count": len(self.errors),
        }


def rule_name(rule):
    return getattr(rule, "__name__", type(rule).__name__)


def rule_code(rule):
    code = getattr(rule, "_code", None)
    return str(code) if code is not None else ""


def describe_rule_location(rule):
    """Best-effort file:line where the rule class/function is defined."""
    try:
        filename = inspect.getsourcefile(rule) or inspect.getfile(rule)
        _, start_line = inspect.getsourcelines(rule)
        return "{}:{}".format(filename, start_line)
    except (OSError, TypeError):
        return getattr(rule, "__module__", "<unknown>")


def _result_records(linter):
    """Normalize how rules expose findings (dlint and bare visitors)."""
    getter = getattr(linter, "get_results", None)
    if callable(getter):
        return list(getter())
    if hasattr(linter, "results"):
        return list(getattr(linter, "results"))
    try:
        return list(linter)
    except TypeError:
        return []


def _node_at(tree, lineno, col_offset):
    best = tree
    for node in ast.walk(tree):
        node_lineno = getattr(node, "lineno", None)
        node_col = getattr(node, "col_offset", None)
        if node_lineno == lineno and node_col == col_offset:
            return node
        if node_lineno is not None and node_lineno <= lineno:
            best = node
    return best


def _error_location(exc):
    frames = traceback.extract_tb(exc.__traceback__)
    for frame in reversed(frames):
        if frame.filename and "rule_diff/runner.py" not in frame.filename:
            return "{}:{}".format(frame.filename, frame.lineno)
    if frames:
        frame = frames[-1]
        return "{}:{}".format(frame.filename, frame.lineno)
    return "<unknown>"


class RuleRunner(object):
    """Run a fixed collection of rule classes/objects on one AST tree."""

    def __init__(self, rules, name=""):
        self.rules = tuple(rules)
        self.name = name

    def run(self, tree, source_lines):
        result = RunResult()
        for rule in self.rules:
            linter = rule() if isinstance(rule, type) else rule
            label = rule_name(rule)
            location = describe_rule_location(rule)
            try:
                linter.visit(tree)
                records = _result_records(linter)
            except Exception as exc:  # rule crashes are data, not test failures
                result.errors.append(RuleError(
                    rule_name=label,
                    exception_type=type(exc).__name__,
                    message=str(exc),
                    location=_error_location(exc),
                    rule_location=location,
                ))
                continue
            for record in records:
                lineno = int(getattr(record, "lineno", 1) or 1)
                col_offset = int(getattr(record, "col_offset", 0) or 0)
                node = _node_at(tree, lineno, col_offset)
                snippet = textwrap.dedent(
                    source_lines[lineno - 1]
                    if 0 < lineno <= len(source_lines) else ""
                ).strip()
                result.alerts.append(Alert(
                    rule_name=label,
                    code=rule_code(rule),
                    message=getattr(record, "message", ""),
                    lineno=lineno,
                    col_offset=col_offset,
                    node_type=type(node).__name__,
                    snippet=snippet,
                    rule_location=location,
                ))
        return result

    def rule_locations(self):
        return {rule_name(rule): describe_rule_location(rule)
                for rule in self.rules}


def evaluate(source, rules):
    """Parse ``source`` and run one rule set; always returns a RunResult."""
    tree = ast.parse(source)
    source_lines = source.splitlines()
    return RuleRunner(rules).run(tree, source_lines)


def compare(source, old_rules, new_rules):
    """Run both rule sets on the same program.

    Returns ``(old_result, new_result)``.  The two results are evaluated on
    independently parsed trees so a rule that mutates visitor state cannot
    leak into the other revision.
    """
    old_result = evaluate(source, old_rules)
    new_result = evaluate(source, new_rules)
    return old_result, new_result
