"""Deterministic fixture rules used to validate the rule-diff backend.

These rules deliberately model a refactoring that opens a false negative and
one that introduces a false positive, plus a rule that crashes. They are
plain ast.NodeVisitor classes exposing the same get_results/results protocol
as dlint linters, so the backend exercises them without flake8.
"""

import ast


class _Finding(object):
    def __init__(self, lineno, col_offset, message):
        self.lineno = lineno
        self.col_offset = col_offset
        self.message = message


class _BaseRule(ast.NodeVisitor):
    _code = "TST001"
    message = "generic finding"

    def __init__(self):
        self.results = []

    def get_results(self):
        return self.results

    def _flag(self, node):
        self.results.append(_Finding(node.lineno, node.col_offset, self.message))


def _call_name(node):
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


class StrictEvalRule(_BaseRule):
    """Flags every call named eval (bare or attribute-qualified)."""
    _code = "TST100"
    message = "eval is dangerous"

    def visit_Call(self, node):
        if _call_name(node) == "eval":
            self._flag(node)
        self.generic_visit(node)


class AliasBlindEvalRule(_BaseRule):
    """Refactored rule that only sees attribute-qualified eval.

    A bare eval() (including one reached through an import alias) is no
    longer flagged: an injected false negative.
    """
    _code = "TST100"
    message = "eval is dangerous"

    def visit_Call(self, node):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "eval":
            self._flag(node)
        self.generic_visit(node)


class OverbroadEvalRule(_BaseRule):
    """Refactored rule that also flags harmless run() calls.

    An injected false positive: run() was not warned about before.
    """
    _code = "TST100"
    message = "eval is dangerous"

    def visit_Call(self, node):
        name = _call_name(node)
        if name in ("eval", "run"):
            self._flag(node)
        self.generic_visit(node)


class CrashingRule(_BaseRule):
    """A rule that raises while visiting a constant condition."""
    _code = "TST200"
    message = "should never be produced"

    def visit_If(self, node):
        if isinstance(node.test, ast.Constant) and node.test.value is True:
            raise RuntimeError("boom: cannot handle if True")
        self.generic_visit(node)


class StableRule(_BaseRule):
    """A well-behaved rule used alongside the crashing one."""
    _code = "TST201"
    message = "stable finding"

    def visit_Call(self, node):
        if _call_name(node) == "danger":
            self._flag(node)
        self.generic_visit(node)


class AssignmentRule(_BaseRule):
    """Flags a simple assignment to the name secret."""
    _code = "TST300"
    message = "hardcoded secret assignment"

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "secret":
                self._flag(node)
        self.generic_visit(node)
