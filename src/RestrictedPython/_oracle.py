"""Independent oracle for expected guard sites.

The expected guard list is derived from the untransformed source using
plain Python language semantics.  The policy transformer is never used as
the oracle, so a shared misclassification cannot hide a missing guard.
"""

from __future__ import annotations

import ast

from RestrictedPython.audit import APPLY_GUARD
from RestrictedPython.audit import ExpectedGuardSite
from RestrictedPython.audit import GETATTR_GUARD
from RestrictedPython.audit import GETITEM_GUARD
from RestrictedPython.audit import GETITER_GUARD
from RestrictedPython.audit import ITER_UNPACK_GUARD
from RestrictedPython.audit import UNPACK_GUARD
from RestrictedPython.audit import WRITE_GUARD


def _span(node: ast.AST) -> tuple[int, int, int, int]:
    return (
        node.lineno,
        node.col_offset,
        node.end_lineno,
        node.end_col_offset,
    )


class ExpectedGuardCollector(ast.NodeVisitor):
    """Collect guard sites required by the untransformed source tree."

    This visitor is deliberately independent of the restricting
    transformer: it encodes the language-level expectation of which
    operations need a guard instead of reusing the policy rules.
    """

    def __init__(self) -> None:
        self.sites: list[ExpectedGuardSite] = []

    def _add(self, guard: str, kind: str, node: ast.AST,
             span_node: ast.AST | None = None) -> None:
        self.sites.append(ExpectedGuardSite(
            guard, kind, node, _span(span_node or node)))

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self.generic_visit(node)
        if isinstance(node.ctx, ast.Load):
            self._add(GETATTR_GUARD, "attribute_load", node, node)
        else:
            self._add(WRITE_GUARD, "attribute_store", node, node.value)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        self.generic_visit(node)
        if isinstance(node.ctx, ast.Load):
            self._add(GETITEM_GUARD, "subscript_load", node, node)
        else:
            self._add(WRITE_GUARD, "subscript_store", node, node)

    def visit_For(self, node: ast.For) -> None:
        self.generic_visit(node)
        is_unpack = isinstance(node.target, ast.Tuple)
        self._add(
            ITER_UNPACK_GUARD if is_unpack else GETITER_GUARD,
            "for_unpack" if is_unpack else "for_iteration",
            node, node.iter)

    def visit_comprehension(self, node: ast.comprehension) -> None:
        self.generic_visit(node)
        is_unpack = isinstance(node.target, ast.Tuple)
        self._add(
            ITER_UNPACK_GUARD if is_unpack else GETITER_GUARD,
            "comprehension_unpack" if is_unpack
            else "comprehension_iteration",
            node, node.iter)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.generic_visit(node)
        for target in node.targets:
            if isinstance(target, ast.Tuple):
                self._add(UNPACK_GUARD, "assign_unpack", node, node)

    def visit_With(self, node: ast.With) -> None:
        self.generic_visit(node)
        for item in node.items:
            if isinstance(item.optional_vars, ast.Tuple):
                self._add(UNPACK_GUARD, "with_unpack", node, node)

    def visit_Call(self, node: ast.Call) -> None:
        self.generic_visit(node)
        needs_apply = any(
            isinstance(argument, ast.Starred) for argument in node.args)
        needs_apply = needs_apply or any(
            keyword.arg is None for keyword in node.keywords)
        if needs_apply:
            self._add(APPLY_GUARD, "call_spread", node, node)


def collect_expected_sites(tree: ast.AST) -> list[ExpectedGuardSite]:
    """Return the guard sites required by the untransformed source."""
    collector = ExpectedGuardCollector()
    collector.visit(tree)
    return collector.sites
