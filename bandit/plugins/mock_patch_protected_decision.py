#
# SPDX-License-Identifier: Apache-2.0
r"""
===========================================================
B616: Test for protected decisions reached under mock.patch
===========================================================

Test helpers are commonly moved into shared packages so that release and
test entry points can reuse them. When that happens, a
``unittest.mock.patch`` scope that was meant for tests may also surround a
release (production) entry point, silently replacing a protected decision
function -- for example an authorization check -- with a test double.

This plugin is configured with the repository's release entry points and a
small set of protected decision functions::

    mock_patch_protected_decision:
      release_entry_points:
        - myapp.main.deploy
      protected_decision_functions:
        - shared_pkg.authz.check_permission

For every call site it uses the module AST to track intra-module calls and
explicit aliases (import aliases and simple name assignments), and it
records ``unittest.mock.patch`` decorators and ``with`` statements whose
target is a string literal. A finding is reported at the call site where a
configured release entry point (transitively) reaches a protected decision
function while a matching patch target is statically in effect. Call chains
rooted at other entry points (for example tests sharing the same helpers)
are not reported.

Patch targets that cannot be statically determined (a non-literal target)
produce an independent low-severity record flagged for manual review.

:Example:

.. code-block:: none

    >> Issue: [B616:mock_patch_protected_decision] Release entry
       'release_entry' reaches protected decision function
       'shared_pkg.authz.check_permission' while unittest.mock.patch target
       'shared_pkg.authz.check_permission' (line 14) is active; the
       decision may be replaced by a test double.
       Severity: Medium   Confidence: High
       CWE: CWE-284 (https://cwe.mitre.org/data/definitions/284.html)
       Location: examples/mock_patch_release_entry.py:15:15

.. seealso::

 - https://docs.python.org/3/library/unittest.mock.html
 - https://cwe.mitre.org/data/definitions/284.html

.. versionadded:: 1.9.0

"""
import ast

import bandit
from bandit.core import issue
from bandit.core import test_properties as test

_MOCK_PATCH = "unittest.mock.patch"


def gen_config(name):
    if name == "mock_patch_protected_decision":
        return {
            "release_entry_points": [],
            "protected_decision_functions": [],
        }


def _dotted_name(expr):
    """Return the dotted name for a Name/Attribute chain, else None."""
    parts = []
    while isinstance(expr, ast.Attribute):
        parts.append(expr.attr)
        expr = expr.value
    if isinstance(expr, ast.Name):
        parts.append(expr.id)
    else:
        return None
    return ".".join(reversed(parts))


def _name_matches(qualname, configured):
    return qualname == configured or qualname.endswith("." + configured)


def _target_matches_protected(target, protected):
    if _name_matches(target, protected) or _name_matches(protected, target):
        return True
    # patch targets name the lookup location, which may live in a
    # different module than the protected function definition
    return target.split(".")[-1] == protected.split(".")[-1]


class _ModuleIndex:
    """Static per-module model of functions, aliases, and call edges."""

    def __init__(self, module_node):
        self.aliases = {}
        self.functions = {}
        self.calls = {}
        self._visit_statements(module_node.body, "")
        self._resolve_aliases()

    def _visit_statements(self, stmts, scope):
        for stmt in stmts:
            self._visit_statement(stmt, scope)

    def _visit_statement(self, stmt, scope):
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qualname = scope + stmt.name
            self.functions[qualname] = stmt
            self.calls[qualname] = self._direct_calls(stmt)
            self._visit_statements(stmt.body, qualname + ".")
            return
        if isinstance(stmt, ast.ClassDef):
            self._visit_statements(stmt.body, scope + stmt.name + ".")
            return
        if isinstance(stmt, ast.Import):
            for name in stmt.names:
                if name.asname:
                    self.aliases[name.asname] = name.name
        elif isinstance(stmt, ast.ImportFrom):
            if stmt.module:
                for name in stmt.names:
                    alias = name.asname or name.name
                    self.aliases[alias] = stmt.module + "." + name.name
        elif isinstance(stmt, ast.Assign):
            # explicit alias: single name bound to another dotted name
            if len(stmt.targets) == 1 and isinstance(
                stmt.targets[0], ast.Name
            ):
                value = _dotted_name(stmt.value)
                if value:
                    self.aliases[stmt.targets[0].id] = value
        for child in ast.iter_child_nodes(stmt):
            if isinstance(child, ast.stmt):
                self._visit_statement(child, scope)

    def _direct_calls(self, funcdef):
        found = set()

        def visit(node):
            for child in ast.iter_child_nodes(node):
                if isinstance(
                    child,
                    (
                        ast.FunctionDef,
                        ast.AsyncFunctionDef,
                        ast.ClassDef,
                        ast.Lambda,
                    ),
                ):
                    continue
                if isinstance(child, ast.Call):
                    name = _dotted_name(child.func)
                    if name:
                        found.add(name)
                visit(child)

        for stmt in funcdef.body:
            visit(stmt)
        return found

    def _resolve_aliases(self):
        for _ in range(len(self.aliases) + 1):
            changed = False
            for key, value in list(self.aliases.items()):
                resolved = self.resolve(value)
                if resolved != value:
                    self.aliases[key] = resolved
                    changed = True
            if not changed:
                break

    def resolve(self, name):
        head, _, rest = name.partition(".")
        if head in self.aliases:
            return self.aliases[head] + ("." + rest if rest else "")
        return name

    def reaches_protected(self, func_qualname, protected):
        """Protected functions reachable from a module-local function."""
        reached = set()
        seen = set()
        stack = [func_qualname]
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            for callee in self.calls.get(current, ()):
                resolved = self.resolve(callee)
                for prot in protected:
                    if _name_matches(resolved, prot):
                        reached.add(prot)
                if resolved in self.functions:
                    stack.append(resolved)
                elif callee in self.functions:
                    stack.append(callee)
        return reached


def _get_index(module_node):
    index = getattr(module_node, "_b616_index", None)
    if index is None:
        index = _ModuleIndex(module_node)
        module_node._b616_index = index
    return index


def _module_root(node):
    while hasattr(node, "_bandit_parent"):
        node = node._bandit_parent
    return node


def _patch_call_target(call_node, index):
    """Return (target, is_static) if the call is unittest.mock.patch()."""
    name = _dotted_name(call_node.func)
    if name is None or index.resolve(name) != _MOCK_PATCH:
        return None
    if not call_node.args:
        return ("", False)
    first = call_node.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return (first.value, True)
    return ("", False)


def _active_patch_targets(node, index):
    """Statically known patch targets in effect at the given node."""
    targets = []
    current = node
    while hasattr(current, "_bandit_parent"):
        parent = current._bandit_parent
        if isinstance(parent, (ast.With, ast.AsyncWith)):
            for item in parent.items:
                expr = item.context_expr
                if isinstance(expr, ast.Call):
                    result = _patch_call_target(expr, index)
                    if result and result[1]:
                        targets.append((result[0], expr.lineno))
        elif isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in parent.decorator_list:
                if isinstance(decorator, ast.Call):
                    result = _patch_call_target(decorator, index)
                    if result and result[1]:
                        targets.append((result[0], decorator.lineno))
        current = parent
    return targets


def _enclosing_entry(node, entries):
    """Configured release entry enclosing the node, if any."""
    scopes = []
    current = node
    while hasattr(current, "_bandit_parent"):
        parent = current._bandit_parent
        if isinstance(
            parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            scopes.append(parent.name)
        current = parent
    if not scopes:
        return None
    qualname = ".".join(reversed(scopes))
    name = scopes[0]
    for entry in entries:
        if (
            qualname == entry
            or name == entry
            or qualname.endswith("." + entry)
            or entry.endswith("." + qualname)
        ):
            return entry
    return None


@test.takes_config
@test.checks("Call")
@test.test_id("B616")
def mock_patch_protected_decision(context, config):
    entries = config.get("release_entry_points") or []
    protected = config.get("protected_decision_functions") or []
    if not entries or not protected:
        return None

    node = context.node
    index = _get_index(_module_root(node))

    patch_target = _patch_call_target(node, index)
    if patch_target is not None:
        if not patch_target[1]:
            return bandit.Issue(
                severity=bandit.LOW,
                confidence=bandit.MEDIUM,
                cwe=issue.Cwe.IMPROPER_ACCESS_CONTROL,
                text="Manual review: unittest.mock.patch target cannot be "
                "statically determined; verify that no protected decision "
                "function is replaced on a release call chain.",
            )
        return None

    entry = _enclosing_entry(node, entries)
    if entry is None:
        return None

    targets = _active_patch_targets(node, index)
    if not targets:
        return None

    callee = _dotted_name(node.func)
    if callee is None:
        return None
    resolved = index.resolve(callee)

    reached = {prot for prot in protected if _name_matches(resolved, prot)}
    if resolved in index.functions:
        reached |= index.reaches_protected(resolved, protected)
    if not reached:
        return None

    for target, patch_lineno in targets:
        for prot in sorted(reached):
            if _target_matches_protected(target, prot):
                return bandit.Issue(
                    severity=bandit.MEDIUM,
                    confidence=bandit.HIGH,
                    cwe=issue.Cwe.IMPROPER_ACCESS_CONTROL,
                    text="Release entry '%s' reaches protected decision "
                    "function '%s' while unittest.mock.patch target '%s' "
                    "(line %d) is active; the decision may be replaced "
                    "by a test double."
                    % (entry, prot, target, patch_lineno),
                )
    return None
