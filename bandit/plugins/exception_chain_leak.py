#
# SPDX-License-Identifier: Apache-2.0
r"""
======================================================
B114: Test for sensitive data leaking via raise chains
======================================================

Client facing code often sanitizes exception messages before returning
them, but support/diagnostic interfaces may still walk the exception
chain (``__cause__`` and ``__context__``) to build their output. If an
exception raised by a sensitive local call (for example a password or
key retrieval helper) is preserved anywhere in that chain, the data it
carries can be exposed even though the outward message looks clean.

This plugin inspects ``raise`` statements and distinguishes four chain
behaviors:

- **Wrapped message**: ``raise CleanError("...") from exc`` keeps the
  original exception reachable via ``__cause__``.
- **Preserved exception object**: ``raise exc`` re-raises the original
  exception object unchanged.
- **Implicit context**: ``raise CleanError("...")`` inside an ``except``
  block still links the active exception via ``__context__``.
- **Explicitly suppressed chain**: ``raise CleanError("...") from None``
  drops the chain and is not reported.
- **Bare raise**: a plain ``raise`` re-raises the active exception.

An exception variable is considered tainted when the ``try`` body of the
handling ``except`` block contains a call to a configured sensitive
function. The analysis is limited to the current file: calls that are
not in the configured list are never positively inferred to be
sensitive, so unknown callees do not produce findings.

**Config Options:**

.. code-block:: yaml

    sensitive_exception_chain:
      sensitive_calls:
        - getpass.getpass
        - keyring.get_password
        - keyring.set_password

:Example:

.. code-block:: none

    >> Issue: [B114:sensitive_exception_chain] Exception chain may
       expose sensitive data: 'raise ... from exc' keeps the exception
       from keyring.get_password() at line 6 reachable via __cause__.
       Severity: Medium   Confidence: High
       CWE: CWE-209 (https://cwe.mitre.org/data/definitions/209.html)
       Location: examples/exception_chain_leak.py:8:8

.. seealso::

 - https://cwe.mitre.org/data/definitions/209.html
 - https://docs.python.org/3/reference/simple_stmts.html#raise

.. versionadded:: 1.9.0

"""
import ast

import bandit
from bandit.core import issue
from bandit.core import test_properties as test
from bandit.core import utils

_TRY_TYPES = (ast.Try,) + (
    (ast.TryStar,) if hasattr(ast, "TryStar") else ()
)

_SCOPE_TYPES = (
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.Lambda,
    ast.ClassDef,
)


def gen_config(name):
    if name == "sensitive_exception_chain":
        return {
            "sensitive_calls": [
                "getpass.getpass",
                "keyring.get_password",
                "keyring.set_password",
            ]
        }


def _walk_local(stmts):
    """Walk statements without descending into nested scopes."""
    stack = list(stmts)
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, _SCOPE_TYPES):
            continue
        stack.extend(ast.iter_child_nodes(node))


def _find_sensitive_call(stmts, sensitive_calls, import_aliases):
    """Return (qualname, node) of the first sensitive call, if any."""
    found = None
    for node in _walk_local(stmts):
        if isinstance(node, ast.Call):
            qualname = utils.get_call_name(node, import_aliases)
            if qualname in sensitive_calls:
                if found is None or node.lineno < found[1].lineno:
                    found = (qualname, node)
    return found


def _enclosing_scope(node):
    scope = getattr(node, "_bandit_parent", None)
    while scope is not None:
        if isinstance(
            scope, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            return scope
        scope = getattr(scope, "_bandit_parent", None)
    return None


def _enclosing_handler(node):
    """Innermost except handler active for a raise, if any."""
    parent = getattr(node, "_bandit_parent", None)
    while parent is not None:
        if isinstance(parent, ast.ExceptHandler):
            return parent
        if isinstance(parent, (ast.Module,) + _SCOPE_TYPES):
            return None
        parent = getattr(parent, "_bandit_parent", None)
    return None


def _tainted_names(scope, sensitive_calls, import_aliases):
    """Map of exception variable names to their sensitive source.

    A name is tainted when it is bound by an ``except ... as name``
    clause guarding a try body that contains a sensitive call, or when
    it is assigned directly from another tainted name.
    """
    tainted = {}
    body = (
        scope.body
        if hasattr(scope, "body")
        else list(ast.iter_child_nodes(scope))
    )
    for node in _walk_local(body):
        if isinstance(node, _TRY_TYPES):
            source = _find_sensitive_call(
                node.body, sensitive_calls, import_aliases
            )
            if source is not None:
                for handler in node.handlers:
                    if handler.name:
                        tainted[handler.name] = (
                            source[0],
                            source[1].lineno,
                        )
    changed = True
    while changed:
        changed = False
        for node in _walk_local(body):
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Name)
            ):
                src = node.value.id
                dst = node.targets[0].id
                if src in tainted and dst not in tainted:
                    tainted[dst] = tainted[src]
                    changed = True
    return tainted


def _handler_sensitive_source(handler, sensitive_calls, import_aliases):
    """Sensitive call guarded by the try of the given handler."""
    try_node = getattr(handler, "_bandit_parent", None)
    if isinstance(try_node, _TRY_TYPES):
        source = _find_sensitive_call(
            try_node.body, sensitive_calls, import_aliases
        )
        if source is not None:
            return (source[0], source[1].lineno)
    return None


def _source_text(source):
    return f"{source[0]}() at line {source[1]}"


@test.takes_config
@test.checks("Raise")
@test.test_id("B114")
def sensitive_exception_chain(context, config):
    node = context.node
    sensitive_calls = set(config["sensitive_calls"])
    import_aliases = context.import_aliases or {}
    handler = _enclosing_handler(node)

    if node.exc is None:
        # Bare raise re-raises the active exception unchanged.
        if handler is None:
            return
        source = _handler_sensitive_source(
            handler, sensitive_calls, import_aliases
        )
        if source is None:
            return
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.HIGH,
            cwe=issue.Cwe.ERROR_MESSAGE_SENSITIVE_INFO,
            text=(
                "Bare raise re-raises the active exception which may "
                "contain sensitive data from "
                f"{_source_text(source)}."
            ),
        )

    if (
        isinstance(node.cause, ast.Constant)
        and node.cause.value is None
    ):
        # "raise ... from None" explicitly suppresses the chain.
        return

    scope = _enclosing_scope(node)
    if scope is None:
        return
    tainted = _tainted_names(scope, sensitive_calls, import_aliases)

    # Preserved exception object: "raise exc" re-raises the object.
    if isinstance(node.exc, ast.Name) and node.exc.id in tainted:
        source = tainted[node.exc.id]
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.HIGH,
            cwe=issue.Cwe.ERROR_MESSAGE_SENSITIVE_INFO,
            text=(
                f"Re-raised exception object '{node.exc.id}' may "
                "contain sensitive data from "
                f"{_source_text(source)}."
            ),
        )

    if node.cause is not None:
        # Explicit chain: "raise Clean(...) from exc" keeps __cause__.
        if isinstance(node.cause, ast.Name) and node.cause.id in tainted:
            source = tainted[node.cause.id]
            return bandit.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.HIGH,
                cwe=issue.Cwe.ERROR_MESSAGE_SENSITIVE_INFO,
                text=(
                    "Exception chain may expose sensitive data: "
                    f"'raise ... from {node.cause.id}' keeps the "
                    "exception from "
                    f"{_source_text(source)} reachable via __cause__ "
                    "even though the outward message is sanitized."
                ),
            )
        # Unknown cause: no positive inference.
        return

    # Implicit context: a new exception raised inside a handler still
    # links the active exception via __context__.
    if handler is not None:
        source = _handler_sensitive_source(
            handler, sensitive_calls, import_aliases
        )
        if source is not None:
            return bandit.Issue(
                severity=bandit.MEDIUM,
                confidence=bandit.MEDIUM,
                cwe=issue.Cwe.ERROR_MESSAGE_SENSITIVE_INFO,
                text=(
                    "Exception raised in this handler is implicitly "
                    "chained via __context__ to the exception from "
                    f"{_source_text(source)}; use 'raise ... from "
                    "None' to suppress the chain."
                ),
            )
