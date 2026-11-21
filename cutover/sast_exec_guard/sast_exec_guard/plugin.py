#
# SPDX-License-Identifier: Apache-2.0
r"""
================================================
X901/X902: Replacement checks for retired B102
================================================

This plugin is the business-approved replacement for the Bandit built-in
rule B102 (``exec_used``). It is deliberately *narrower* than B102:

* X901 only flags a bare, unqualified exec(...) call that sits in
  a shallow (top-level function) scope. Nested-function exec(...)
  calls, qualified calls such as builtins.exec(...) and import
  aliases such as from builtins import exec as run are not recognized.
* X901 refuses to evaluate files living under an unscanned legacy root, so
  code in legacy-only directories is never inspected by the replacement.
* X902 is a brand-new check for bare ``eval(...)`` calls. It produces
  additional findings, but those new findings do not cover any of the
  exec-detection responsibility owned by B102.

The narrower scope is the coverage gap the cutover validation must make
explicit before the built-in rule can be retired.
"""
import os

import bandit
from bandit.core import issue
from bandit.core import test_properties as test

# Directories outside the replacement plugin scope. Matched as normalized
# path fragments so the rule is independent of the checkout location.
UNSCANNED_PATH_FRAGMENTS = (
    os.path.join("cutover", "corpus", "legacy"),
)


def _in_unscanned_legacy_root(context):
    """Return True when the file is outside the replacement scope."""
    filename = context.filename or ""
    normalized = os.path.normpath(filename).replace(os.sep, "/")
    for fragment in UNSCANNED_PATH_FRAGMENTS:
        normalized_fragment = os.path.normpath(fragment).replace(
            os.sep, "/"
        )
        if normalized_fragment in normalized:
            return True
    return False


def _call_scope_depth(context):
    """Count enclosing function scopes of the current call node."""
    node = getattr(context, "node", None)
    depth = 0
    while node is not None:
        node = getattr(node, "_bandit_parent", None)
        if node is not None and node.__class__.__name__ in (
            "FunctionDef",
            "AsyncFunctionDef",
        ):
            depth += 1
    return depth


def _exec_issue():
    return bandit.Issue(
        severity=bandit.MEDIUM,
        confidence=bandit.HIGH,
        cwe=issue.Cwe.OS_COMMAND_INJECTION,
        text="Use of exec detected (replacement plugin X901).",
    )


def _eval_issue():
    return bandit.Issue(
        severity=bandit.MEDIUM,
        confidence=bandit.HIGH,
        cwe=issue.Cwe.OS_COMMAND_INJECTION,
        text="Use of eval detected (replacement plugin X902).",
    )


@test.test_id("X901")
@test.checks("Call")
def guard_exec_used(context):
    # Directory-level responsibility boundary: legacy roots are not scanned
    # by the replacement plugin at all. The cutover harness classifies the
    # resulting miss as a directory-coverage gap from the file path.
    if _in_unscanned_legacy_root(context):
        return None
    # Syntax-level boundary: only a bare, unqualified exec() in a shallow
    # scope matches. Nested-function exec() calls (depth >= 2) and qualified
    # or aliased names (qualname "builtins.exec") slip through.
    if (
        context.call_function_name_qual == "exec"
        and _call_scope_depth(context) <= 1
    ):
        return _exec_issue()
    return None


@test.test_id("X902")
@test.checks("Call")
def guard_eval_used(context):
    if _in_unscanned_legacy_root(context):
        return None
    if context.call_function_name_qual == "eval":
        return _eval_issue()
    return None
