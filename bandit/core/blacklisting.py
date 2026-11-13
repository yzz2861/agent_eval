#
# Copyright 2016 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0
import ast
import fnmatch

from bandit.core import issue


def report_issue(check, name):
    return issue.Issue(
        severity=check.get("level", "MEDIUM"),
        confidence="HIGH",
        cwe=check.get("cwe", issue.Cwe.NOTSET),
        text=check["message"].replace("{name}", name),
        ident=name,
        test_id=check.get("id", "LEGACY"),
    )


def _is_wildcard(qualname):
    """Return True if *qualname* contains glob wildcard characters."""
    return any(char in qualname for char in "*?[]")


def _matches_qualname(name, qualname, prefix_match=False):
    """Match *name* against a blacklist qualname.

    Wildcard qualnames are matched with :mod:`fnmatch`; plain qualnames use
    the historical equality semantics for calls and prefix semantics for
    imports (selected with *prefix_match*).  The behaviour does not depend
    on the order in which plugins happened to load.
    """
    if name is None:
        return False
    if _is_wildcard(qualname):
        return fnmatch.fnmatchcase(name, qualname)
    if prefix_match:
        return name.startswith(qualname)
    return name == qualname


def _sort_checks(checks):
    """Return *checks* in a stable, documented evaluation order.

    Exact qualnames are evaluated before wildcard ones; within each group the
    blacklist id and the qualname provide a deterministic tie breaker.
    """

    def sort_key(check):
        wildcards = sorted(
            qn for qn in check.get("qualnames", []) if _is_wildcard(qn)
        )
        exact = sorted(
            qn for qn in check.get("qualnames", []) if not _is_wildcard(qn)
        )
        # Exact matches (0) must win over wildcard matches (1).
        return (
            1 if wildcards and not exact else 0,
            check.get("id", ""),
            exact,
            wildcards,
        )

    return sorted(checks, key=sort_key)


def _find_check(checks, match_name, prefix_match=False):
    """Deterministically pick the blacklist check matching *match_name*."""
    fallback = None
    for check in _sort_checks(checks):
        for qualname in check.get("qualnames", []):
            if not _matches_qualname(
                match_name, qualname, prefix_match
            ):
                continue
            if not _is_wildcard(qualname):
                # Exact match has the highest documented priority.
                return check
            if fallback is None:
                fallback = check
    return fallback


def blacklist(context, config):
    """Generic blacklist test, B001.

    This generic blacklist test will be called for any encountered node with
    defined blacklist data available. This data is loaded via plugins using
    the 'bandit.blacklists' entry point. Please see the documentation for more
    details. Each blacklist datum has a unique bandit ID that may be used for
    filtering purposes, or alternatively all blacklisting can be filtered using
    the id of this built in test, 'B001'.
    """
    blacklists = config
    node_type = context.node.__class__.__name__

    if node_type == "Call":
        func = context.node.func
        if isinstance(func, ast.Name) and func.id == "__import__":
            if len(context.node.args):
                if isinstance(
                    context.node.args[0], ast.Constant
                ) and isinstance(context.node.args[0].value, str):
                    name = context.node.args[0].value
                else:
                    # TODO(??): import through a variable, need symbol tab
                    name = "UNKNOWN"
            else:
                name = ""  # handle '__import__()'
        else:
            name = context.call_function_name_qual
            # In the case the Call is an importlib.import, treat the first
            # argument name as an actual import module name.
            # Will produce None if argument is not a literal or identifier
            if name in ["importlib.import_module", "importlib.__import__"]:
                if context.call_args_count > 0:
                    name = context.call_args[0]
                else:
                    name = context.call_keywords["name"]
        check = _find_check(blacklists[node_type], name)
        if check is not None:
            return report_issue(check, name)

    if node_type.startswith("Import"):
        prefix = ""
        if node_type == "ImportFrom":
            if context.node.module is not None:
                prefix = context.node.module + "."

        for imported in context.node.names:
            full_name = prefix + imported.name
            check = _find_check(
                blacklists[node_type], full_name, prefix_match=True
            )
            if check is not None:
                return report_issue(check, imported.name)
