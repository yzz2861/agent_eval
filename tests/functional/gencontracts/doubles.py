"""Injectable defect doubles for the team rules.

Each double wraps a real rule function and simulates a plausible
regression, so the self-tests can verify that (a) the harness detects
the deviation and attributes it to the right contracts, and (b) the
shrinker can minimise the failing example.  Doubles keep the real
rule's metadata (``_checks``, ``_test_id``, ``_config``) so they run
through Bandit's own tester unchanged.
"""

import ast


def _relabel(double, origin):
    double.__name__ = origin.__name__ + "__double"
    double._checks = origin._checks
    double._test_id = origin._test_id
    if hasattr(origin, "_config"):
        double._config = origin._config
    return double


def _mentions_copy_call(node):
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            func = sub.func
            if isinstance(func, ast.Name) and func.id == "copy":
                return True
            if isinstance(func, ast.Attribute) and func.attr == "copy":
                return True
    return False


def copy_move_blind(origin):
    """Defect double: B602 loses commands routed through copy.copy."""

    def double(context, *args):
        node = context.node
        if node.args and _mentions_copy_call(node.args[0]):
            return None
        return origin(context, *args)

    return _relabel(double, origin)


def exact_password_keyword_only(origin):
    """Defect double: B106 only recognises the exact keyword 'password'."""

    def double(context, *args):
        result = origin(context, *args)
        if result is None:
            return None
        for keyword in context.node.keywords:
            if (
                keyword.arg == "password"
                and isinstance(keyword.value, ast.Constant)
                and isinstance(keyword.value.value, str)
            ):
                return result
        return None

    return _relabel(double, origin)
