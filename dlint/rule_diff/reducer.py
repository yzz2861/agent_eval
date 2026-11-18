"""Category-preserving witness reduction.

Reduction only deletes module-level statements or shrinks literals; it never
introduces a new construct, so the reduced witness stays inside the same
bounded AST subset. A candidate is accepted only when the difference category
is exactly preserved, which keeps an injected false negative from silently
turning into a false-positive witness (and vice versa).
"""

from __future__ import annotations

import ast

from .language import unparse


def _valid_candidate(source):
    try:
        compile(source, "<reduced>", "exec")
    except SyntaxError:
        return False
    return source.strip() != ""


def _module_source(statements):
    module = ast.Module(body=list(statements), type_ignores=[])
    ast.fix_missing_locations(module)
    return unparse(module)


def _remove_statement_slices(statements, granularity, classify_fn,
                             target_category, steps):
    """ddmin complement step: drop one slice at a time."""
    length = len(statements)
    for start in range(0, length, granularity):
        end = min(start + granularity, length)
        candidate = statements[:start] + statements[end:]
        if not candidate:
            continue
        source = _module_source(candidate)
        steps[0] += 1
        if _valid_candidate(source) and classify_fn(source) == target_category:
            return candidate
    return None


def _keep_statement_slices(statements, granularity, classify_fn,
                           target_category, steps):
    """ddmin subset step: keep one slice at a time."""
    length = len(statements)
    for start in range(0, length, granularity):
        end = min(start + granularity, length)
        candidate = statements[start:end]
        if not candidate:
            continue
        source = _module_source(candidate)
        steps[0] += 1
        if _valid_candidate(source) and classify_fn(source) == target_category:
            return candidate
    return None


def _ddmin_statements(source, classify_fn, target_category, deadline, steps):
    statements = ast.parse(source).body
    if len(statements) < 2:
        return statements
    granularity = 2
    while len(statements) >= 2 and deadline():
        length = len(statements)
        before = length
        reduced = _remove_statement_slices(
            statements, granularity, classify_fn, target_category, steps
        )
        if reduced is not None:
            statements = reduced
            granularity = 2
        else:
            reduced = _keep_statement_slices(
                statements, granularity, classify_fn, target_category, steps
            )
            if reduced is not None:
                statements = reduced
                granularity = 2
        # Terminate when a full pass at the finest granularity made no
        # progress; otherwise this never converges for a 2-statement input.
        if len(statements) == before:
            if granularity >= length:
                break
            granularity = min(length, granularity * 2)
    return statements


def _shrink_literals(statements, classify_fn, target_category, deadline,
                     steps):
    """Replace constants with smaller equivalents if the category holds."""
    smaller = {"x": "", 1: 0, 2: 0, 3: 1}
    tree = ast.Module(body=list(statements), type_ignores=[])
    ast.fix_missing_locations(tree)
    changed = True
    while changed and deadline():
        changed = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or node.value not in smaller:
                continue
            original = node.value
            node.value = smaller[original]
            candidate_source = unparse(tree)
            steps[0] += 1
            if (_valid_candidate(candidate_source)
                    and classify_fn(candidate_source) == target_category):
                changed = True
                break
            node.value = original
    return tree.body


def reduce_witness(source, target_category, classify_fn, deadline):
    """Reduce ``source`` while preserving exactly ``target_category``.

    :param classify_fn: callable mapping source -> category string or None.
    :param deadline: zero-argument callable, True while time remains.
    :returns: ``(reduced_source, reduction_steps)``. The returned program is
              re-validated to compile and to still exhibit the category.
    """
    steps = [0]
    statements = _ddmin_statements(
        source, classify_fn, target_category, deadline, steps
    )
    statements = _shrink_literals(
        statements, classify_fn, target_category, deadline, steps
    )
    reduced_source = _module_source(statements)
    if not _valid_candidate(reduced_source):
        return source, 0
    if classify_fn(reduced_source) != target_category:
        # Safety net: never return a witness whose category drifted.
        return source, 0
    return reduced_source, steps[0]


# Alias used by the orchestration layer.
reduce = reduce_witness
