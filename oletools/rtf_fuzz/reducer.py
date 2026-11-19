"""
Syntax-unit delta debugging for fuzzing findings.

When the oracles detect a discrepancy, the offending document is reduced using
the classical ddmin algorithm applied to *syntactic units* (groups, control
words, backslash-bin entries and hexadecimal text fragments) instead of raw
bytes.  Every reduction candidate is re-checked against the exact signature of
the original :class:`oletools.rtf_fuzz.oracle.Difference`: a smaller document
that merely triggers a different parse exception is rejected, so the minimised
sample always explains the same finding.

The reducer shares the campaign's :class:`oletools.rtf_fuzz.oracle.Budget`
and therefore obeys the same step/byte ceiling.
"""

import copy

from . import model
from . import oracle as oracle_module


def _syntax_units(tree):
    """List removable syntax units (mutable child nodes of real groups)."""
    units = []
    for node in model.walk(tree):
        if not isinstance(node, model.GroupNode):
            continue
        if isinstance(node, model.DocumentNode):
            continue
        for child in list(node.children):
            units.append((node, child))
    return units


def _node_path(tree, target):
    """Return the child-index path of target within tree, or None."""
    def search(node, path):
        if node is target:
            return list(path)
        for index, child in enumerate(getattr(node, "children", ())):
            found = search(child, path + [index])
            if found is not None:
                return found
        return None
    return search(tree, [])


def _remove_unit(tree, group, child):
    """Return a deep copy of tree with the identified child removed.

    Nodes are located by their child-index path rather than by content, so
    duplicated but distinct syntax units cannot be removed by mistake.
    """
    path = _node_path(tree, child)
    if path is None:
        return tree
    clone = copy.deepcopy(tree)
    node = clone
    for index in path[:-1]:
        node = node.children[index]
    del node.children[path[-1]]
    return clone


def _render_without_units(tree, removables):
    # Resolve every unit to its path against the original tree first, then
    # apply all deletions to a single clone from deepest to shallowest so the
    # remaining paths stay valid after each deletion.
    paths = []
    for _group, child in list(removables):
        node_path = _node_path(tree, child)
        if node_path is None:
            return None
        paths.append(node_path)
    clone = copy.deepcopy(tree)
    for node_path in sorted(paths, reverse=True):
        node = clone
        for index in node_path[:-1]:
            node = node.children[index]
        del node.children[node_path[-1]]
    return clone


class ReductionOutcome(object):
    """Result of reducing a finding to a minimal reproducing sample."""

    def __init__(self, tree, original_size, reduced_size, steps,
                 signature_kept, stop_reason=None):
        self.tree = tree
        self.original_size = original_size
        self.reduced_size = reduced_size
        self.steps = steps
        self.signature_kept = signature_kept
        self.stop_reason = stop_reason

    @property
    def document(self):
        return model.render(self.tree)


def reduce_finding(tree, difference, budget, comparator, max_rounds=12):
    """Syntax-unit ddmin that preserves the original difference signature.

    The algorithm removes increasing subsets of the removable syntax units and
    only accepts a smaller tree when the comparator still reports the exact
    same Difference signature. A candidate that degrades into an unrelated
    parse exception is therefore rejected.
    """
    target_signature = difference.signature()
    original_document = model.render(tree)
    current = copy.deepcopy(tree)
    steps = 0

    class _BudgetExhausted(Exception):
        pass

    def keeps_signature(candidate_tree):
        document = model.render(candidate_tree)
        if not budget.allow(len(document)):
            raise _BudgetExhausted()
        if oracle_module.run_with_budget(document, budget) is None:
            raise _BudgetExhausted()
        candidate_diff = comparator(document)
        return (candidate_diff is not None
                and candidate_diff.signature() == target_signature)

    for _ in range(max_rounds):
        units = _syntax_units(current)
        if not units:
            break
        total = len(units)
        reduced_this_round = False
        # ddmin: split into n subsets for n = 2, 4, ..., total. When n reaches
        # total each subset is a single unit, so any individually removable
        # unit is guaranteed to be tried and accepted.
        granularity = 2
        while granularity <= total:
            chunk_size = max(1, total // granularity)
            start_index = 0
            while start_index < total:
                if budget.exhausted:
                    break
                chunk = units[start_index:start_index + chunk_size]
                steps += 1
                candidate = _render_without_units(current, chunk)
                try:
                    accepted = (candidate is not None
                                and keeps_signature(candidate))
                except _BudgetExhausted:
                    break
                if accepted:
                    current = candidate
                    reduced_this_round = True
                    break
                start_index += chunk_size
            if reduced_this_round or budget.exhausted:
                break
            if granularity >= total:
                break
            granularity = min(total, granularity * 2)
        if not reduced_this_round or budget.exhausted:
            break

    final_document = model.render(current)
    final_diff = comparator(final_document)
    signature_kept = (final_diff is not None
                      and final_diff.signature() == target_signature)
    return ReductionOutcome(
        current, len(original_document), len(final_document), steps,
        signature_kept, budget.stop_reason)
