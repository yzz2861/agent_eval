"""
Approval explanation for two complete CVSS 4.0 vectors.

Given an original vector and a reviewed vector, this module enumerates every
inclusion-minimal set of metric changes whose joint application moves the score
across a caller-supplied threshold. All scores, metric inheritance (modified
metrics falling back to base metrics, E/CR/IR/AR defaults) and the one decimal
round half up rounding are taken directly from :class:`cvss.cvss4.CVSS4`, so the
returned vectors can be re-checked with the unmodified calculator.

No external solver is used: the search is a bounded enumeration over the sets of
literally changed metric fields.
"""

from __future__ import unicode_literals

from itertools import combinations as _combinations

from .constants4 import METRICS_ABBREVIATIONS
from .cvss4 import CVSS4
from .exceptions import CVSS4ApprovalError

# Supplemental metrics do not influence the CVSS 4.0 base score, so they can never
# be part of an explanation of why a score gate changed.
SUPPLEMENTAL_METRICS = ("S", "AU", "R", "V", "RE", "U")


class MetricChange(object):
    """A single literally changed metric field between the two vectors."""

    def __init__(self, metric, old_value, new_value, old_effective, new_effective):
        self.metric = metric
        self.old_value = old_value
        self.new_value = new_value
        self.old_effective = old_effective
        self.new_effective = new_effective

    def __repr__(self):
        return "MetricChange({0}: {1}->{2})".format(
            self.metric,
            self.old_value if self.old_value is not None else "absent",
            self.new_value if self.new_value is not None else "absent",
        )

    def __eq__(self, other):
        return isinstance(other, MetricChange) and self.metric == other.metric

    def __hash__(self):
        return hash(self.metric)


class MinimalChangeGroup(object):
    """
    An inclusion-minimal set of metric changes that moves the score across the gate.
    """

    def __init__(self, changes, vector, score, original_score):
        self.changes = changes
        self.vector = vector
        self.score = score
        self.original_score = original_score

    @property
    def metrics(self):
        return tuple(change.metric for change in self.changes)

    def __repr__(self):
        return "MinimalChangeGroup({0} -> {1})".format(self.metrics, self.score)

    def __eq__(self, other):
        if isinstance(other, MinimalChangeGroup):
            return self.vector == other.vector
        return NotImplemented

    def __hash__(self):
        return hash(self.vector)


class ApprovalExplanation(object):
    """
    Result of an approval explanation request.
    """

    def __init__(
        self,
        original_vector,
        reviewed_vector,
        threshold,
        direction,
        original_score,
        reviewed_score,
        changes,
        minimal_groups,
        coupled_groups,
        max_evaluations,
        evaluations,
        complete,
        ignored_supplemental,
    ):
        self.original_vector = original_vector
        self.reviewed_vector = reviewed_vector
        self.threshold = threshold
        self.direction = direction
        self.original_score = original_score
        self.reviewed_score = reviewed_score
        self.changes = changes
        self.minimal_groups = minimal_groups
        self.coupled_groups = coupled_groups
        self.max_evaluations = max_evaluations
        self.evaluations = evaluations
        self.complete = complete
        self.ignored_supplemental = ignored_supplemental

    @property
    def proven(self):
        """
        True when every feasible change set was evaluated, so the returned groups are
        guaranteed to be all inclusion-minimal crossing groups.
        """
        return self.complete

    def __repr__(self):
        return ("ApprovalExplanation(threshold={0}, direction={1!r}, groups={2}, complete={3})"
                ).format(self.threshold, self.direction, len(self.minimal_groups), self.complete)


def _effective_value(cvss4, metric):
    """
    Value of metric as used by the score, honouring modified-metric inheritance and the
    E/CR/IR/AR defaults, via the original CVSS4.m() semantics.
    """
    return cvss4.m(metric)


def _literal_metrics(cvss4):
    """
    Literally provided metric fields, excluding supplemental metrics which never affect score.
    """
    result = {}
    for metric, value in cvss4.original_metrics.items():
        if metric in SUPPLEMENTAL_METRICS:
            continue
        result[metric] = value
    return result


def _build_change(metric, old_literal, new_literal, original_cvss, reviewed_cvss):
    old_effective = _effective_value(original_cvss, metric)
    new_effective = _effective_value(reviewed_cvss, metric)
    return MetricChange(metric, old_literal, new_literal, old_effective, new_effective)


def _compute_changes(original_cvss, reviewed_cvss):
    old_literal = _literal_metrics(original_cvss)
    new_literal = _literal_metrics(reviewed_cvss)
    ignored = sorted(
        set(reviewed_cvss.original_metrics).intersection(SUPPLEMENTAL_METRICS)
        | set(original_cvss.original_metrics).intersection(SUPPLEMENTAL_METRICS)
    )
    metrics = sorted(set(old_literal).union(new_literal), key=list(METRICS_ABBREVIATIONS).index)
    changes = []
    for metric in metrics:
        old_value = old_literal.get(metric)
        new_value = new_literal.get(metric)
        if old_value == new_value:
            continue
        changes.append(_build_change(metric, old_value, new_value, original_cvss, reviewed_cvss))
    return changes, ignored


def _normalize_coupling(changes, coupled_groups):
    """
    Merge caller supplied coupling groups into disjoint equivalence classes (atoms). Metrics not
    mentioned stay singleton atoms. Raises CVSS4ApprovalError on unknown metrics.
    """
    change_by_metric = {change.metric: change for change in changes}
    if coupled_groups is None:
        coupled_groups = []
    parent = {change.metric: change.metric for change in changes}

    def find(metric):
        while parent[metric] != metric:
            parent[metric] = parent[parent[metric]]
            metric = parent[metric]
        return metric

    normalized = []
    for group in coupled_groups:
        metrics = tuple(dict.fromkeys(group))
        if not metrics:
            continue
        for metric in metrics:
            if metric not in change_by_metric:
                raise CVSS4ApprovalError(
                    "Coupled metric \"{0}\" is not changed between the two vectors".format(metric)
                )
        normalized.append(metrics)
        root = find(metrics[0])
        for metric in metrics[1:]:
            other = find(metric)
            if other != root:
                parent[other] = root

    atoms = {}
    for change in changes:
        atoms.setdefault(find(change.metric), []).append(change)
    atom_list = [
        tuple(sorted(group, key=lambda change: change.metric)) for group in atoms.values()
    ]
    return atom_list


def _candidate_vector(original_cvss, selected_changes):
    """
    Build a valid, ordered CVSS4 vector by applying selected literal changes to the original
    fields and dropping fields the review removed. Inheritance and defaults are recomputed by
    CVSS4, keeping the original scoring semantics.
    """
    values = dict(original_cvss.original_metrics)
    for change in selected_changes:
        if change.new_value is None:
            values.pop(change.metric, None)
        else:
            values[change.metric] = change.new_value
    parts = []
    for metric in METRICS_ABBREVIATIONS:
        if metric in values and values[metric] != "X":
            parts.append("{0}:{1}".format(metric, values[metric]))
    return "CVSS:4.0/" + "/".join(parts)


def _crosses(score, threshold, direction):
    if direction == "below":
        return score <= threshold
    return score >= threshold


def _enumerate_minimal_groups(original_cvss, atoms, threshold, direction, max_evaluations):
    """
    Enumerate inclusion-minimal atom sets whose composed changes cross the gate.

    Atoms are the coupling units, so only atom-union feasible sets are considered. A set that
    contains an already proven crossing subset is skipped, which preserves minimality while
    pruning the search.

    Returns (groups, evaluations, complete). When the evaluation budget is exhausted complete is
    False: every returned group is still proven minimal, but further minimal groups may exist.
    """
    minimal_groups = []
    crossing_subsets = []
    evaluations = 0
    complete = True
    atom_count = len(atoms)

    def contains_crossing_subset(indices):
        chosen = set(indices)
        for subset in crossing_subsets:
            if subset.issubset(chosen):
                return True
        return False

    for size in range(1, atom_count + 1):
        layer = []
        combinations = _combinations(range(atom_count), size)
        for combo in combinations:
            indices = frozenset(combo)
            if contains_crossing_subset(indices):
                continue
            layer.append(indices)
        for indices in layer:
            if evaluations >= max_evaluations:
                complete = False
                return minimal_groups, evaluations, complete
            selected_changes = []
            for index in indices:
                selected_changes.extend(atoms[index])
            vector = _candidate_vector(original_cvss, selected_changes)
            score = CVSS4(vector).base_score
            evaluations += 1
            if _crosses(score, threshold, direction):
                ordered = []
                for change in sorted(selected_changes, key=lambda change: change.metric):
                    ordered.append(change)
                crossing_subsets.append(indices)
                minimal_groups.append(
                    MinimalChangeGroup(tuple(ordered), vector, score, original_cvss.base_score)
                )
    return minimal_groups, evaluations, complete


def explain_approval(
    original_vector,
    reviewed_vector,
    threshold,
    direction="below",
    coupled_groups=None,
    max_evaluations=100000,
):
    """
    Explain which changes between two complete CVSS 4.0 vectors move the score across a gate.

    Args:
        original_vector (str): full vector before the review, e.g. the high risk rating
        reviewed_vector (str): full vector after the review
        threshold (float): score gate, compared after the standard one decimal rounding
        direction (str): "below" accepts scores <= threshold (downgrade gates), "above" accepts
                         scores >= threshold (upgrade gates)
        coupled_groups (iterable of iterables of str): metric abbreviations whose changes must
                         always be applied or rejected together; overlapping groups are merged
        max_evaluations (int): safety bound on the number of candidate vectors scored

    Returns:
        ApprovalExplanation: all inclusion-minimal crossing groups found, each with the full
        ordered vector and its rounded score, plus provenance flags

    Raises:
        CVSS4ApprovalError: on invalid direction, non-positive evaluation bound or bad coupling
        CVSS4MalformedError/CVSS4MandatoryError: if either vector is not a valid CVSS 4.0 vector
    """
    if direction not in ("below", "above"):
        raise CVSS4ApprovalError(
            "direction must be \"below\" or \"above\", got {0!r}".format(direction)
        )
    if not isinstance(max_evaluations, int) or max_evaluations <= 0:
        raise CVSS4ApprovalError("max_evaluations must be a positive integer")

    original_cvss = CVSS4(original_vector)
    reviewed_cvss = CVSS4(reviewed_vector)
    original_score = original_cvss.base_score
    reviewed_score = reviewed_cvss.base_score

    changes, ignored_supplemental = _compute_changes(original_cvss, reviewed_cvss)
    atoms = _normalize_coupling(changes, coupled_groups)

    minimal_groups = []
    evaluations = 0
    complete = True
    if not _crosses(original_score, threshold, direction):
        if changes:
            minimal_groups, evaluations, complete = _enumerate_minimal_groups(
                original_cvss, atoms, threshold, direction, max_evaluations
            )

    return ApprovalExplanation(
        original_vector=original_cvss.clean_vector(),
        reviewed_vector=reviewed_cvss.clean_vector(),
        threshold=threshold,
        direction=direction,
        original_score=original_score,
        reviewed_score=reviewed_score,
        changes=tuple(changes),
        minimal_groups=tuple(minimal_groups),
        coupled_groups=tuple(tuple(group) for group in (coupled_groups or [])),
        max_evaluations=max_evaluations,
        evaluations=evaluations,
        complete=complete,
        ignored_supplemental=tuple(ignored_supplemental),
    )

