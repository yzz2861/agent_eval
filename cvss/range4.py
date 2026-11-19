# Copyright (c) 2026 Red Hat, Inc.
# License: LGPLv3+

"""
Range queries over CVSS4 vectors, intended for triage backends.

Given a partially known CVSS4 vector and per-metric constraints (a metric may be
fixed to a single value or narrowed to a set of candidate values), compute the
reachable minimum and maximum scores together with complete vectors attaining
them.

Known threat and environmental metrics are supplied in the vector (or default to
"X") and are scored with the official rules; every candidate combination is
scored through the CVSS4 class, i.e. through the macro vector lookup and final
rounding. Combinations are enumerated lazily and deduplicated by their effective
scoring values, so the combination space is never fully materialized.

The library is compatible with both Python 2 and Python 3.
"""

from __future__ import unicode_literals

import itertools
from collections import namedtuple

from .constants4 import METRICS_ABBREVIATIONS, METRICS_MANDATORY, METRICS_VALUE_NAMES
from .cvss4 import CVSS4
from .exceptions import CVSS4MalformedError, CVSS4UnsatisfiableError

try:
    basestring
except NameError:
    basestring = str

# Metrics which influence the score through CVSS4.m(). Supplemental metrics
# (S, AU, R, V, RE, U) never influence the score.
SCORING_METRICS = (
    "AV",
    "AC",
    "AT",
    "PR",
    "UI",
    "VC",
    "VI",
    "VA",
    "SC",
    "SI",
    "SA",
    "E",
    "CR",
    "IR",
    "AR",
)

# Optional metrics default to "X" (not defined) when neither fixed nor constrained.
OPTIONAL_DEFAULT = "X"

CVSS4ScoreRange = namedtuple(
    "CVSS4ScoreRange", ("min_score", "min_vector", "max_score", "max_vector")
)


def _parse_partial_vector(vector):
    """
    Parses metrics from a possibly incomplete CVSS4 vector. Mandatory metrics may
    be missing, unlike in CVSS4.parse_vector.

    Raises:
        CVSS4MalformedError: if vector is not in expected format
    """
    metrics = {}
    if not vector:
        return metrics
    if vector.endswith("/"):
        raise CVSS4MalformedError('Malformed CVSS4 vector, trailing "/"')
    if not vector.startswith("CVSS:4.0/"):
        raise CVSS4MalformedError(
            'Malformed CVSS4 vector "{0}" is missing mandatory prefix '
            "or uses unsupported CVSS version".format(vector)
        )
    for field in vector.split("/")[1:]:
        if field == "":
            raise CVSS4MalformedError('Empty field in CVSS4 vector "{0}"'.format(vector))
        try:
            metric, value = field.split(":")
        except ValueError:
            raise CVSS4MalformedError('Malformed CVSS4 field "{0}"'.format(field))
        if metric in metrics:
            raise CVSS4MalformedError('Duplicate metric "{0}"'.format(metric))
        if metric not in METRICS_VALUE_NAMES:
            raise CVSS4MalformedError('Invalid metric key in CVSS4 vector "{0}"'.format(field))
        if value not in METRICS_VALUE_NAMES[metric]:
            raise CVSS4MalformedError('Invalid metric value in CVSS4 vector "{0}"'.format(field))
        metrics[metric] = value
    return metrics


def _normalize_constraint(metric, constraint):
    """
    Normalizes a single constraint to a list of candidate values in canonical
    metric order. A plain string fixes the metric to a single value, an iterable
    narrows the candidate set.

    Raises:
        CVSS4MalformedError: if metric or any value is invalid
        CVSS4UnsatisfiableError: if the candidate set is empty
    """
    if metric not in METRICS_VALUE_NAMES:
        raise CVSS4MalformedError('Invalid metric key "{0}"'.format(metric))
    if isinstance(constraint, basestring):
        requested = {constraint}
    else:
        try:
            requested = set(constraint)
        except TypeError:
            raise CVSS4MalformedError(
                'Invalid constraint for metric "{0}": {1!r}'.format(metric, constraint)
            )
    for value in requested:
        if value not in METRICS_VALUE_NAMES[metric]:
            raise CVSS4MalformedError('Invalid metric value "{0}:{1}"'.format(metric, value))
    candidates = [value for value in METRICS_VALUE_NAMES[metric] if value in requested]
    if not candidates:
        raise CVSS4UnsatisfiableError(
            'Constraint for metric "{0}" leaves no candidate values'.format(metric)
        )
    return candidates


def _effective_key(metrics):
    """
    Computes the values which actually determine the score, replicating CVSS4.m()
    so combinations scoring identically are evaluated only once.
    """
    key = []
    for metric in SCORING_METRICS:
        selected = metrics[metric]
        modified = metrics.get("M" + metric, OPTIONAL_DEFAULT)
        if modified != OPTIONAL_DEFAULT:
            selected = modified
        if metric == "E" and selected == OPTIONAL_DEFAULT:
            selected = "A"
        elif metric in ("CR", "IR", "AR") and selected == OPTIONAL_DEFAULT:
            selected = "H"
        key.append(selected)
    return tuple(key)


def _build_vector(metrics):
    """
    Builds a complete CVSS4 vector string with all metrics in the order required
    by the specification, so it can be re-scored independently by CVSS4.
    """
    return "CVSS:4.0/" + "/".join(
        "{0}:{1}".format(metric, metrics[metric]) for metric in METRICS_ABBREVIATIONS
    )


def score_range(vector="", constraints=None):
    """
    Computes the reachable minimum and maximum CVSS4 scores for a partially
    known vector.

    Args:
        vector (str): partial CVSS4 vector; metrics present are fixed, missing
                      mandatory metrics range over all their values unless
                      constrained, missing optional metrics default to "X"
        constraints (dict): metric abbreviation to either a single value (fixes
                            the metric) or an iterable of values (narrows its
                            candidate set)

    Returns:
        CVSS4ScoreRange: named tuple with min_score, min_vector, max_score and
                         max_vector; both vectors are complete and re-scoring
                         them with CVSS4 yields the respective endpoint score

    Raises:
        CVSS4MalformedError: if the vector, a metric or a value is invalid
        CVSS4UnsatisfiableError: if the constraints leave no valid combination
    """
    fixed = _parse_partial_vector(vector)

    candidates = {}
    for metric in METRICS_ABBREVIATIONS:
        if metric in fixed:
            candidates[metric] = [fixed[metric]]
        elif metric in METRICS_MANDATORY:
            candidates[metric] = list(METRICS_VALUE_NAMES[metric])
        else:
            candidates[metric] = [OPTIONAL_DEFAULT]

    for metric, constraint in (constraints or {}).items():
        values = _normalize_constraint(metric, constraint)
        if metric in fixed:
            if fixed[metric] not in values:
                raise CVSS4UnsatisfiableError(
                    'Metric "{0}" fixed to "{1}" contradicts constraint {2!r}'.format(
                        metric, fixed[metric], constraint
                    )
                )
            continue
        candidates[metric] = values

    varied = [metric for metric in METRICS_ABBREVIATIONS if len(candidates[metric]) > 1]
    constant = dict(
        (metric, values[0]) for metric, values in candidates.items() if len(values) == 1
    )

    scores_by_key = {}
    min_result = None
    max_result = None
    for combination in itertools.product(*(candidates[metric] for metric in varied)):
        metrics = dict(constant)
        metrics.update(zip(varied, combination))
        key = _effective_key(metrics)
        if key not in scores_by_key:
            full_vector = _build_vector(metrics)
            scores_by_key[key] = (CVSS4(full_vector).base_score, full_vector)
        score, full_vector = scores_by_key[key]
        if min_result is None or score < min_result[0]:
            min_result = (score, full_vector)
        if max_result is None or score > max_result[0]:
            max_result = (score, full_vector)

    if min_result is None:
        raise CVSS4UnsatisfiableError("Constraints leave no valid metric combination")

    return CVSS4ScoreRange(
        min_score=min_result[0],
        min_vector=min_result[1],
        max_score=max_result[0],
        max_vector=max_result[1],
    )
