"""
Finite joint checking for independently supplied CVSS candidate values.
"""

from __future__ import unicode_literals

from itertools import product
from math import isnan

from .cvss2 import CVSS2
from .cvss3 import CVSS3
from .cvss4 import CVSS4
from .exceptions import CVSSJointCheckError

__all__ = ["JointCheckResult", "joint_check"]

SEVERITY_ORDER = ("None", "Low", "Medium", "High", "Critical")
SEVERITY_SCORE_LIMITS = {
    "None": 0.0,
    "Low": 3.9,
    "Medium": 6.9,
    "High": 8.9,
    "Critical": 10.0,
}
CVSS_CLASSES = (CVSS2, CVSS3, CVSS4)


class JointCheckResult(object):
    """
    Holds candidate combinations that can occur together and unresolved conflicts.
    """

    def __init__(
        self,
        combinations,
        undetermined_announcements,
        conflicts,
        candidates,
        rejected_candidates=None,
    ):
        self.combinations = combinations
        self.undetermined_announcements = undetermined_announcements
        self.conflicts = conflicts
        self.candidates = candidates
        self.rejected_candidates = rejected_candidates or {}

    @property
    def is_determined(self):
        return not self.undetermined_announcements and not self.conflicts

    @property
    def is_feasible(self):
        return bool(self.combinations)

    @property
    def severity_combinations(self):
        combinations = []
        for combination in self.combinations:
            severity_combination = dict(
                (announcement_id, candidate["severity"])
                for announcement_id, candidate in combination.items()
            )
            if severity_combination not in combinations:
                combinations.append(severity_combination)
        return combinations

    def as_dict(self):
        return {
            "combinations": self.combinations,
            "undetermined_announcements": self.undetermined_announcements,
            "conflicts": self.conflicts,
            "candidates": self.candidates,
            "rejected_candidates": self.rejected_candidates,
            "severity_combinations": self.severity_combinations,
        }


def joint_check(announcements, constraints=None, threshold=None, max_combinations=10000):
    """
    Checks finite candidate severity combinations under shared observations.

    Args:
        announcements (dict): Announcement IDs mapped to candidate data. Each candidate may
                              provide a vector, a severity, an optional score, and observation
                              values. A per-announcement threshold overrides the global one.
        constraints (iterable): Cross-announcement relations. An equality relation binds two
                                observations to the same value. A mutual-exclusion relation binds
                                them to different values.
        threshold: Maximum accepted numeric score or severity tier.
        max_combinations (int): Safety limit for the explicitly supplied candidate space.

    Returns:
        JointCheckResult: Feasible combinations, undetermined announcements, and conflicts.
    """
    constraints = list(constraints or [])
    prepared_candidates = {}
    rejected_candidates = {}
    undetermined_announcements = []

    _validate_threshold(threshold, "threshold")
    _validate_max_combinations(max_combinations)
    _validate_announcements(announcements)

    for announcement_id, announcement_data in announcements.items():
        announcement_threshold = announcement_data.get("threshold", threshold)
        _validate_threshold(announcement_threshold, "threshold for {0}".format(announcement_id))
        eligible_candidates = []
        rejected = []

        for candidate in announcement_data.get("candidates", []):
            prepared_candidate = _prepare_candidate(candidate)
            if _within_threshold(prepared_candidate, announcement_threshold):
                eligible_candidates.append(prepared_candidate)
            else:
                rejected_candidate = _public_candidate(prepared_candidate)
                rejected_candidate["rejection_reason"] = _threshold_reason(
                    prepared_candidate, announcement_threshold
                )
                rejected.append(rejected_candidate)

        prepared_candidates[announcement_id] = eligible_candidates
        rejected_candidates[announcement_id] = rejected
        if not eligible_candidates:
            undetermined_announcements.append(announcement_id)

    if undetermined_announcements:
        return JointCheckResult(
            [],
            undetermined_announcements,
            [],
            prepared_candidates,
            rejected_candidates,
        )

    prepared_constraints = _prepare_constraints(constraints, list(announcements.keys()))
    candidate_sets = [prepared_candidates[announcement_id] for announcement_id in announcements]
    combination_count = 1
    for candidates in candidate_sets:
        combination_count *= len(candidates)
    if combination_count > max_combinations:
        raise CVSSJointCheckError(
            "Candidate space has {0} combinations, limit is {1}".format(
                combination_count, max_combinations
            )
        )

    feasible_combinations = []
    conflicts = {}
    for selected_candidates in product(*candidate_sets):
        combination = dict(zip(announcements.keys(), selected_candidates))
        combination_conflicts = _check_constraints(combination, prepared_constraints)
        if combination_conflicts:
            _record_conflicts(conflicts, combination_conflicts)
        else:
            feasible_combinations.append(_public_combination(combination))

    return JointCheckResult(
        feasible_combinations,
        undetermined_announcements,
        _sorted_conflicts(conflicts),
        prepared_candidates,
        rejected_candidates,
    )


def _validate_announcements(announcements):
    if not isinstance(announcements, dict) or not announcements:
        raise CVSSJointCheckError("Announcements must be a non-empty dictionary")
    for announcement_id, announcement_data in announcements.items():
        if not isinstance(announcement_data, dict):
            raise CVSSJointCheckError(
                "Announcement {0} must be a dictionary".format(announcement_id)
            )
        candidates = announcement_data.get("candidates", [])
        if not isinstance(candidates, (list, tuple)) or not candidates:
            raise CVSSJointCheckError(
                "Announcement {0} must contain at least one candidate".format(announcement_id)
            )


def _prepare_candidate(candidate):
    if not isinstance(candidate, dict):
        raise CVSSJointCheckError("Candidate must be a dictionary")

    vector = candidate.get("vector")
    severity = candidate.get("severity")
    score = candidate.get("score")
    observations = candidate.get("observations", {})

    if not isinstance(observations, dict):
        raise CVSSJointCheckError("Candidate observations must be a dictionary")

    if vector is not None:
        cvss_object = _parse_vector(vector)
        vector_severity = cvss_object.severities()[-1]
        vector_score = cvss_object.scores()[-1]
        if severity is None:
            severity = vector_severity
        elif severity != vector_severity:
            raise CVSSJointCheckError(
                "Candidate severity {0} does not match vector severity {1}".format(
                    severity, vector_severity
                )
            )
        if score is None:
            score = float(vector_score)
        elif float(score) != float(vector_score):
            raise CVSSJointCheckError(
                "Candidate score {0} does not match vector score {1}".format(
                    score, vector_score
                )
            )

    if severity not in SEVERITY_SCORE_LIMITS:
        raise CVSSJointCheckError("Invalid candidate severity {0}".format(severity))
    if score is None:
        score = SEVERITY_SCORE_LIMITS[severity]
    _validate_score(score)

    return {
        "vector": vector,
        "severity": severity,
        "score": float(score),
        "observations": dict(observations),
    }


def _parse_vector(vector):
    for cvss_class in CVSS_CLASSES:
        try:
            return cvss_class(vector)
        except Exception:
            pass
    raise CVSSJointCheckError("Invalid CVSS vector {0}".format(vector))


def _validate_threshold(threshold, name):
    if threshold is None:
        return
    if isinstance(threshold, str) and threshold in SEVERITY_SCORE_LIMITS:
        return
    _validate_score(threshold, name)


def _validate_score(score, name="candidate score"):
    try:
        numeric_score = float(score)
        if isnan(numeric_score):
            raise ValueError
    except (TypeError, ValueError):
        raise CVSSJointCheckError("Invalid {0} {1}".format(name, score))
    if not 0.0 <= numeric_score <= 10.0:
        raise CVSSJointCheckError("{0} must be between 0 and 10".format(name.capitalize()))


def _validate_max_combinations(max_combinations):
    if isinstance(max_combinations, bool) or not isinstance(max_combinations, int):
        raise CVSSJointCheckError("max_combinations must be a positive integer")
    if max_combinations < 1:
        raise CVSSJointCheckError("max_combinations must be a positive integer")


def _within_threshold(candidate, threshold):
    if threshold is None:
        return True
    if isinstance(threshold, str):
        return _severity_rank(candidate["severity"]) <= _severity_rank(threshold)
    return candidate["score"] <= float(threshold)


def _threshold_reason(candidate, threshold):
    if isinstance(threshold, str):
        return "severity {0} is above threshold {1}".format(
            candidate["severity"], threshold
        )
    return "score {0} is above threshold {1}".format(candidate["score"], float(threshold))


def _severity_rank(severity):
    return SEVERITY_ORDER.index(severity)


def _prepare_constraints(constraints, announcement_ids):
    prepared = []
    for constraint in constraints:
        if not isinstance(constraint, dict):
            raise CVSSJointCheckError("Constraint must be a dictionary")
        relation = constraint.get("relation")
        if relation not in ("equal", "mutually_exclusive"):
            raise CVSSJointCheckError(
                "Constraint relation must be 'equal' or 'mutually_exclusive'"
            )

        left = _prepare_constraint_endpoint(constraint.get("left"), announcement_ids)
        right = _prepare_constraint_endpoint(constraint.get("right"), announcement_ids)
        if left[0] == right[0]:
            raise CVSSJointCheckError("Constraints can only relate different announcements")
        prepared.append({"relation": relation, "left": left, "right": right})
    return prepared


def _prepare_constraint_endpoint(endpoint, announcement_ids):
    if not isinstance(endpoint, dict):
        raise CVSSJointCheckError("Constraint endpoint must be a dictionary")
    announcement_id = endpoint.get("announcement")
    observation = endpoint.get("observation")
    if announcement_id not in announcement_ids:
        raise CVSSJointCheckError(
            "Unknown constraint announcement {0}".format(announcement_id)
        )
    if not observation:
        raise CVSSJointCheckError("Constraint endpoint must name an observation")
    return announcement_id, observation


def _check_constraints(combination, constraints):
    conflicts = []
    for constraint in constraints:
        left_announcement, left_observation = constraint["left"]
        right_announcement, right_observation = constraint["right"]
        left_observations = combination[left_announcement]["observations"]
        right_observations = combination[right_announcement]["observations"]
        if left_observation not in left_observations:
            raise CVSSJointCheckError(
                "Announcement {0} has no observation {1}".format(
                    left_announcement, left_observation
                )
            )
        if right_observation not in right_observations:
            raise CVSSJointCheckError(
                "Announcement {0} has no observation {1}".format(
                    right_announcement, right_observation
                )
            )

        left_value = left_observations[left_observation]
        right_value = right_observations[right_observation]
        if constraint["relation"] == "equal" and left_value != right_value:
            conflicts.append(_conflict(constraint, combination, left_value, right_value))
        if constraint["relation"] == "mutually_exclusive" and left_value == right_value:
            conflicts.append(_conflict(constraint, combination, left_value, right_value))
    return conflicts


def _conflict(constraint, combination, left_value, right_value):
    left_announcement, left_observation = constraint["left"]
    right_announcement, right_observation = constraint["right"]
    return {
        "relation": constraint["relation"],
        "observations": [
            {
                "announcement": left_announcement,
                "observation": left_observation,
                "value": left_value,
            },
            {
                "announcement": right_announcement,
                "observation": right_observation,
                "value": right_value,
            },
        ],
        "severities": {
            announcement_id: combination[announcement_id]["severity"]
            for announcement_id in combination
        }
    }


def _record_conflicts(conflicts, new_conflicts):
    for conflict in new_conflicts:
        key = repr(conflict)
        conflicts[key] = conflict


def _sorted_conflicts(conflicts):
    return [conflicts[key] for key in sorted(conflicts.keys())]


def _public_combination(combination):
    return {
        announcement_id: _public_candidate(candidate)
        for announcement_id, candidate in combination.items()
    }


def _public_candidate(candidate):
    return {
        "vector": candidate["vector"],
        "severity": candidate["severity"],
        "score": candidate["score"],
        "observations": dict(candidate["observations"]),
    }
