"""Public API for the dlint rule-diff backend.

Compare two revisions of lint rules over a fixed bounded subset of Python
programs, witness programs whose verdicts change, reduce them while preserving
their difference category, and report alert-set changes, rule locations and
premises. An empty result is a bounded exploration result, never an
equivalence proof.
"""

from .core import (
    ALERT_ADDED,
    ALERT_CHANGED,
    ALERT_REMOVED,
    Budget,
    CATEGORY_MEANING,
    Difference,
    DifferenceCategory,
    DiffReport,
    ERROR_CLEARED,
    ERROR_INTRODUCED,
    compare_rules,
    render_text,
    replay,
    uncovered_features,
)
from .language import (
    BoundedSubset,
    Bounds,
    Coverage,
    ProgramGenerator,
    SUBSET,
    SUPPORTED_NODES,
    extract_premises,
    is_in_subset,
    unsupported_kinds,
)
from .runner import (
    Alert,
    RuleError,
    RuleRunner,
    RunResult,
    describe_rule_location,
)

DiffReport.Witness = Difference

__all__ = (
    "ALERT_ADDED", "ALERT_CHANGED", "ALERT_REMOVED", "ERROR_CLEARED",
    "ERROR_INTRODUCED", "CATEGORY_MEANING", "Budget", "Difference",
    "DifferenceCategory", "DiffReport", "compare_rules", "render_text",
    "replay", "uncovered_features", "BoundedSubset", "Bounds", "Coverage",
    "ProgramGenerator", "SUBSET", "SUPPORTED_NODES", "extract_premises",
    "is_in_subset", "unsupported_kinds", "Alert", "RuleError", "RuleRunner",
    "RunResult", "describe_rule_location",
)
