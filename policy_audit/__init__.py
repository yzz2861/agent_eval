"""Release-gate audit for YAML security policies built on PyYAML safe loading.

The audit loads policy YAML documents through ``yaml.SafeLoader`` so that
scalar resolution (``yes``/``010``/``0x10`` ...) and merge keys (``<<``)
behave exactly as they do in production parsing, merges them with the real
deep-merge semantics, and then analyses the *effective* rule set instead of
the raw file text that reviewers sign off on.
"""

from .loader import Issue, LoadedPolicy, Provenance, load_policy
from .analyze import RuleVerdict, analyze_policy
from .compare import ScopeChange, compare_policies
from .report import render_report, render_comparison

__all__ = [
    "Issue",
    "LoadedPolicy",
    "Provenance",
    "load_policy",
    "RuleVerdict",
    "analyze_policy",
    "ScopeChange",
    "compare_policies",
    "render_report",
    "render_comparison",
]
