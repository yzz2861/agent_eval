#!/usr/bin/env python

"""Small, source-only control-flow helpers used by Dlint evidence rules.

The functions in this module never import or execute analyzed code.  They
walk an already parsed ``ast`` tree and return the exits that a function can
reach.  The engine is intentionally bounded: callers provide a path budget
and an over-budget analysis is reported as unknown rather than clean.
"""

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

from . import evidence


def build_cfg(function_node, config=None):
    """Return the bounded path evidence for ``function_node``.

    This is a convenience alias for callers that think in terms of a control
    flow graph.  ``evidence.analyze_function`` returns the same information
    in a form that is easier to serialize.
    """

    if config is None:
        config = evidence.AnalysisConfig()
    return evidence.analyze_function(function_node, config)


def collect_evidence(function_node, config=None):
    return build_cfg(function_node, config)


__all__ = ['build_cfg', 'collect_evidence']
