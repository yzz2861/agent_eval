#!/usr/bin/env python

"""Public compatibility facade for Dlint branch evidence."""

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

from .flow import evidence as _evidence

CONTRACT_UNKNOWN = _evidence.CONTRACT_UNKNOWN
EXCEPTION_CLEANUP = _evidence.EXCEPTION_CLEANUP
ExitKind = _evidence.ExitKind
NORMAL = _evidence.NORMAL
NORMAL_RETURN = _evidence.NORMAL_RETURN
RECOGNIZED_EXCEPTION_CLEANUP = _evidence.RECOGNIZED_EXCEPTION_CLEANUP
Status = _evidence.Status
UNKNOWN_CONTRACT = _evidence.UNKNOWN_CONTRACT
UNCHECKED = _evidence.UNCHECKED
UNCHECKED_RETURN = _evidence.UNCHECKED_RETURN
UNCHECKED_EXCEPTION = _evidence.UNCHECKED_EXCEPTION
AnalysisConfig = _evidence.AnalysisConfig
ExitEvidence = _evidence.ExitEvidence
FunctionEvidence = _evidence.FunctionEvidence
ResourceEvidence = _evidence.ResourceEvidence
Finding = _evidence.Finding
PathStep = _evidence.PathStep
analyze_function = _evidence.analyze_function
analyze_module = _evidence.analyze_module
analyze_branches = _evidence.analyze_branches
analyze_resource = _evidence.analyze_resource
branch_evidence = _evidence.branch_evidence
collect_branch_evidence = _evidence.collect_branch_evidence
collect_evidence = _evidence.collect_evidence


__all__ = [
    'CONTRACT_UNKNOWN',
    'EXCEPTION_CLEANUP',
    'ExitKind',
    'NORMAL',
    'NORMAL_RETURN',
    'RECOGNIZED_EXCEPTION_CLEANUP',
    'Status',
    'UNKNOWN_CONTRACT',
    'UNCHECKED',
    'UNCHECKED_RETURN',
    'UNCHECKED_EXCEPTION',
    'AnalysisConfig',
    'ExitEvidence',
    'FunctionEvidence',
    'ResourceEvidence',
    'Finding',
    'PathStep',
    'analyze_function',
    'analyze_module',
    'analyze_branches',
    'analyze_resource',
    'branch_evidence',
    'collect_branch_evidence',
    'collect_evidence',
]
