#!/usr/bin/env python

"""Compatibility imports for temporary resource cleanup evidence."""

from __future__ import (
    absolute_import,
    division,
    print_function,
    unicode_literals,
)

from .resource_lifecycle import (  # noqa F401
    AnalysisConfig,
    CONTRACT_UNKNOWN,
    EXCEPTION_CLEANUP,
    ExitEvidence,
    ExitKind,
    FunctionEvidence,
    NORMAL,
    NORMAL_RETURN,
    RECOGNIZED_EXCEPTION_CLEANUP,
    Status,
    UNCHECKED,
    UNCHECKED_EXCEPTION,
    UNCHECKED_RETURN,
    UNKNOWN_CONTRACT,
    analyze_branches,
    analyze_function,
    analyze_module,
    analyze_resource,
    branch_evidence,
    collect_branch_evidence,
    collect_evidence,
)


__all__ = [
    'AnalysisConfig',
    'CONTRACT_UNKNOWN',
    'EXCEPTION_CLEANUP',
    'ExitEvidence',
    'ExitKind',
    'FunctionEvidence',
    'NORMAL',
    'NORMAL_RETURN',
    'RECOGNIZED_EXCEPTION_CLEANUP',
    'Status',
    'UNCHECKED',
    'UNCHECKED_EXCEPTION',
    'UNCHECKED_RETURN',
    'UNKNOWN_CONTRACT',
    'analyze_branches',
    'analyze_function',
    'analyze_module',
    'analyze_resource',
    'branch_evidence',
    'collect_branch_evidence',
    'collect_evidence',
]
