"""Compatibility module name for independence_check."""

from securesystemslib.independence_check import *  # noqa: F403
from securesystemslib.independence_check import (  # noqa: F401
    AuditResult,
    IndependenceChecker,
    IndependenceCheckError,
    IndependenceReport,
    IndependenceVerifier,
    attach_independence_check,
    audit_independence,
    check_independence,
    find_independent_assignment,
    is_independent,
    recompute_independence,
    verify_independence,
    verify_offline_attestation,
)
from securesystemslib.independence_sample import (  # noqa: F401
    build_shared_substitute_sample,
    create_shared_substitute_sample,
)
