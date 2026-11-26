"""Compatibility import for the independence audit feature."""

from securesystemslib.independence_check import *  # noqa: F403
from securesystemslib.independence_check import (  # noqa: F401
    AuditResult,
    IndependenceCheckError,
    IndependenceVerifier,
    attach_independence_check,
    audit_independence,
    check_independence,
    find_independent_assignment,
    recompute_independence,
    verify_independence,
    verify_offline_attestation,
)
from securesystemslib.independence_sample import (  # noqa: F401
    build_shared_substitute_sample,
    create_shared_substitute_sample,
)
