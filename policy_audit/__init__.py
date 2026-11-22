"""
CVSS policy pre-check toolkit.

This package treats the Red Hat ``cvss`` library as the *scoring kernel* and builds a policy
review layer on top of it:

* :mod:`policy_audit.universe`  - finite, specification-valid metric combinations per version
* :mod:`policy_audit.policy`    - band configuration, allowed metric values, missing-candidate rule
* :mod:`policy_audit.graph`     - one-independent-fact adjacency, connected components, witnesses
* :mod:`policy_audit.compare`   - cross-version review on a shared mapping

Only vectors accepted by the scoring kernel are ever produced; invalid combinations are rejected
by the kernel itself rather than silently synthesised.
"""

from .universe import VERSIONS, LegalVector, build_universe, score_vector
from .policy import Policy, load_policy
from .graph import BandGraph, Edge, build_band_graph
from .compare import compare_versions
from .report import audit_version, build_report

__all__ = [
    "VERSIONS",
    "LegalVector",
    "build_universe",
    "score_vector",
    "Policy",
    "load_policy",
    "BandGraph",
    "Edge",
    "build_band_graph",
    "compare_versions",
    "audit_version",
    "build_report",
]
