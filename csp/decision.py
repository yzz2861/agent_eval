"""Compatibility import for the CSP rollout decision API.

The implementation lives in :mod:`csp.rollout`.  This module keeps the
decision entry point discoverable for callers that think in terms of runtime
decisions rather than rollout records.
"""

from csp.rollout import *  # noqa: F403
from csp.rollout import __all__  # noqa: F401
