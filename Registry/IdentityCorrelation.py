"""Compatibility alias for Registry.Identity.

The identity correlation API historically appeared under both the
Identity and IdentityCorrelation names in case notes.  New code should
import from Registry.Identity.
"""
from .Identity import *  # noqa: F401,F403
from .Identity import __all__  # noqa: F401
