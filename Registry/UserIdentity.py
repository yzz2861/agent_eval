"""Compatibility alias for Registry.Identity.

Use Registry.Identity for new code.  This module keeps the user-identity
name importable for callers that phrase the feature that way.
"""
from .Identity import *  # noqa: F401,F403
from .Identity import __all__  # noqa: F401
