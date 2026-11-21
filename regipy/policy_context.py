"""Compatibility import surface for regipy.policy."""

from regipy.policy import *  # noqa: F401,F403
from regipy.policy import __all__ as _policy_all

__all__ = list(_policy_all)
