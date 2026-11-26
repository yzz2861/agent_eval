"""Compatibility namespace for review-manifest importing.

The implementation lives in :mod:`detect_secrets.audit.reconcile`; this module
exists so the feature is importable under the action-oriented name.
"""
from .reconcile import *  # noqa: F401,F403
from .reconcile import __all__  # noqa: F401
