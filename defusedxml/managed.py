"""Alias module for :mod:`defusedxml.scoped`.

The managed-read API lives in :mod:`defusedxml.scoped`; this module keeps the
name discoverable for services that describe the entry point as a managed
reader.
"""

from .scoped import *  # noqa: F401,F403
from .scoped import __all__  # noqa: F401
