"""Compatibility alias for :mod:`in_toto.handoff`."""

from in_toto import handoff as _core
from in_toto.handoff import *  # noqa: F403


def __getattr__(name):
    return _core.__getattr__(name)
