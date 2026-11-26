"""Compatibility name for LC_NOTE audit helpers."""

from .note_audit import *  # noqa: F401,F403
from . import note_audit as _note_audit

__all__ = _note_audit.__all__
