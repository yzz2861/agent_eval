"""Compatibility import path for the assignment planner."""

from . import assignment as _core


__all__ = [name for name in dir(_core) if not name.startswith("_")]
for _name in __all__:
    globals()[_name] = getattr(_core, _name)
