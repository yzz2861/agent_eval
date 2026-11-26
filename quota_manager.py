"""Compatibility entry point; implementation lives in approval_quota."""

from approval_quota import *  # noqa: F401,F403
import approval_quota as _core

for _name, _value in vars(_core).items():
    if not _name.startswith("_"):
        globals()[_name] = _value

__all__ = [name for name in globals() if not name.startswith("_")]

