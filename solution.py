"""Conventional solution entry point for the approval quota feature."""

from approval_quota import *  # noqa: F401,F403
import approval_quota as _approval_quota


for _name, _value in vars(_approval_quota).items():
    if not _name.startswith("_"):
        globals()[_name] = _value


__all__ = [name for name in globals() if not name.startswith("_")]
