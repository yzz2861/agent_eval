"""Sandbox-friendly pytest bootstrap.

The evaluation sandbox denies stat() on directories above this repository,
while pytest conftest discovery walks parent directories unconditionally.
Treat inaccessible parent paths as "no conftest here" so collection stays
inside the repository. In a normal checkout this patch is a no-op.
"""

import pathlib

_original_is_file = pathlib.Path.is_file


def _safe_is_file(self):
    try:
        return _original_is_file(self)
    except PermissionError:
        return False


pathlib.Path.is_file = _safe_is_file
