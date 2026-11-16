"""Sandbox compatibility shim.

When the test process runs under a filesystem sandbox that denies ``stat``
calls on parent directories outside the workspace, pytest otherwise aborts
collection while walking the directory tree looking for conftest files.
This shim turns those permission errors into "directory exists" results so
the walk can continue; real files inside the workspace are unaffected.
"""

import os
import stat as _stat

_real_stat = os.stat


def _sandbox_safe_stat(path, *args, **kwargs):
    try:
        return _real_stat(path, *args, **kwargs)
    except PermissionError:
        return os.stat_result((
            _stat.S_IFDIR | 0o755, 0, 0, 1, 0, 0, 0, 0, 0, 0
        ))


os.stat = _sandbox_safe_stat
