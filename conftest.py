"""Pytest collection shim for sandboxed workspaces

When the parent directories of the workspace are not stat()-able,
pytest's package collection raises PermissionError while walking up
from tests/. Treat paths outside the workspace as inaccessible
directories so collection stays inside the repository root.

"""

import os
import stat as stat_mod
from pathlib import Path


_ROOT = Path(__file__).resolve().parent

_orig_stat = Path.stat


def _stat(self, *args, **kwargs):
    try:
        return _orig_stat(self, *args, **kwargs)
    except (PermissionError, OSError):
        try:
            self.relative_to(_ROOT)
        except (ValueError, OSError):
            return os.stat_result((stat_mod.S_IFDIR | 0o755, 0, 0,
                                   1, 0, 0, 0, 0, 0, 0))
        raise


Path.stat = _stat


def pytest_ignore_collect(collection_path, config):
    try:
        collection_path.relative_to(_ROOT)
    except (ValueError, PermissionError, OSError):
        return True

    try:
        os.stat(collection_path)
    except (PermissionError, OSError):
        return True

    return None
