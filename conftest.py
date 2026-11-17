"""Local-only pytest bootstrap shim.

The sandbox denies ``stat()`` on directories above the workspace root, but
pytest 9 walks parent directories while looking for ``conftest.py`` files.
Treat those denied paths as absent so test collection can proceed normally.
"""
import pathlib


_orig_is_file = pathlib.PosixPath.is_file


def _safe_is_file(self):
    try:
        return _orig_is_file(self)
    except PermissionError:
        return False


pathlib.PosixPath.is_file = _safe_is_file
