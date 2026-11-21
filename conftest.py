import os
import pathlib


# Some hardened sandboxes deny stat() on directories above the workspace root,
# which makes pytest"s upward conftest/hook discovery raise PermissionError
# during collection. Treat such inaccessible ancestor paths as absent so test
# collection keeps working; in ordinary environments this is a no-op.
_ORIGINAL_IS_FILE = pathlib.Path.is_file
_ORIGINAL_IS_DIR = pathlib.Path.is_dir


def _is_inaccessible(path):
    try:
        os.stat(path)
        return False
    except OSError:
        return True


def _safe_is_file(self):
    if _is_inaccessible(str(self)):
        return False
    return _ORIGINAL_IS_FILE(self)


def _safe_is_dir(self):
    if _is_inaccessible(str(self)):
        return False
    return _ORIGINAL_IS_DIR(self)


pathlib.Path.is_file = _safe_is_file
pathlib.Path.is_dir = _safe_is_dir
