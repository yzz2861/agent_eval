# Sandbox compatibility shim.
#
# The evaluation sandbox denies ``stat()`` on directories above the
# workspace.  pytest 9 walks those parent directories while looking for
# ``conftest.py`` files and treats the resulting ``PermissionError`` as a
# collection error.  Parent directories that cannot be inspected cannot
# contain a loadable ``conftest.py`` either, so treat them like any other
# non-file path instead of aborting collection.
#
# The patch is installed only when a parent directory of the rootdir really
# raises ``PermissionError`` on ``stat()``; in an ordinary checkout every
# parent is readable and this module does nothing.

import pathlib


def _sandbox_blocks_parent_stat():
    current = pathlib.Path(__file__).resolve().parent
    for parent in current.parents:
        try:
            parent.is_file()
        except PermissionError:
            return True
    return False


if _sandbox_blocks_parent_stat():
    _original_is_file = pathlib.Path.is_file

    def _is_file(self):
        try:
            return _original_is_file(self)
        except PermissionError:
            return False

    pathlib.Path.is_file = _is_file

