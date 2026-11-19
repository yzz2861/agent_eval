#
# SPDX-License-Identifier: Apache-2.0
"""Path normalisation, repository-prefix rewriting and path-tree helpers.

The takeover layer must keep working while the repository layout is being
split and moved.  Two historical path names can therefore refer to the same
file.  ``PathMap`` records those renames so a finding carried over from an old
report can still be located after a move, and so ownership can be resolved
against either the old or the new tree.
"""
import os


def normalize_path(path):
    """Return a canonical, repository-relative, POSIX style path.

    Absolute paths and Windows separators are accepted so reports produced on
    different machines or operating systems remain comparable.

    :param path: Raw path as found in a report or policy file.
    :return: Normalised path using ``/`` separators with no leading ``./``.
    """
    if path is None:
        return ""
    text = str(path).replace("\\", "/").strip()
    while text.startswith("/"):
        text = text[1:]
    # Collapse redundant separators and ``..`` / ``.`` segments without
    # touching the filesystem.
    text = os.path.normpath(text).replace(os.sep, "/")
    if text == ".":
        return ""
    return text


def is_within(directory, path):
    """Return True when *path* is *directory* itself or located below it.

    Both arguments are normalised first, so trailing slashes and ``./``
    prefixes do not affect the result.

    :param directory: Owning directory (prefix) from the policy.
    :param path: File path to test.
    :return: True if the file belongs to the directory tree.
    """
    base = normalize_path(directory)
    target = normalize_path(path)
    if not base:
        return True
    if target == base:
        return True
    return target.startswith(base + "/")


class PathMap:
    """Repository of path renames discovered while the monorepo is split.

    Mappings are expressed as ``old_prefix -> new_prefix``.  When a finding is
    only known under an old path, :meth:`rewrite` yields the current path.
    Rewriting only applies when the old prefix actually matches, so unmoved
    files are returned untouched.
    """

    def __init__(self, mappings=None):
        # Longest old prefix first so nested mappings win over broad ones.
        self._mappings = sorted(
            (
                (normalize_path(old), normalize_path(new))
                for old, new in (mappings or [])
            ),
            key=lambda pair: len(pair[0]),
            reverse=True,
        )

    @classmethod
    def from_dict(cls, data):
        """Build a map from the ``path_moves`` section of a policy document.

        :param data: Mapping of old prefix to new prefix (may be empty).
        :return: A populated :class:`PathMap`.
        """
        data = data or {}
        return cls(list(data.items()))

    def rewrite(self, path):
        """Rewrite an old path into its current repository location.

        :param path: Path that may predate a repository split.
        :return: The current path when a mapping matches, otherwise the
                 normalised input path.
        """
        normalized = normalize_path(path)
        for old_prefix, new_prefix in self._mappings:
            if normalized == old_prefix or normalized.startswith(
                old_prefix + "/"
            ):
                suffix = normalized[len(old_prefix) :].lstrip("/")
                return (
                    new_prefix
                    if not suffix
                    else normalize_path(new_prefix + "/" + suffix)
                )
        return normalized

    def moved(self, path):
        """Return True when *path* is affected by a recorded rename."""
        return self.rewrite(path) != normalize_path(path)
