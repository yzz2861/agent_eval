"""Project scope binding for exception decisions.

A scope identifies *where* an exception is allowed to apply. It deliberately
does not participate in :class:`SecretIdentity`, so moving a file does not
change the identity of the secret it contains.

An exception is only valid for a finding when the finding's scope is contained
within the scope that was approved. Widening the scope (e.g. an exception
approved for ``acme/payments`` later being used in ``acme``) therefore fails
the containment check and forces a fresh decision.
"""
from dataclasses import dataclass
from functools import lru_cache
from pathlib import PurePosixPath
from typing import Any
from typing import Dict
from typing import Tuple


@lru_cache(maxsize=None)
def _normalize_path(relative_path: str) -> Tuple[str, ...]:
    if relative_path in ('', '.'):
        return ()

    pure = PurePosixPath(relative_path)
    if pure.is_absolute():
        raise ValueError(f'scope path must be relative to the project: {relative_path!r}')

    parts = pure.parts
    if '..' in parts:
        raise ValueError(f'scope path must not escape the project: {relative_path!r}')

    return parts


@dataclass(frozen=True)
class Scope:
    """A project (repository) plus an optional path prefix inside it.

    :param project: stable identifier of the project/repository (e.g. its URL
        or a registered name). Findings from another project never match.
    :param path_prefix: POSIX-style relative directory/file prefix. An empty
        tuple means the whole project.
    """

    project: str
    path_prefix: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.project, str) or not self.project.strip():
            raise ValueError('scope requires a non-empty project identifier')

    @classmethod
    def from_string(cls, project: str, relative_path: str = '') -> 'Scope':
        return cls(project=project, path_prefix=_normalize_path(relative_path))

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Scope':
        raw_path = data.get('path', '')
        if isinstance(raw_path, (list, tuple)):
            path = tuple(str(part) for part in raw_path)
        else:
            path = _normalize_path(str(raw_path))
        return cls(project=str(data['project']), path_prefix=path)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'project': self.project,
            'path': '/'.join(self.path_prefix),
        }

    def contains(self, other: 'Scope') -> bool:
        """Return whether ``other`` is inside ``self``.

        The project must match exactly and the approved path prefix must be a
        prefix of the finding's path. ``acme`` contains ``acme/payments`` but
        not the reverse, which is what makes scope widening fail closed.
        """
        if self.project != other.project:
            return False

        if len(self.path_prefix) > len(other.path_prefix):
            return False

        return other.path_prefix[: len(self.path_prefix)] == self.path_prefix

    def __str__(self) -> str:
        if not self.path_prefix:
            return self.project
        return f'{self.project}/{"/".join(self.path_prefix)}'
