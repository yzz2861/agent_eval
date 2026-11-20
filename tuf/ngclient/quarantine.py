# Copyright 2026, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Local, caller-managed quarantine policy for target content.

This module lets application integrators block delivery of specific
previously valid target content (for example after an incident response
team flags an artifact digest), without disabling TUF verification:
targets are still verified against signed metadata exactly as before,
and the quarantine policy is applied as an additional local check when
content is about to be delivered to the caller.

Properties of the policy:
  * Quarantine entries are scoped to a repository (identified by its
    metadata base URL) and match on target content identity (hash
    algorithm and digest), never on the target path: renaming a target
    on the repository does not make quarantined bytes deliverable again.
  * The policy is provided by the caller through a trusted, local entry
    point (``Updater.set_quarantine_policy()`` or
    ``Updater.load_quarantine_policy()``): the updater never fetches
    policy from the network and no external credentials are involved.
  * The policy is immutable and replaced atomically: each
    ``find_cached_target()``/``download_target()`` call uses the policy
    snapshot that was active when the call started. Calls already in
    progress (old handles) finish under the old snapshot; only new
    attempts observe the new policy.
  * If loading a new policy fails, the previously active policy remains
    in effect and the failure is logged.

The serialized policy format is JSON::

    {
      "version": 1,
      "repositories": {
        "https://example.com/metadata/": {
          "sha256": ["<hex digest>", ...]
        }
      }
    }
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from tuf.api import exceptions

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

logger = logging.getLogger(__name__)

POLICY_VERSION = 1


class QuarantinePolicyError(Exception):
    """Quarantine policy could not be loaded.

    Raised when caller-provided policy data cannot be parsed or
    validated. The previously active policy remains in effect.
    """


class QuarantinedTargetError(exceptions.RepositoryError):
    """Target content is quarantined by local policy: not delivered."""


class QuarantinePolicy:
    """Immutable set of quarantined target content identities.

    Args:
        entries: Mapping of repository metadata base URL to a mapping of
            hash algorithm to an iterable of hex digests, e.g.
            ``{"https://example.com/metadata/": {"sha256": ["ab..."]}}``.
            ``None`` (the default) creates an empty policy that
            quarantines nothing.
    """

    def __init__(
        self,
        entries: Mapping[str, Mapping[str, Iterable[str]]] | None = None,
    ):
        normalized: dict[str, dict[str, frozenset[str]]] = {}
        for repository, algorithms in (entries or {}).items():
            repo_key = _ensure_trailing_slash(repository)
            repo_entries = normalized.setdefault(repo_key, {})
            for algorithm, digests in algorithms.items():
                existing = repo_entries.setdefault(algorithm, frozenset())
                repo_entries[algorithm] = existing | frozenset(
                    d.lower() for d in digests
                )
        self._entries = normalized

    def __len__(self) -> int:
        """Number of quarantined digests across all repositories."""
        return sum(
            len(digests)
            for algorithms in self._entries.values()
            for digests in algorithms.values()
        )

    def __repr__(self) -> str:
        repositories = len(self._entries)
        return (
            f"QuarantinePolicy(repositories={repositories}, "
            f"digests={len(self)})"
        )

    def is_quarantined(
        self, repository: str, hashes: Mapping[str, str]
    ) -> bool:
        """Check whether content is quarantined for ``repository``.

        Args:
            repository: Metadata base URL identifying the repository.
            hashes: Hash algorithm to hex digest mapping of the content,
                e.g. ``TargetFile.hashes``.

        Returns:
            True if any of the given content digests is quarantined in
            the scope of ``repository``.
        """
        repo_entries = self._entries.get(_ensure_trailing_slash(repository))
        if repo_entries is None:
            return False
        return any(
            digest.lower() in repo_entries.get(algorithm, frozenset())
            for algorithm, digest in hashes.items()
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> QuarantinePolicy:
        """Deserialize a quarantine policy from caller-provided bytes.

        Args:
            data: Serialized policy (JSON, see module docstring).

        Raises:
            QuarantinePolicyError: Data is not a valid policy.

        Returns:
            New immutable ``QuarantinePolicy``.
        """
        try:
            raw: Any = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise QuarantinePolicyError(
                f"Quarantine policy is not valid JSON: {e}"
            ) from e

        if not isinstance(raw, dict):
            raise QuarantinePolicyError(
                "Quarantine policy must be a JSON object"
            )

        version = raw.get("version")
        if version != POLICY_VERSION:
            raise QuarantinePolicyError(
                f"Unsupported quarantine policy version {version!r}, "
                f"expected {POLICY_VERSION}"
            )

        repositories = raw.get("repositories")
        if not isinstance(repositories, dict):
            raise QuarantinePolicyError(
                "Quarantine policy 'repositories' must be an object"
            )

        entries: dict[str, dict[str, list[str]]] = {}
        for repository, algorithms in repositories.items():
            if not isinstance(repository, str) or not isinstance(
                algorithms, dict
            ):
                raise QuarantinePolicyError(
                    "Quarantine policy repositories must map repository "
                    "URL strings to objects of hash algorithms"
                )
            for algorithm, digests in algorithms.items():
                if (
                    not isinstance(algorithm, str)
                    or not isinstance(digests, list)
                    or not all(isinstance(d, str) and d for d in digests)
                ):
                    raise QuarantinePolicyError(
                        f"Quarantine policy entry for {repository!r} must "
                        "map hash algorithm names to lists of non-empty "
                        "hex digest strings"
                    )
            entries[repository] = algorithms

        return cls(entries)


def _ensure_trailing_slash(url: str) -> str:
    """Return url guaranteed to end in a slash."""
    return url if url.endswith("/") else f"{url}/"
