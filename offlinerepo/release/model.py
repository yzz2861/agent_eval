# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Pure data model for staged artifacts, object keys and release plans.

No I/O happens here so dependency derivation and visibility ordering can be
unit-tested and reviewed before any object-store interaction.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum

METADATA_PREFIX = "metadata/"
TARGETS_PREFIX = "targets/"
CONTENT_PREFIX = "content/"
POINTER_SUFFIX = ".json"
HASH_ALGORITHM = "sha256"


class ArtifactKind(str, Enum):
    """Discriminates signed TUF metadata from protected target content."""

    METADATA = "metadata"
    TARGET = "target"


@dataclass(frozen=True)
class StagedRelease:
    """Signed metadata bytes plus the full target payload set for a release.

    ``metadata`` maps a role name (``root``, ``targets``, a delegated role,
    ``snapshot`` or ``timestamp``) to its already-signed JSON bytes. Targets
    map a repository-relative path to payload bytes; retaining previously
    published paths keeps old versions referenced by the new metadata.
    """

    metadata: dict[str, bytes]
    targets: dict[str, bytes]


@dataclass(frozen=True)
class ContentObject:
    """An immutable, content-addressed object destined for the object store."""

    key: str
    data: bytes
    digest: str
    length: int
    role: str | None = None
    version: int | None = None
    target_path: str | None = None
    kind: ArtifactKind = ArtifactKind.METADATA


@dataclass(frozen=True)
class UploadRecord:
    """Outcome of staging one content object."""

    key: str
    outcome: str  # "uploaded" | "reused"
    attempts: int


@dataclass(frozen=True)
class SwitchPoint:
    """One atomic visibility change: move a pointer to a content object."""

    name: str
    pointer_key: str
    content_key: str


@dataclass(frozen=True)
class ReleasePlan:
    """A complete, ordered, offline-derived publication plan.

    ``uploads`` lists immutable content objects in dependency order.
    ``switch_order`` lists pointer flips that may run only after every upload
    has succeeded. ``expected_etags`` is the repository generation captured at
    planning time and drives stale-root rejection. ``blockers`` collects every
    condition needing a human; when non-empty the plan must not be executed.
    """

    plan_id: str
    base_root_version: int
    uploads: tuple[ContentObject, ...]
    switch_order: tuple[SwitchPoint, ...]
    expected_etags: dict[str, str]
    retained_keys: frozenset[str]
    garbage_keys: frozenset[str]
    blockers: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_publishable(self) -> bool:
        """Return whether every pre-switch check passed."""
        return not self.blockers

    def role_object(self, role: str) -> ContentObject:
        """Return the staged content object for a metadata role."""
        for obj in self.uploads:
            if obj.role == role:
                return obj
        msg = f"no staged object for role {role!r}"
        raise KeyError(msg)


@dataclass(frozen=True)
class ReleaseReport:
    """Auditable record of what an execution actually did."""

    plan_id: str
    uploads: list[UploadRecord]
    switches: list[str]
    retained_keys: list[str]

    @property
    def reused(self) -> list[str]:
        """Keys that were already present and therefore not rewritten."""
        return [u.key for u in self.uploads if u.outcome == "reused"]

    @property
    def uploaded(self) -> list[str]:
        """Keys that required at least one store write."""
        return [u.key for u in self.uploads if u.outcome == "uploaded"]


def sha256_digest(data: bytes) -> str:
    """Return the hex sha256 digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def metadata_object_key(role: str, version: int) -> str:
    """Return the versioned, immutable metadata object key."""
    return f"{METADATA_PREFIX}{version}.{role}.json"


def metadata_pointer_key(role: str) -> str:
    """Return the mutable non-versioned pointer key for a role."""
    return f"{METADATA_PREFIX}{role}{POINTER_SUFFIX}"


def target_object_key(target_path: str, digest: str) -> str:
    """Return the hash-prefixed, immutable target object key."""
    directory, separator, basename = target_path.rpartition("/")
    return f"{TARGETS_PREFIX}{directory}{separator}{digest}.{basename}"
