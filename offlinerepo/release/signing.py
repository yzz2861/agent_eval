# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Offline construction and signing of release input artifacts.

This models the air-gapped signing step: it produces the signed metadata and
target bytes that the (also offline) repository planner consumes. Signing keys
live here only to drive the demonstration; in production they would be held by
the offline signers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import (
    DelegatedRole,
    Delegations,
    Metadata,
    MetaFile,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)

from .model import StagedRelease

HASH_ALGORITHMS = ["sha256"]
PROJECT_ROLE = "project"
TOP_LEVEL = ("root", "targets", "snapshot", "timestamp")
ALL_ROLES = (*TOP_LEVEL, PROJECT_ROLE)


def _in(days: int) -> datetime:
    now = datetime.now(UTC).replace(microsecond=0)
    return now + timedelta(days=days)


@dataclass
class RepoKeyring:
    """In-memory signers for every role (demo stand-in for offline keys)."""

    signers: dict[str, CryptoSigner] = field(default_factory=dict)

    @classmethod
    def generate(cls) -> RepoKeyring:
        """Generate a fresh demo keyring with one signer per role."""
        signers = {name: CryptoSigner.generate_ecdsa() for name in TOP_LEVEL}
        signers[PROJECT_ROLE] = CryptoSigner.generate_ecdsa()
        return cls(signers)


class ReleaseBuilder:
    """Builds signed staged releases, preserving prior target versions.

    The builder retains previously published target content so later releases
    can keep an old version referenced while adding a new one. The planner
    independently decides object-store reuse purely from content hashes.
    """

    def __init__(self, keyring: RepoKeyring) -> None:
        self._keyring = keyring
        self._versions = dict.fromkeys(ALL_ROLES, 0)
        self._targets: dict[str, bytes] = {}

    def _bump(self, name: str) -> int:
        """Increment and return the metadata version for a role."""
        self._versions[name] += 1
        return self._versions[name]

    def _build_root(self, bump: bool) -> Metadata[Root]:
        if bump or self._versions["root"] == 0:
            self._versions["root"] += 1
        root = Metadata(Root(expires=_in(365)))
        root.signed.version = self._versions["root"]
        for name in TOP_LEVEL:
            root.signed.add_key(self._keyring.signers[name].public_key, name)
        root.signed.roles["root"].threshold = 1
        root.sign(self._keyring.signers["root"])
        return root

    def _delegations(self) -> Delegations:
        project_key = self._keyring.signers[PROJECT_ROLE].public_key
        role = DelegatedRole(
            PROJECT_ROLE,
            [project_key.keyid],
            1,
            terminating=True,
            paths=["project/*"],
        )
        return Delegations(
            keys={project_key.keyid: project_key},
            roles={PROJECT_ROLE: role},
        )

    def _sign(self, name: str, md: Metadata[object]) -> None:
        md.sign(self._keyring.signers[name])

    def build_release(
        self,
        changed: dict[str, bytes],
        *,
        bump_root: bool = False,
        removed_paths: frozenset[str] | None = None,
    ) -> StagedRelease:
        """Assemble a fully signed release from changed target content.

        ``changed`` maps a target path to its new bytes. Paths absent here keep
        their previous bytes, so an old target version stays referenced by the
        newly signed metadata. Set ``bump_root`` to rotate the root version
        (signed by the same trusted root key) to exercise root pointer OCC.
        """
        for path in removed_paths or frozenset():
            changed.pop(path, None)
        self._targets.update(changed)
        for path in removed_paths or frozenset():
            self._targets.pop(path, None)

        root = self._build_root(bump_root)

        targets = Metadata(
            Targets(expires=_in(30), delegations=self._delegations())
        )
        project = Metadata(Targets(expires=_in(30)))

        for path, data in self._targets.items():
            info = TargetFile.from_data(path, data, HASH_ALGORITHMS)
            if path.startswith("project/"):
                project.signed.targets[path] = info
            else:
                targets.signed.targets[path] = info

        targets.signed.version = self._bump("targets")
        project.signed.version = self._bump(PROJECT_ROLE)
        self._sign("targets", targets)
        self._sign(PROJECT_ROLE, project)

        snapshot = Metadata(Snapshot(expires=_in(7)))
        snapshot.signed.meta["targets.json"] = MetaFile.from_data(
            targets.signed.version, targets.to_bytes(), HASH_ALGORITHMS
        )
        project_name = f"{PROJECT_ROLE}.json"
        snapshot.signed.meta[project_name] = MetaFile.from_data(
            project.signed.version, project.to_bytes(), HASH_ALGORITHMS
        )
        snapshot.signed.version = self._bump("snapshot")
        self._sign("snapshot", snapshot)

        timestamp = Metadata(Timestamp(expires=_in(1)))
        timestamp.signed.snapshot_meta = MetaFile.from_data(
            snapshot.signed.version, snapshot.to_bytes(), HASH_ALGORITHMS
        )
        timestamp.signed.version = self._bump("timestamp")
        self._sign("timestamp", timestamp)

        return StagedRelease(
            metadata={
                "root": root.to_bytes(),
                "targets": targets.to_bytes(),
                PROJECT_ROLE: project.to_bytes(),
                "snapshot": snapshot.to_bytes(),
                "timestamp": timestamp.to_bytes(),
            },
            targets=dict(self._targets),
        )
