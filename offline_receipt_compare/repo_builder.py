"""In-memory TUF repository builder for deterministic test fixtures.

Supports the small subset of TUF needed by the examples: ed25519 top-level
keys, path-pattern delegations and a consistent-snapshot metadata layout.
Everything is held in memory and then written as a verifiable bundle.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from securesystemslib.signer import CryptoSigner

from tuf.api.metadata import (
    SPECIFICATION_VERSION,
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
from tuf.api.serialization.json import JSONSerializer

SPEC_VERSION = ".".join(SPECIFICATION_VERSION)
SERIALIZER = JSONSerializer(compact=False)
TOP_LEVEL = ("root", "targets", "snapshot", "timestamp")


def in_days(days: int, moment: datetime | None = None) -> datetime:
    """Return an expiry datetime ``days`` after ``moment``."""
    base = moment or datetime.now(UTC)
    return base.replace(microsecond=0) + timedelta(days=days)


@dataclass
class DelegationSpec:
    """Declarative description of one delegated targets role."""

    # Declarative description of one delegated targets role.
    name: str
    paths: list[str]
    terminating: bool = False


class FixtureRepository:
    """Build and persist a small TUF repository with delegated roles."""

    # Build and persist a small TUF repository with delegated targets roles.
    def __init__(
        self,
        expiry_base: datetime | None = None,
        consistent_snapshot: bool = True,
    ) -> None:
        """Initialize signers and the top-level targets role."""
        self.expiry_base = expiry_base or datetime.now(UTC)
        self.consistent_snapshot = consistent_snapshot
        self.signers: dict[str, CryptoSigner] = {}
        self.targets: dict[str, Metadata[Targets]] = {}
        self.target_content: dict[str, bytes] = {}
        self.delegations: dict[str, list[DelegationSpec]] = {}
        self._bootstrap_top_level()

    def _bootstrap_top_level(self) -> None:
        """Generate one ed25519 signer per top-level role."""
        for role in TOP_LEVEL:
            self.signers[role] = CryptoSigner.generate_ed25519()
        self.targets["targets"] = Metadata(
            Targets(expires=in_days(30, self.expiry_base))
        )

    def add_target(
        self, path: str, content: bytes, role: str = "targets"
    ) -> TargetFile:
        """Register target content under the given role and return its info."""
        self.target_content[path] = content
        target_file = TargetFile.from_data(path, content, ["sha256"])
        if role not in self.targets:
            self.targets[role] = Metadata(
                Targets(expires=in_days(30, self.expiry_base))
            )
        self.targets[role].signed.targets[path] = target_file
        return target_file

    def add_delegation(self, parent: str, spec: DelegationSpec) -> None:
        """Add a path-pattern delegation and lazily create its signer."""
        self.delegations.setdefault(parent, []).append(spec)
        if spec.name not in self.signers:
            self.signers[spec.name] = CryptoSigner.generate_ed25519()
        if spec.name not in self.targets:
            self.targets[spec.name] = Metadata(
                Targets(expires=in_days(30, self.expiry_base))
            )

    def _build_root(self) -> Metadata[Root]:
        """Build root metadata authorizing the top-level signers."""
        root = Metadata(
            Root(
                expires=in_days(365, self.expiry_base),
                consistent_snapshot=self.consistent_snapshot,
            )
        )
        for role in TOP_LEVEL:
            root.signed.add_key(self.signers[role].public_key, role)
        return root

    def _build_delegations(self, parent: str) -> Delegations | None:
        specs = self.delegations.get(parent)
        if not specs:
            return None
        keys: dict = {}
        roles: dict[str, DelegatedRole] = {}
        for spec in specs:
            signer = self.signers[spec.name]
            keys[signer.public_key.keyid] = signer.public_key
            roles[spec.name] = DelegatedRole(
                name=spec.name,
                keyids=[signer.public_key.keyid],
                threshold=1,
                terminating=spec.terminating,
                paths=list(spec.paths),
            )
        return Delegations(keys=keys, roles=roles)

    def _signed_targets(self) -> dict[str, Metadata[Targets]]:
        """Attach delegations and sign every targets role."""
        signed: dict[str, Metadata[Targets]] = {}
        for role, metadata in self.targets.items():
            delegations = self._build_delegations(role)
            metadata.signed.delegations = delegations
            metadata.sign(self.signers[role])
            signed[role] = metadata
        return signed

    def write(self, metadata_dir: str | Path) -> dict[str, bytes]:
        """Sign all roles and write the verifiable bundle to disk."""
        # Sign every role and write the verifiable metadata bundle to disk.
        metadata_dir = Path(metadata_dir)
        metadata_dir.mkdir(parents=True, exist_ok=True)
        signed_targets = self._signed_targets()
        root = self._build_root()
        root.sign(self.signers["root"])

        snapshot = Metadata(Snapshot(expires=in_days(30, self.expiry_base)))
        for role, metadata in signed_targets.items():
            snapshot.signed.meta[f"{role}.json"] = MetaFile.from_data(
                metadata.signed.version,
                metadata.to_bytes(SERIALIZER),
                ["sha256"],
            )
        snapshot.sign(self.signers["snapshot"])

        timestamp = Metadata(Timestamp(expires=in_days(2, self.expiry_base)))
        timestamp.signed.snapshot_meta = MetaFile.from_data(
            snapshot.signed.version,
            snapshot.to_bytes(SERIALIZER),
            ["sha256"],
        )
        timestamp.sign(self.signers["timestamp"])

        bundle: dict[str, bytes] = {}
        self._write(metadata_dir, "root", root, bundle)
        self._write(metadata_dir, "snapshot", snapshot, bundle)
        self._write(metadata_dir, "timestamp", timestamp, bundle)
        for role, metadata in signed_targets.items():
            self._write(metadata_dir, role, metadata, bundle)
        return bundle

    @staticmethod
    def _write(
        metadata_dir: Path,
        role: str,
        metadata: Metadata,
        bundle: dict[str, bytes],
    ) -> None:
        data = metadata.to_bytes(SERIALIZER)
        bundle[role] = data
        (metadata_dir / f"{role}.json").write_bytes(data)
