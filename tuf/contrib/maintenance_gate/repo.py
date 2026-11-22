"""Offline authorization repository for the maintenance gate.

This is the *publisher* side of the gate.  It builds a tiny TUF repository
whose only purpose is to carry signed pause and resume authorization slips as
delegated targets metadata.

Each call to AuthorizationRepository.publish produces one coherent TUF release
(an epoch): timestamp and snapshot are bumped together and every targets role
referenced by snapshot is pinned by version, length and hash.  The device gate
can therefore tell a complete, verifiable release apart from a half set that
arrived out of order on a maintenance channel.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import PurePosixPath

from securesystemslib.signer import CryptoSigner

from tuf.api.metadata import (
    DelegatedRole,
    Delegations,
    Metadata,
    MetaFile,
    Role,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer
from tuf.contrib.maintenance_gate.model import ACTION_FIELD, PAUSE, RESUME

SERIALIZER = JSONSerializer(validate=True)


def _now_plus(days: int) -> datetime:
    """Return a timezone aware expiry date days in the future."""
    return datetime.now(UTC) + timedelta(days=days)


@dataclass(frozen=True)
class DelegationSpec:
    """Declaration of one delegated maintenance role.

    Attributes:
        name: Delegated TUF role name.
        paths: Target path patterns the role is trusted to speak for.
        terminating: Whether a target lookup stops at this role.
    """

    name: str
    paths: list[str]
    terminating: bool = False


@dataclass(frozen=True)
class Statement:
    """A publisher request for one pause/resume authorization slip."""

    role: str
    action: str
    targets: frozenset[str]

    @staticmethod
    def pause(role: str, *targets: str) -> Statement:
        """Build a pause statement for targets signed by role."""
        return Statement(role, PAUSE, frozenset(targets))

    @staticmethod
    def resume(role: str, *targets: str) -> Statement:
        """Build a resume statement for targets signed by role."""
        return Statement(role, RESUME, frozenset(targets))


class AuthorizationRepository:
    """Builds signed, mutually consistent TUF authorization releases.

    The repository keeps every role version it ever produced, mirroring how an
    offline authorization authority would keep an audit trail.  Devices only
    ever receive the serialized bytes, exactly like material arriving on a
    maintenance channel.
    """

    def __init__(
        self,
        delegations: list[DelegationSpec],
        *,
        expiry_days: int = 365,
    ) -> None:
        self.expiry = _now_plus(expiry_days)
        self.delegations = delegations

        # One ed25519 signing key per TUF role.
        self.signers: dict[str, CryptoSigner] = {}
        for role in ("root", "timestamp", "snapshot", "targets"):
            self.signers[role] = CryptoSigner.generate_ed25519()
        for spec in delegations:
            self.signers[spec.name] = CryptoSigner.generate_ed25519()

        # Latest serialized bytes per role, and the full per-epoch history.
        self.role_bytes: dict[str, bytes] = {}
        self.epochs: list[dict[str, bytes]] = []

        root = self._build_root()
        self.role_bytes["root"] = self._sign(root, "root")

    def _build_root(self) -> Root:
        """Assemble root with keys for top level and delegated roles."""
        keys = {
            signer.public_key.keyid: signer.public_key
            for signer in self.signers.values()
        }
        roles = {
            name: Role([self.signers[name].public_key.keyid], 1)
            for name in ("root", "timestamp", "snapshot", "targets")
        }
        return Root(
            version=1,
            expires=self.expiry,
            keys=keys,
            roles=roles,
        )

    def _build_targets(self) -> Targets:
        """Build the top level targets role and its delegation graph."""
        delegated_roles = {}
        delegation_keys = {}
        for spec in self.delegations:
            signer = self.signers[spec.name]
            delegation_keys[signer.public_key.keyid] = signer.public_key
            delegated_roles[spec.name] = DelegatedRole(
                name=spec.name,
                keyids=[signer.public_key.keyid],
                threshold=1,
                terminating=spec.terminating,
                paths=list(spec.paths),
            )
        delegations = Delegations(keys=delegation_keys, roles=delegated_roles)
        return Targets(version=1, expires=self.expiry, delegations=delegations)

    def _sign(self, signed: object, role: str) -> bytes:
        """Wrap signed in metadata, sign it and return canonical bytes."""
        metadata: Metadata = Metadata(signed)  # type: ignore[arg-type]
        metadata.sign(self.signers[role])
        return metadata.to_bytes(SERIALIZER)

    def _delegated_targets(
        self, role: str, version: int, statements: list[Statement]
    ) -> Targets:
        """Build one delegated role targets metadata for an epoch."""
        target_files = {}
        for statement in statements:
            if statement.role != role:
                continue
            for path in statement.targets:
                target_files[path] = self._auth_target_file(
                    path, statement.action
                )
        return Targets(
            version=version, expires=self.expiry, targets=target_files
        )

    @staticmethod
    def _auth_target_file(path: str, action: str) -> TargetFile:
        """Create a target entry carrying a maintenance action in custom."""
        # The maintenance gate authorizes by target path; content hashes are
        # still required by TUF, so record a stable placeholder payload hash.
        payload = f"authorization::{path}".encode()
        target_file = TargetFile.from_data(path, payload, ["sha256"])
        target_file.unrecognized_fields["custom"] = {ACTION_FIELD: action}
        return target_file

    def publish(self, statements: list[Statement]) -> dict[str, bytes]:
        """Publish one coherent authorization release.

        Every delegated role referenced by the repository gets a fresh targets
        version carrying the statements addressed to it.  Timestamp, snapshot
        and all targets metadata are bumped and signed together so the
        resulting bytes form one self-consistent TUF epoch.

        Args:
            statements: Pause/resume slips to distribute over delegated roles.

        Returns:
            Mapping of role name to signed metadata bytes, including timestamp,
            snapshot, targets and every delegated role.
        """
        epoch_number = len(self.epochs) + 1
        release: dict[str, bytes] = {}

        # The top level targets role only carries the delegation graph.
        release["targets"] = self._sign(self._build_targets(), "targets")

        role_versions: dict[str, int] = {}
        for spec in self.delegations:
            previous = (
                Metadata.from_bytes(self.role_bytes[spec.name]).signed
                if spec.name in self.role_bytes
                else None
            )
            version = (previous.version + 1) if previous else 1
            role_versions[spec.name] = version
            release[spec.name] = self._sign(
                self._delegated_targets(spec.name, version, statements),
                spec.name,
            )

        snapshot = self._build_snapshot(release, role_versions)
        release["snapshot"] = self._sign(snapshot, "snapshot")

        timestamp = self._build_timestamp(release["snapshot"], epoch_number)
        release["timestamp"] = self._sign(timestamp, "timestamp")

        self.role_bytes.update(release)
        self.epochs.append(dict(release))
        return release

    def _build_snapshot(
        self,
        release: dict[str, bytes],
        role_versions: dict[str, int],
    ) -> Snapshot:
        """Pin every targets role of the epoch by version, length and hash."""
        previous_version = (
            Metadata.from_bytes(self.role_bytes["snapshot"]).signed.version
            if "snapshot" in self.role_bytes
            else 0
        )
        meta = {
            "targets.json": MetaFile.from_data(
                1, release["targets"], ["sha256"]
            )
        }
        for spec in self.delegations:
            meta[f"{spec.name}.json"] = MetaFile.from_data(
                role_versions[spec.name], release[spec.name], ["sha256"]
            )
        return Snapshot(
            version=previous_version + 1, expires=self.expiry, meta=meta
        )

    def _build_timestamp(
        self, snapshot_bytes: bytes, epoch_number: int
    ) -> Timestamp:
        """Pin the snapshot of this epoch; timestamp version equals epoch."""
        snapshot_meta = MetaFile.from_data(
            epoch_number, snapshot_bytes, ["sha256"]
        )
        return Timestamp(
            version=epoch_number,
            expires=self.expiry,
            snapshot_meta=snapshot_meta,
        )

    @property
    def root_bytes(self) -> bytes:
        """Return the trusted root metadata used to bootstrap a device."""
        return self.role_bytes["root"]

    @staticmethod
    def tamper(data: bytes) -> bytes:
        """Flip a byte to simulate corrupted or tampered channel material."""
        raw = bytearray(data)
        raw[0] ^= 0x01
        return bytes(raw)


def target_path(*parts: str) -> str:
    """Join package name parts into a canonical POSIX target path."""
    return PurePosixPath(*parts).as_posix()
