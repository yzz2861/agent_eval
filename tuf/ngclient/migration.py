# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Offline migration checker for ngclient device fleets.

This module helps maintenance crews plan a staged migration of large device
fleets to a new release channel (repository). Devices in the field carry
different trusted roots, different locally cached (delegation) state and
different clocks: the checker determines, for each class of device, how far
the TUF client workflow can safely advance against a candidate metadata set
-- and which devices first need an intermediate root that is still pending
approval.

The checker is fully offline and read-only: it verifies everything in
memory through `TrustedMetadataSet` and never touches the device's
on-disk metadata cache or any network resource.

Same-version metadata carried over from the old channel in the candidate
set is never trusted blindly: it is cross-checked against the trusted
chain (root signatures, timestamp snapshot meta and snapshot meta) that
was built from the device's own trusted root.

Example::

    candidate = MigrationCandidate(
        roots=[root_v2_bytes, root_v3_bytes],
        timestamp=timestamp_bytes,
        snapshot=snapshot_bytes,
        targets={"targets": targets_bytes, "role1": role1_bytes},
        legacy_metadata={"targets": old_channel_targets_bytes},
    )
    checker = MigrationChecker(candidate)
    report = checker.check(
        DeviceClass(
            name="fleet-a",
            trusted_root=root_v1_bytes,
            reference_time=datetime.now(UTC),
        )
    )
    if report.blocker and report.blocker.missing_root_version:
        print("needs intermediate root", report.blocker.missing_root_version)
"""

from __future__ import annotations

import contextlib
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from tuf.api import exceptions
from tuf.api.dsse import SimpleEnvelope
from tuf.api.metadata import Metadata, Root, Snapshot, Targets, Timestamp
from tuf.ngclient._internal.trusted_metadata_set import TrustedMetadataSet
from tuf.ngclient.config import EnvelopeType

if TYPE_CHECKING:
    from datetime import datetime

    from tuf.api.metadata import Signed

logger = logging.getLogger(__name__)


@dataclass
class DeviceClass:
    """State carried by a class of devices to be migrated.

    Args:
        name: Identifier of the device class (used in reports).
        trusted_root: Trusted root metadata bytes found on the device.
        reference_time: The device clock: all expiry checks are made
            against this time.
        cached_metadata: Locally cached metadata (role name to bytes) the
            device carries in its metadata dir, e.g. delegated targets it
            already verified earlier. Replayed like `Updater` does:
            failures are ignored in favour of candidate metadata.
    """

    name: str
    trusted_root: bytes
    reference_time: datetime
    cached_metadata: dict[str, bytes] = field(default_factory=dict)


@dataclass
class MigrationCandidate:
    """Metadata set a device class is checked against.

    Args:
        roots: All candidate root versions (any order, any channel).
        timestamp: Candidate timestamp metadata.
        snapshot: Candidate snapshot metadata.
        targets: Candidate targets metadata, role name to bytes. Must
            contain top-level `targets`; delegated roles are loaded
            in delegation order automatically.
        legacy_metadata: Same-version metadata from the old channel that
            is part of the candidate set. It is cross-checked against the
            trusted chain, never trusted directly.
    """

    roots: list[bytes] = field(default_factory=list)
    timestamp: bytes | None = None
    snapshot: bytes | None = None
    targets: dict[str, bytes] = field(default_factory=dict)
    legacy_metadata: dict[str, bytes] = field(default_factory=dict)


@dataclass
class Evidence:
    """One verified step of the simulated migration."""

    step: str
    role: str
    version: int
    detail: str


@dataclass
class Blocker:
    """Reason a device class cannot migrate further.

    Args:
        step: Workflow step that failed, e.g. `root` or
            `timestamp`.
        reason: Human readable failure description.
        missing_root_version: If set, the intermediate root version that
            must be supplied (pending approval) before this device class
            can migrate.
    """

    step: str
    reason: str
    missing_root_version: int | None = None


@dataclass
class LegacyCheck:
    """Result of cross-checking old-channel metadata against the chain."""

    role: str
    ok: bool
    detail: str


@dataclass
class MigrationReport:
    """Outcome of checking one device class against a candidate set."""

    device: str
    can_migrate: bool
    reached_step: str
    root_version: int | None
    evidence: list[Evidence] = field(default_factory=list)
    blocker: Blocker | None = None
    legacy_checks: list[LegacyCheck] = field(default_factory=list)

    @property
    def needs_intermediate_root(self) -> int | None:
        """Intermediate root version blocking migration, if any."""
        if self.blocker is not None:
            return self.blocker.missing_root_version
        return None


class MigrationChecker:
    """Offline, read-only migration checker for ngclient fleets.

    Simulates the TUF detailed client workflow in memory for each device
    class, using the device's own trusted root, cached metadata and clock.
    No device state is modified.
    """

    def __init__(
        self,
        candidate: MigrationCandidate,
        envelope_type: EnvelopeType = EnvelopeType.METADATA,
    ):
        self._candidate = candidate
        self._envelope_type = envelope_type

    def check(self, device: DeviceClass) -> MigrationReport:
        """Simulate migration of `device` through the candidate set.

        Returns a report describing how far the device class can safely
        migrate, the blocking point if any, and the evidence for every
        verified step.
        """
        report = MigrationReport(
            device=device.name,
            can_migrate=False,
            reached_step="none",
            root_version=None,
        )

        try:
            trusted_set = TrustedMetadataSet(
                device.trusted_root, self._envelope_type
            )
        except exceptions.RepositoryError as e:
            report.blocker = Blocker(
                Root.type, f"trusted root failed to load: {e}"
            )
            return report

        trusted_set.reference_time = device.reference_time
        # Roots verified so far: the device trusted root plus every root
        # loaded from the candidate set
        loaded_roots = [trusted_set.root]
        report.evidence.append(
            Evidence(
                "bootstrap",
                Root.type,
                loaded_roots[0].version,
                "device trusted root loaded and self-signed",
            )
        )

        if not self._update_root_chain(trusted_set, report, loaded_roots):
            report.root_version = trusted_set.root.version
            report.reached_step = Root.type
            return report
        report.root_version = trusted_set.root.version
        report.reached_step = Root.type

        # Targets metadata loaded during this run, delegator lookup source
        loaded_targets: dict[str, Targets] = {}
        self._replay_cached_timestamp(trusted_set, device)

        if not self._update_top_level(
            trusted_set, device, report, loaded_targets
        ):
            report.root_version = trusted_set.root.version
            return report

        self._check_legacy(trusted_set, loaded_roots, report)
        report.can_migrate = all(c.ok for c in report.legacy_checks)
        return report

    def _load_signed(self, data: bytes) -> Signed:
        """Deserialize metadata bytes into a `Signed` object."""
        if self._envelope_type is EnvelopeType.SIMPLE:
            return SimpleEnvelope.from_bytes(data).get_signed()
        return Metadata.from_bytes(data).signed

    def _update_root_chain(
        self,
        trusted_set: TrustedMetadataSet,
        report: MigrationReport,
        loaded_roots: list[Root],
    ) -> bool:
        """Apply candidate roots in version order.

        Returns False (and sets a blocker) if the chain cannot be
        completed with the candidate set.
        """
        pending: dict[int, bytes] = {}
        for data in self._candidate.roots:
            try:
                version = self._load_signed(data).version
            except exceptions.RepositoryError as e:
                report.blocker = Blocker(
                    Root.type, f"candidate root failed to parse: {e}"
                )
                return False
            pending[version] = data

        while trusted_set.root.version + 1 in pending:
            version = trusted_set.root.version + 1
            try:
                trusted_set.update_root(pending.pop(version))
            except exceptions.RepositoryError as e:
                report.blocker = Blocker(
                    Root.type, f"root v{version} failed verification: {e}"
                )
                return False
            loaded_roots.append(trusted_set.root)
            report.evidence.append(
                Evidence(
                    Root.type,
                    Root.type,
                    version,
                    f"root v{version} verified by v{version - 1} chain "
                    "and self-signed",
                )
            )

        unreachable = [v for v in pending if v > trusted_set.root.version]
        if unreachable:
            missing = trusted_set.root.version + 1
            report.blocker = Blocker(
                Root.type,
                f"candidate set contains root v{min(unreachable)}+ but "
                f"intermediate root v{missing} is missing: it must be "
                "supplied (pending approval) before migration",
                missing_root_version=missing,
            )
            return False
        return True

    @staticmethod
    def _replay_cached_timestamp(
        trusted_set: TrustedMetadataSet, device: DeviceClass
    ) -> None:
        """Replay device-cached timestamp like `Updater` does.

        Failures are ignored: candidate metadata is authoritative.
        """
        data = device.cached_metadata.get(Timestamp.type)
        if data is None:
            return
        with contextlib.suppress(exceptions.RepositoryError):
            trusted_set.update_timestamp(data)

    @staticmethod
    def _replay_cached_snapshot(
        trusted_set: TrustedMetadataSet, device: DeviceClass
    ) -> None:
        """Replay device-cached snapshot as intermediate metadata."""
        data = device.cached_metadata.get(Snapshot.type)
        if data is None:
            return
        with contextlib.suppress(exceptions.RepositoryError, RuntimeError):
            trusted_set.update_snapshot(data, trusted=True)

    def _replay_cached_targets(
        self,
        trusted_set: TrustedMetadataSet,
        device: DeviceClass,
        report: MigrationReport,
        loaded_targets: dict[str, Targets],
    ) -> None:
        """Replay device-cached targets metadata.

        Only metadata still matching the final snapshot is reusable:
        failures are ignored as candidate metadata is authoritative.
        """
        cached = device.cached_metadata
        for role in self._delegation_order(cached):
            delegator = self._find_delegator(loaded_targets, role)
            if delegator is None:
                continue
            try:
                if role == Targets.type:
                    tg = trusted_set.update_targets(cached[role])
                else:
                    tg = trusted_set.update_delegated_targets(
                        cached[role], role, delegator
                    )
            except (exceptions.RepositoryError, RuntimeError):
                continue
            loaded_targets[role] = tg
            report.evidence.append(
                Evidence(
                    "cache",
                    role,
                    tg.version,
                    "device-cached metadata replayed",
                )
            )

    @staticmethod
    def _delegation_order(metadata: dict[str, bytes]) -> list[str]:
        """Return targets role names, top-level first, in given order."""
        roles = [
            r for r in metadata if r not in (Timestamp.type, Snapshot.type)
        ]
        roles.sort(key=lambda r: r != Targets.type)
        return roles

    @staticmethod
    def _find_delegator(
        loaded_targets: dict[str, Targets], role: str
    ) -> str | None:
        """Find the already loaded delegator that delegates to a role."""
        if role == Targets.type:
            return Root.type
        for name, targets in loaded_targets.items():
            if targets.delegations is None:
                continue
            if role in (targets.delegations.roles or {}):
                return name
        return None

    def _update_top_level(
        self,
        trusted_set: TrustedMetadataSet,
        device: DeviceClass,
        report: MigrationReport,
        loaded_targets: dict[str, Targets],
    ) -> bool:
        """Apply candidate timestamp, snapshot and targets metadata."""
        if not self._update_timestamp(trusted_set, report):
            return False
        self._replay_cached_snapshot(trusted_set, device)
        if not self._update_snapshot(trusted_set, report):
            return False
        return self._update_targets(trusted_set, device, report, loaded_targets)

    def _update_timestamp(
        self, trusted_set: TrustedMetadataSet, report: MigrationReport
    ) -> bool:
        """Apply candidate timestamp metadata."""
        if self._candidate.timestamp is None:
            report.blocker = Blocker(
                Timestamp.type, "no candidate timestamp metadata provided"
            )
            return False
        try:
            ts = trusted_set.update_timestamp(self._candidate.timestamp)
        except exceptions.RepositoryError as e:
            report.blocker = Blocker(Timestamp.type, str(e))
            return False
        report.evidence.append(
            Evidence(
                Timestamp.type,
                Timestamp.type,
                ts.version,
                "timestamp verified against trusted root, not expired "
                "at device clock",
            )
        )
        report.reached_step = Timestamp.type
        return True

    def _update_snapshot(
        self, trusted_set: TrustedMetadataSet, report: MigrationReport
    ) -> bool:
        """Apply candidate snapshot metadata."""
        if self._candidate.snapshot is None:
            report.blocker = Blocker(
                Snapshot.type, "no candidate snapshot metadata provided"
            )
            return False
        try:
            sn = trusted_set.update_snapshot(self._candidate.snapshot)
        except exceptions.RepositoryError as e:
            report.blocker = Blocker(Snapshot.type, str(e))
            return False
        report.evidence.append(
            Evidence(
                Snapshot.type,
                Snapshot.type,
                sn.version,
                "snapshot verified against timestamp meta (hashes, "
                "length, version)",
            )
        )
        report.reached_step = Snapshot.type
        return True

    def _update_targets(
        self,
        trusted_set: TrustedMetadataSet,
        device: DeviceClass,
        report: MigrationReport,
        loaded_targets: dict[str, Targets],
    ) -> bool:
        """Apply cached and candidate targets metadata."""
        pending = dict(self._candidate.targets)
        data = pending.pop(Targets.type, None)
        if data is not None:
            try:
                tg = trusted_set.update_targets(data)
            except exceptions.RepositoryError as e:
                report.blocker = Blocker(Targets.type, str(e))
                return False
            loaded_targets[Targets.type] = tg
            report.evidence.append(
                Evidence(
                    Targets.type,
                    Targets.type,
                    tg.version,
                    "targets verified against snapshot meta and delegator root",
                )
            )

        # Cached targets can only be replayed once the delegators they
        # depend on are loaded
        self._replay_cached_targets(trusted_set, device, report, loaded_targets)

        while pending:
            progressed = False
            for role in list(pending):
                delegator = self._find_delegator(loaded_targets, role)
                if delegator is None:
                    continue
                data = pending.pop(role)
                try:
                    tg = trusted_set.update_delegated_targets(
                        data, role, delegator
                    )
                except exceptions.RepositoryError as e:
                    report.blocker = Blocker(role, str(e))
                    return False
                loaded_targets[role] = tg
                report.evidence.append(
                    Evidence(
                        Targets.type,
                        role,
                        tg.version,
                        f"{role} verified against snapshot meta and "
                        f"delegator {delegator}",
                    )
                )
                progressed = True
            if not progressed:
                report.blocker = Blocker(
                    Targets.type,
                    "no delegator found in candidate set for roles: "
                    + ", ".join(sorted(pending)),
                )
                return False
        report.reached_step = Targets.type
        return True

    def _check_legacy(
        self,
        trusted_set: TrustedMetadataSet,
        loaded_roots: list[Root],
        report: MigrationReport,
    ) -> None:
        """Cross-check old-channel metadata against the trusted chain."""
        for role, data in self._candidate.legacy_metadata.items():
            try:
                detail = self._check_legacy_item(
                    trusted_set, loaded_roots, role, data
                )
                report.legacy_checks.append(LegacyCheck(role, True, detail))
                report.evidence.append(Evidence("legacy", role, -1, detail))
            except (exceptions.RepositoryError, ValueError) as e:
                report.legacy_checks.append(
                    LegacyCheck(role, False, f"legacy {role} rejected: {e}")
                )

    def _check_legacy_item(
        self,
        trusted_set: TrustedMetadataSet,
        loaded_roots: list[Root],
        role: str,
        data: bytes,
    ) -> str:
        """Verify one old-channel metadata item against the chain."""
        if role == Root.type:
            signed = self._load_signed(data)
            for chain_root in loaded_roots:
                if signed.to_dict() == chain_root.to_dict():
                    return (
                        f"legacy root v{signed.version} is part of the "
                        "verified root chain"
                    )
            raise ValueError(
                "legacy root is not part of the verified root chain"
            )

        if role == Timestamp.type:
            md = Metadata.from_bytes(data)
            trusted_set.root.verify_delegate(
                Timestamp.type, md.signed_bytes, md.signatures
            )
            return (
                f"legacy timestamp v{md.signed.version} signatures "
                "verified against trusted root"
            )

        signed = self._load_signed(data)
        if role == Snapshot.type:
            meta = trusted_set.timestamp.snapshot_meta
        else:
            meta = trusted_set.snapshot.meta.get(f"{role}.json")
            if meta is None:
                raise ValueError(
                    f"snapshot meta has no entry for '{role}.json'"
                )
        if signed.version != meta.version:
            raise ValueError(
                f"expected version {meta.version}, got {signed.version}"
            )
        meta.verify_length_and_hashes(data)
        return (
            f"legacy {role} v{signed.version} matches chain meta "
            "(version, hashes, length)"
        )
