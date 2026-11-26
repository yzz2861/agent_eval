# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test ngclient offline migration checker."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from securesystemslib.signer import CryptoSigner

from tests.repository_simulator import RepositorySimulator
from tuf.api.metadata import DelegatedRole, Metadata, Root, Targets
from tuf.api.serialization.json import JSONSerializer
from tuf.ngclient.migration import (
    DeviceClass,
    MigrationCandidate,
    MigrationChecker,
)


class TestMigrationChecker(unittest.TestCase):
    """Test fleet migration planning with heterogeneous device classes.

    The simulated fleet migrates from an old channel (root v1) to a new
    channel (root v3) through an intermediate root (v2) that is pending
    approval for some device classes.
    """

    sim: RepositorySimulator
    old_root: bytes
    intermediate_root: bytes
    new_root: bytes
    old_timestamp: bytes
    old_snapshot: bytes
    old_targets: bytes
    old_role1: bytes
    new_timestamp: bytes
    new_snapshot: bytes
    new_targets: bytes
    new_role1: bytes

    def setUp(self) -> None:
        sim = RepositorySimulator()
        sim.compute_metafile_hashes_length = True

        # Old channel: delegated role "role1" with a target
        role = DelegatedRole("role1", [], 1, False, ["*"], None)
        sim.add_delegation("targets", role, Targets(expires=sim.safe_expiry))
        sim.add_target("role1", b"role1 content", "file1.txt")
        sim.targets.version += 1
        sim.update_snapshot()

        # Old channel consistent set (what devices may have cached)
        self.old_root = sim.signed_roots[0]
        self.old_timestamp = sim.fetch_metadata("timestamp")
        self.old_snapshot = sim.fetch_metadata("snapshot")
        self.old_targets = sim.fetch_metadata("targets")
        self.old_role1 = sim.fetch_metadata("role1")

        # Intermediate root v2 (same keys): some devices never received it
        sim.root.version += 1
        sim.publish_root()
        self.intermediate_root = sim.signed_roots[1]

        # New channel root v3: root key rotation, signed by old and new
        old_signers = list(sim.signers[Root.type].values())
        new_signer = CryptoSigner.generate_ed25519()
        sim.root.roles[Root.type].keyids.clear()
        sim.signers[Root.type].clear()
        sim.root.add_key(new_signer.public_key, Root.type)
        sim.add_signer(Root.type, new_signer)
        for signer in old_signers:
            sim.add_signer(Root.type, signer)
        sim.root.version += 1
        sim.publish_root()
        self.new_root = sim.signed_roots[2]

        # New channel content
        sim.add_target("targets", b"new firmware", "firmware.bin")
        sim.targets.version += 1
        sim.update_snapshot()

        self.new_timestamp = sim.fetch_metadata("timestamp")
        self.new_snapshot = sim.fetch_metadata("snapshot")
        self.new_targets = sim.fetch_metadata("targets")
        self.new_role1 = sim.fetch_metadata("role1")
        self.sim = sim

    def _candidate(
        self,
        roots: list[bytes],
        legacy: dict[str, bytes] | None = None,
    ) -> MigrationCandidate:
        return MigrationCandidate(
            roots=roots,
            timestamp=self.new_timestamp,
            snapshot=self.new_snapshot,
            targets={"targets": self.new_targets, "role1": self.new_role1},
            legacy_metadata=legacy or {},
        )

    def test_three_device_classes(self) -> None:
        now = datetime.now(UTC)
        # Old-channel role1 (same version as in the new chain) must be
        # cross-checked against the chain, not trusted directly
        legacy = {"role1": self.old_role1}
        checker = MigrationChecker(
            self._candidate([self.intermediate_root, self.new_root], legacy)
        )

        # fleet-a: trusted root v1, empty cache, current clock
        report_a = checker.check(DeviceClass("fleet-a", self.old_root, now))

        # fleet-b: already has intermediate root v2, carries cached
        # delegation state, clock is 10 days ahead
        report_b = checker.check(
            DeviceClass(
                "fleet-b",
                self.intermediate_root,
                now + timedelta(days=10),
                cached_metadata={
                    "timestamp": self.old_timestamp,
                    "snapshot": self.old_snapshot,
                    "targets": self.old_targets,
                    "role1": self.old_role1,
                },
            )
        )

        for report in (report_a, report_b):
            self.assertTrue(report.can_migrate, report.blocker)
            self.assertIsNone(report.blocker)
            self.assertEqual(report.root_version, 3)
            self.assertEqual(report.reached_step, "targets")
            self.assertEqual(report.needs_intermediate_root, None)
            # old-channel metadata verified against the chain
            self.assertEqual([c.role for c in report.legacy_checks], ["role1"])
            self.assertTrue(all(c.ok for c in report.legacy_checks))

        # fleet-a evidence: full root chain v1 -> v2 -> v3 was verified
        root_versions = [
            e.version for e in report_a.evidence if e.step == "root"
        ]
        self.assertEqual(root_versions, [2, 3])
        steps = {e.step for e in report_a.evidence}
        self.assertEqual(
            steps,
            {"bootstrap", "root", "timestamp", "snapshot", "targets", "legacy"},
        )

        # fleet-b evidence: cached delegation state was replayed
        self.assertTrue(
            any(
                e.step == "cache" and e.role == "role1"
                for e in report_b.evidence
            )
        )

        # fleet-c: never received the intermediate root v2 and the
        # candidate set only contains the new channel root v3
        blocked_checker = MigrationChecker(
            self._candidate([self.new_root], legacy)
        )
        report_c = blocked_checker.check(
            DeviceClass("fleet-c", self.old_root, now)
        )
        self.assertFalse(report_c.can_migrate)
        self.assertIsNotNone(report_c.blocker)
        assert report_c.blocker is not None
        self.assertEqual(report_c.blocker.step, "root")
        self.assertEqual(report_c.needs_intermediate_root, 2)
        self.assertIn("pending approval", report_c.blocker.reason)
        self.assertEqual(report_c.root_version, 1)
        self.assertEqual(report_c.reached_step, "root")

    def test_legacy_root_matches_chain(self) -> None:
        # Old-channel root v1 is part of fleet-a's verified chain
        checker = MigrationChecker(
            self._candidate(
                [self.intermediate_root, self.new_root],
                legacy={"root": self.old_root},
            )
        )
        report = checker.check(
            DeviceClass("fleet-a", self.old_root, datetime.now(UTC))
        )
        self.assertTrue(report.can_migrate, report.blocker)
        self.assertTrue(report.legacy_checks[0].ok)

    def test_legacy_root_mismatch_blocks(self) -> None:
        # A root from a different repository is not in the chain: reject
        other = RepositorySimulator()
        checker = MigrationChecker(
            self._candidate(
                [self.intermediate_root, self.new_root],
                legacy={"root": other.signed_roots[0]},
            )
        )
        report = checker.check(
            DeviceClass("fleet-x", self.old_root, datetime.now(UTC))
        )
        self.assertFalse(report.can_migrate)
        self.assertFalse(report.legacy_checks[0].ok)

    def test_legacy_metadata_mismatch_blocks(self) -> None:
        # Tampered old-channel role1: re-signed but not matching chain meta
        md = Metadata.from_bytes(self.old_role1)
        md.signed.targets.clear()
        signer = next(iter(self.sim.signers["role1"].values()))
        md.signatures.clear()
        md.sign(signer)
        tampered = md.to_bytes(JSONSerializer())

        checker = MigrationChecker(
            self._candidate(
                [self.intermediate_root, self.new_root],
                legacy={"role1": tampered},
            )
        )
        report = checker.check(
            DeviceClass("fleet-x", self.old_root, datetime.now(UTC))
        )
        self.assertFalse(report.can_migrate)
        self.assertEqual(len(report.legacy_checks), 1)
        self.assertFalse(report.legacy_checks[0].ok)

    def test_expired_clock_blocks(self) -> None:
        # Device clock is past metadata expiry: cannot migrate safely
        checker = MigrationChecker(
            self._candidate([self.intermediate_root, self.new_root])
        )
        report = checker.check(
            DeviceClass(
                "fleet-y",
                self.old_root,
                datetime.now(UTC) + timedelta(days=31),
            )
        )
        self.assertFalse(report.can_migrate)
        self.assertIsNotNone(report.blocker)
        assert report.blocker is not None
        self.assertEqual(report.blocker.step, "timestamp")
        self.assertIn("expired", report.blocker.reason)


if __name__ == "__main__":
    unittest.main()
