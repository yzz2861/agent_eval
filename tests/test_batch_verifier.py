# Copyright 2026, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime, timedelta

from tests.repository_simulator import RepositorySimulator
from tuf.api.metadata import DelegatedRole, Targets
from tuf.ngclient import (
    TargetBatchVerifier,
    TargetVerificationStatus,
    Updater,
    verify_targets,
)


class TestTargetBatchVerifier(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.sim = RepositorySimulator()
        role = DelegatedRole("delegated", [], 1, False, ["delegated/*"])
        self.sim.add_delegation(
            "targets", role, Targets(expires=self.sim.safe_expiry)
        )
        self.sim.add_target("targets", b"top-level", "top.txt")
        self.sim.add_target(
            "delegated", b"delegated content", "delegated/file.txt"
        )
        self.sim.targets.version += 1
        self.sim.update_snapshot()
        self.initial_generation = (
            self.sim.root.version,
            self.sim.timestamp.version,
            self.sim.snapshot.version,
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _factory(self) -> Updater:
        metadata_dir = tempfile.mkdtemp(dir=self.temp_dir.name)
        target_dir = tempfile.mkdtemp(dir=self.temp_dir.name)
        return Updater(
            metadata_dir,
            "https://example.com/metadata/",
            target_dir,
            "https://example.com/targets/",
            self.sim,
            bootstrap=self.sim.signed_roots[0],
        )

    def test_empty_batch_cannot_be_signed_off(self) -> None:
        result = TargetBatchVerifier(self._factory).verify([])

        self.assertFalse(result.can_sign_off)
        self.assertEqual(result.results, ())
        self.assertIsNone(result.generation_boundary)

    def test_verify_targets_function_returns_batch_result(self) -> None:
        result = verify_targets(self._factory, ["top.txt"])

        self.assertTrue(result.can_sign_off)
        self.assertEqual(
            result.results[0].status, TargetVerificationStatus.VERIFIED
        )
        self.assertEqual(result.trust_generation, self.initial_generation)
        self.assertIsNone(
            TargetBatchVerifier(self._factory).verify([]).trust_generation
        )

    def test_verifies_batch_with_role_and_version_evidence(self) -> None:
        result = TargetBatchVerifier(self._factory).verify(
            ["top.txt", "delegated/file.txt"]
        )

        self.assertTrue(result.can_sign_off)
        self.assertIsNone(result.generation_boundary)
        self.assertEqual(
            [item.status for item in result.results],
            [
                TargetVerificationStatus.VERIFIED,
                TargetVerificationStatus.VERIFIED,
            ],
        )
        self.assertEqual(
            [(item.role, item.role_version) for item in result.trust_materials],
            [("targets", 2), ("delegated", 1)],
        )
        self.assertEqual(
            {item.generation() for item in result.trust_materials},
            {self.initial_generation},
        )

    def test_distinguishes_missing_and_expired_targets(self) -> None:
        self.sim.md_delegates["delegated"].signed.expires = datetime.now(
            UTC
        ) - timedelta(minutes=1)

        result = TargetBatchVerifier(self._factory).verify(
            ["missing.txt", "delegated/file.txt", "top.txt"]
        )

        self.assertFalse(result.can_sign_off)
        self.assertEqual(
            [item.status for item in result.results],
            [
                TargetVerificationStatus.NOT_FOUND,
                TargetVerificationStatus.EXPIRED,
                TargetVerificationStatus.VERIFIED,
            ],
        )
        self.assertIsNone(result.results[0].trust_material)
        self.assertIsNone(result.results[1].trust_material)
        self.assertEqual(
            result.results[2].trust_material.role, "targets"
        )

    def test_min_validity_reports_without_enough_lifetime(self) -> None:
        result = TargetBatchVerifier(
            self._factory, min_validity=timedelta(days=31)
        ).verify(["top.txt"])

        self.assertFalse(result.can_sign_off)
        self.assertEqual(
            result.results[0].status, TargetVerificationStatus.EXPIRED
        )

    def test_repeated_trust_material_does_not_create_boundary(self) -> None:
        result = TargetBatchVerifier(self._factory).verify(
            ["top.txt", "top.txt"]
        )

        self.assertTrue(result.can_sign_off)
        self.assertIsNone(result.generation_boundary)
        self.assertEqual(
            [item.status for item in result.results],
            [
                TargetVerificationStatus.VERIFIED,
                TargetVerificationStatus.VERIFIED,
            ],
        )

    def test_memory_fetcher_change_reports_generation_boundary(
        self,
    ) -> None:
        call_count = 0

        def changing_factory() -> Updater:
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                self.sim.add_target("targets", b"new target", "new.txt")
                self.sim.targets.version += 1
                self.sim.update_snapshot()
            return self._factory()

        verifier = TargetBatchVerifier(changing_factory)

        result = verifier.verify(["top.txt", "new.txt", "top.txt"])

        self.assertFalse(result.can_sign_off)
        self.assertEqual(result.generation_boundary, 1)
        self.assertEqual(
            [item.status for item in result.results],
            [
                TargetVerificationStatus.VERIFIED,
                TargetVerificationStatus.TRUST_MATERIAL_MISMATCH,
                TargetVerificationStatus.TRUST_MATERIAL_MISMATCH,
            ],
        )
        self.assertTrue(result.results[1].generation_boundary)
        self.assertNotEqual(
            result.results[0].trust_material.generation(),
            result.results[1].trust_material.generation(),
        )
        self.assertEqual(
            result.results[1].trust_material.timestamp_version,
            self.sim.timestamp.version,
        )

    def test_root_rotation_is_reported_as_generation_boundary(self) -> None:
        call_count = 0

        def changing_factory() -> Updater:
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                self.sim.root.version += 1
                self.sim.publish_root()
            return self._factory()

        result = TargetBatchVerifier(changing_factory).verify(
            ["top.txt", "top.txt"]
        )

        self.assertFalse(result.can_sign_off)
        self.assertEqual(result.generation_boundary, 1)
        self.assertEqual(
            result.results[1].status,
            TargetVerificationStatus.TRUST_MATERIAL_MISMATCH,
        )
        self.assertEqual(
            result.results[0].trust_material.root_version,
            1,
        )
        self.assertEqual(
            result.results[1].trust_material.root_version,
            2,
        )


if __name__ == "__main__":
    unittest.main()
