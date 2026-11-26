# Copyright 2026, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import os
import tempfile
import unittest

from tests.repository_simulator import RepositorySimulator, RepositoryTarget
from tuf.api.metadata import DelegatedRole, TargetFile, Targets
from tuf.ngclient import (
    DeploymentContract,
    DeploymentPlanReviewer,
    StoreLocalRecord,
    Updater,
)


class TestDeploymentPlanReviewer(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.metadata_dir = os.path.join(self.temp_dir.name, "metadata")
        self.targets_dir = os.path.join(self.temp_dir.name, "targets")
        os.mkdir(self.metadata_dir)
        os.mkdir(self.targets_dir)

        self.sim = RepositorySimulator()
        role = DelegatedRole(
            "shared-offline-role",
            [],
            1,
            False,
            paths=["tools/offline/*"],
        )
        self.sim.add_delegation(
            "targets", role, Targets(expires=self.sim.safe_expiry)
        )
        self._add_target(
            "shared-offline-role",
            "tools/offline/tool.tar.gz",
            "1.2.0",
            b"offline-tool-1.2.0",
        )
        self._add_target(
            "shared-offline-role",
            "tools/offline/other.tar.gz",
            "1.2.0",
            b"other-tool-1.2.0",
        )
        self.sim.update_snapshot()

        self.contracts = [
            DeploymentContract.create(
                "contract-east",
                "east",
                "shared-offline-role",
                "offline-tool",
                ["tools/offline/tool.tar.gz"],
                ["1.2.0"],
            ),
            DeploymentContract.create(
                "contract-west",
                "west",
                "shared-offline-role",
                "offline-tool",
                ["tools/offline/*.tar.gz"],
                ["1.2.0"],
            ),
        ]
        self.records = {
            "store-east": StoreLocalRecord(
                "store-east",
                "east",
                "offline-tool",
                "1.1.0",
                "tools/offline/tool.tar.gz",
            ),
            "store-west": StoreLocalRecord(
                "store-west",
                "west",
                "offline-tool",
                "1.1.0",
                "tools/offline/other.tar.gz",
            ),
            "store-west-current": StoreLocalRecord(
                "store-west-current",
                "west",
                "offline-tool",
                "1.2.0",
                "tools/offline/tool.tar.gz",
            ),
        }

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _add_target(
        self, role: str, path: str, version: str, data: bytes
    ) -> None:
        target = TargetFile.from_data(path, data, ["sha256"])
        target.unrecognized_fields["custom"] = {
            "package": "offline-tool",
            "version": version,
        }
        role_targets = self.sim.md_delegates[role].signed
        role_targets.targets[path] = target
        self.sim.target_files[path] = RepositoryTarget(data, target)

    def _reviewer(self) -> DeploymentPlanReviewer:
        updater = Updater(
            self.metadata_dir,
            "https://example.com/metadata/",
            self.targets_dir,
            "https://example.com/targets/",
            self.sim,
            bootstrap=self.sim.signed_roots[0],
        )
        return DeploymentPlanReviewer(updater, self.contracts, self.records)

    def test_each_store_gets_its_contract_boundary_candidate(self) -> None:
        approvals = self._reviewer().review_all()

        self.assertEqual(
            [approval.contract_id for approval in approvals["store-east"]],
            ["contract-east"],
        )
        self.assertEqual(
            approvals["store-east"][0].target_path,
            "tools/offline/tool.tar.gz",
        )
        self.assertEqual(
            [approval.contract_id for approval in approvals["store-west"]],
            ["contract-west"],
        )
        self.assertEqual(
            approvals["store-west"][0].target_path,
            "tools/offline/other.tar.gz",
        )
        self.assertEqual(approvals["store-west-current"], ())

    def test_shared_role_does_not_mix_contract_obligations(self) -> None:
        east_record = self.records["store-east"]
        broad_west_contract = self.contracts[1]
        reviewer = DeploymentPlanReviewer(
            self._reviewer()._updater,
            [broad_west_contract],
            {"store-east": east_record},
        )

        self.assertEqual(reviewer.review("store-east"), ())

    def test_rejects_contract_version_not_in_tuf_target(self) -> None:
        contract = DeploymentContract.create(
            "contract-east-old",
            "east",
            "shared-offline-role",
            "offline-tool",
            ["tools/offline/tool.tar.gz"],
            ["1.1.0"],
        )
        reviewer = DeploymentPlanReviewer(
            self._reviewer()._updater,
            [contract],
            {"store-east": self.records["store-east"]},
        )

        self.assertEqual(reviewer.review("store-east"), ())

    def test_rejects_mismatching_client_local_record(self) -> None:
        local_record = StoreLocalRecord(
            "store-east",
            "east",
            "offline-tool",
            "1.1.0",
            "tools/offline/missing.tar.gz",
        )
        reviewer = DeploymentPlanReviewer(
            self._reviewer()._updater,
            [self.contracts[0]],
            {"store-east": local_record},
        )

        self.assertEqual(reviewer.review("store-east"), ())

    def test_minimum_reason_contains_full_intersection_evidence(self) -> None:
        approval = self._reviewer().review("store-east")[0]

        self.assertEqual(
            approval.reasons,
            (
                "store region east matches contract region",
                "delegation shared-offline-role is covered by "
                "contract contract-east",
                "target tools/offline/tool.tar.gz is inside contract boundary",
                "package offline-tool matches contract and record",
                "version 1.2.0 is allowed by contract",
                "client record references the same target path",
            ),
        )

    def test_target_candidates_include_trusted_delegation_role(self) -> None:
        updater = self._reviewer()._updater
        all_targets = updater.get_targetinfos()

        self.assertEqual(
            updater.get_targetinfo_with_role("tools/offline/tool.tar.gz"),
            (
                "shared-offline-role",
                updater.get_targetinfo("tools/offline/tool.tar.gz"),
            ),
        )
        self.assertEqual(
            [role for role, _ in all_targets],
            [
                "shared-offline-role",
                "shared-offline-role",
            ],
        )


if __name__ == "__main__":
    unittest.main()
