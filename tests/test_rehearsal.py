# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test read-only root rotation rehearsal (tuf.ngclient.rehearsal)"""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from securesystemslib.signer import CryptoSigner, Signer

from tuf.api.exceptions import UnsignedMetadataError
from tuf.api.metadata import (
    TOP_LEVEL_ROLE_NAMES,
    Metadata,
    MetaFile,
    Root,
    Snapshot,
    Targets,
    Timestamp,
)
from tuf.ngclient.rehearsal import (
    BlockReason,
    CandidateRoot,
    ClientBatch,
    LaunchWindow,
    RotationRehearsal,
)

T0 = datetime(2026, 11, 20, tzinfo=UTC)
T1 = T0 + timedelta(days=1)
T2 = T0 + timedelta(days=2)
T3 = T0 + timedelta(days=3)
T4 = T0 + timedelta(days=4)

TARGET_VERSION = 5


class TestRotationRehearsal(unittest.TestCase):
    """Test rotation rehearsal projections and Updater cross-checks"""

    signers: list[Signer]
    roots: dict[int, bytes]

    @classmethod
    def setUpClass(cls) -> None:
        cls.signers = [CryptoSigner.generate_ed25519() for _ in range(6)]
        expiry = datetime.now(UTC).replace(microsecond=0) + timedelta(days=30)

        def make_root(
            version: int, key_ids: list[int], sig_ids: list[int]
        ) -> bytes:
            root = Root(
                version=version, expires=expiry, consistent_snapshot=False
            )
            for i in key_ids:
                for role in TOP_LEVEL_ROLE_NAMES:
                    root.add_key(cls.signers[i].public_key, role)
            root.roles[Root.type].threshold = 2
            md = Metadata(root)
            for i in sig_ids:
                md.sign(cls.signers[i], append=True)
            return md.to_bytes()

        # Chain with bilateral threshold 2: every root is signed by both
        # the previous and the new root key sets
        cls.roots = {
            1: make_root(1, [0, 1], [0, 1]),
            2: make_root(2, [1, 2], [0, 1, 2]),
            3: make_root(3, [2, 3], [1, 2, 3]),
            4: make_root(4, [3, 4], [2, 3, 4]),
            5: make_root(5, [4, 5], [3, 4, 5]),
        }

    @classmethod
    def make_candidates(cls, versions: list[int]) -> list[CandidateRoot]:
        visibility = {
            1: (T0, T4),
            2: (T0, T4),
            3: (T0, T1),  # leaves visibility before the weekend
            4: (T1, T3),
            5: (T1, T4),
        }
        return [CandidateRoot(cls.roots[v], *visibility[v]) for v in versions]

    @classmethod
    def make_supporting_metadata(cls, sig_id: int) -> dict[str, bytes]:
        expiry = datetime.now(UTC).replace(microsecond=0) + timedelta(days=30)
        timestamp = Metadata(
            Timestamp(expires=expiry, snapshot_meta=MetaFile(version=1))
        )
        snapshot = Metadata(
            Snapshot(expires=expiry, meta={"targets.json": MetaFile(version=1)})
        )
        targets = Metadata(Targets(expires=expiry))
        files = {}
        for name, md in [
            ("timestamp.json", timestamp),
            ("snapshot.json", snapshot),
            ("targets.json", targets),
        ]:
            md.sign(cls.signers[sig_id])
            files[name] = md.to_bytes()
        return files

    @staticmethod
    def make_windows() -> list[LaunchWindow]:
        return [
            LaunchWindow("pre-weekend", T0, T1),
            LaunchWindow("weekend-launch", T2, T3),
            LaunchWindow("late", T3, T4),
        ]

    def test_three_batches(self) -> None:
        rehearsal = RotationRehearsal(self.make_candidates([1, 2, 3, 4, 5]))
        windows = self.make_windows()
        batches = [
            ClientBatch("canary", self.roots[1], update_budget=8),
            ClientBatch("weekend-only", self.roots[2], update_budget=2),
            ClientBatch("held-back", self.roots[4], update_budget=4),
        ]

        result = rehearsal.evaluate_all(batches, windows, TARGET_VERSION)
        reports = {r.batch.name: r for r in result.reports}

        # canary: full path only before the weekend; afterwards root v3 is
        # no longer visible so the batch is stranded at v2
        canary = reports["canary"]
        self.assertEqual(canary.reachable_windows, ["pre-weekend"])
        self.assertEqual(canary.stranded_version, 2)
        self.assertEqual(canary.block_reason, BlockReason.NOT_VISIBLE)
        self.assertEqual(canary.no_path_since, T1)
        weekend = canary.outcomes[1]
        self.assertEqual(weekend.window.label, "weekend-launch")
        self.assertEqual(len(weekend.steps), 1)
        self.assertEqual(weekend.steps[0].from_version, 1)
        self.assertEqual(weekend.steps[0].to_version, 2)

        # weekend-only: budget of 2 rotations is not enough for v2 -> v5,
        # the batch is stranded at v4 even while material is visible
        weekend_only = reports["weekend-only"]
        self.assertEqual(weekend_only.reachable_windows, [])
        self.assertEqual(weekend_only.stranded_version, 4)
        self.assertEqual(
            weekend_only.block_reason, BlockReason.UPDATE_BUDGET_EXHAUSTED
        )
        self.assertEqual(weekend_only.no_path_since, T1)

        # held-back: only needs v5, reachable in every window
        held_back = reports["held-back"]
        self.assertEqual(held_back.stranded_version, None)
        self.assertEqual(
            held_back.reachable_windows,
            ["pre-weekend", "weekend-launch", "late"],
        )
        self.assertEqual(held_back.no_path_since, None)

        summary = result.summarize()
        self.assertIn("stranded at root v2", summary)
        self.assertIn("stranded at root v4", summary)
        self.assertIn("no path since", summary)

    def test_block_reasons_are_distinct(self) -> None:
        # missing material: chain skips v3 entirely
        rehearsal = RotationRehearsal(self.make_candidates([1, 2, 4, 5]))
        batch = ClientBatch("gap", self.roots[1], update_budget=8)
        outcome = rehearsal.evaluate_window(
            batch, LaunchWindow("w", T0, T4), TARGET_VERSION
        )
        self.assertEqual(outcome.block_reason, BlockReason.MISSING_MATERIAL)
        self.assertEqual(outcome.final_version, 2)
        self.assertIn("v3", outcome.block_detail)

        # insufficient signatures: v3 signed by old keys only, the new
        # root threshold is not met
        expiry = datetime.now(UTC).replace(microsecond=0) + timedelta(days=30)
        bad_root = Root(version=3, expires=expiry, consistent_snapshot=False)
        for i in [2, 3]:
            for role in TOP_LEVEL_ROLE_NAMES:
                bad_root.add_key(self.signers[i].public_key, role)
        bad_root.roles[Root.type].threshold = 2
        bad_md = Metadata(bad_root)
        for i in [1, 2]:
            bad_md.sign(self.signers[i], append=True)
        candidates = [
            *self.make_candidates([2]),
            CandidateRoot(bad_md.to_bytes(), T0, T4),
        ]
        rehearsal = RotationRehearsal(candidates)
        batch = ClientBatch("bad-sig", self.roots[2], update_budget=4)
        outcome = rehearsal.evaluate_window(batch, LaunchWindow("w", T0, T4), 3)
        self.assertEqual(
            outcome.block_reason, BlockReason.INSUFFICIENT_SIGNATURES
        )
        self.assertEqual(outcome.final_version, 2)

    def test_confirm_with_updater_success(self) -> None:
        rehearsal = RotationRehearsal(self.make_candidates([1, 2, 3, 4, 5]))
        batch = ClientBatch("canary", self.roots[1], update_budget=8)
        # supporting metadata signed by a key of the final root v5
        supporting = self.make_supporting_metadata(sig_id=4)
        version = rehearsal.confirm_with_updater(
            batch, LaunchWindow("pre-weekend", T0, T1), supporting
        )
        self.assertEqual(version, TARGET_VERSION)

    def test_confirm_with_updater_missing_intermediate(self) -> None:
        # final root v5 verifies against v4 but v3 is absent from the chain
        rehearsal = RotationRehearsal(self.make_candidates([1, 2, 4, 5]))
        batch = ClientBatch("gap", self.roots[1], update_budget=8)
        window = LaunchWindow("w", T0, T4)

        outcome = rehearsal.evaluate_window(batch, window, TARGET_VERSION)
        self.assertEqual(outcome.block_reason, BlockReason.MISSING_MATERIAL)
        self.assertEqual(outcome.final_version, 2)

        # the real Updater agrees: it stalls at v2 (supporting metadata
        # signed by a key of root v2, the version the client ends up on)
        supporting = self.make_supporting_metadata(sig_id=1)
        version = rehearsal.confirm_with_updater(batch, window, supporting)
        self.assertEqual(version, 2)

    def test_confirm_with_updater_insufficient_signatures(self) -> None:
        expiry = datetime.now(UTC).replace(microsecond=0) + timedelta(days=30)
        bad_root = Root(version=3, expires=expiry, consistent_snapshot=False)
        for i in [2, 3]:
            for role in TOP_LEVEL_ROLE_NAMES:
                bad_root.add_key(self.signers[i].public_key, role)
        bad_root.roles[Root.type].threshold = 2
        bad_md = Metadata(bad_root)
        for i in [1, 2]:
            bad_md.sign(self.signers[i], append=True)
        candidates = [
            *self.make_candidates([2]),
            CandidateRoot(bad_md.to_bytes(), T0, T4),
        ]
        rehearsal = RotationRehearsal(candidates)
        batch = ClientBatch("bad-sig", self.roots[2], update_budget=4)
        with self.assertRaises(UnsignedMetadataError):
            rehearsal.confirm_with_updater(batch, LaunchWindow("w", T0, T4), {})

    def test_invalid_candidates_rejected(self) -> None:
        with self.assertRaises(ValueError):
            RotationRehearsal(
                self.make_candidates([1]) + self.make_candidates([1])
            )
        targets = Metadata(Targets())
        targets.sign(self.signers[0])
        with self.assertRaises(ValueError):
            RotationRehearsal([CandidateRoot(targets.to_bytes(), T0, T4)])


if __name__ == "__main__":
    unittest.main()
