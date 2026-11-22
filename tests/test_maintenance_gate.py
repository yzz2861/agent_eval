"""Tests for the offline maintenance admission gate (tuf.contrib).

The gate is exercised the way an offline device actually sees material: signed
metadata bytes arriving on different channels, possibly reordered or
incomplete. The tests assert that admission depends only on the verified
statements and their authorization versions, never on arrival order.
"""

from __future__ import annotations

import unittest
from itertools import permutations

from securesystemslib.signer import CryptoSigner

from tuf.api.metadata import Metadata
from tuf.api.serialization.json import JSONSerializer
from tuf.contrib.maintenance_gate import (
    AdmissionVerdict,
    AuthorizationRepository,
    DelegationSpec,
    GateStatus,
    MaintenanceGate,
    Statement,
)
from tuf.contrib.maintenance_gate.model import PAUSE, RESUME

DELEGATED = ["channel-a", "channel-b"]
ALL_ROLES = ["timestamp", "snapshot", "targets", *DELEGATED]


class MaintenanceGateTest(unittest.TestCase):
    """Shared fixture building a two-channel authorization repository."""

    def setUp(self) -> None:
        self.repo = AuthorizationRepository(
            [
                DelegationSpec("channel-a", ["pkg/a/*", "pkg/ov/*"]),
                DelegationSpec(
                    "channel-b",
                    ["pkg/b/*", "pkg/shared/*", "pkg/ov/*"],
                    terminating=True,
                ),
            ]
        )
        # epoch 1: pause on both channels.
        self.epoch1 = self.repo.publish(
            [
                Statement.pause("channel-a", "pkg/a/1.bin", "pkg/ov/x.bin"),
                Statement.pause("channel-b", "pkg/shared/s.bin"),
            ]
        )
        # epoch 2: resume a/1, keep the shared pause, add a b pause.
        self.epoch2 = self.repo.publish(
            [
                Statement.resume("channel-a", "pkg/a/1.bin"),
                Statement.pause("channel-b", "pkg/shared/s.bin", "pkg/b/2.bin"),
            ]
        )

    def gate(self) -> MaintenanceGate:
        return MaintenanceGate(self.repo.root_bytes, delegated_roles=DELEGATED)

    def feed(
        self, release: dict[str, bytes], order: list[str]
    ) -> MaintenanceGate:
        gate = self.gate()
        for role in order:
            gate.ingest(role, release[role])
        return gate

    # ------------------------------------------------------------------
    # Order independence.
    # ------------------------------------------------------------------
    def test_same_statements_reordered_give_same_admission(self) -> None:
        """Two identical releases in any order converge on one verdict."""
        reference = self.feed(self.epoch2, ALL_ROLES)
        expected = {
            target: reference.admit(target).verdict
            for target in (
                "pkg/a/1.bin",
                "pkg/b/2.bin",
                "pkg/shared/s.bin",
                "pkg/ov/x.bin",
                "pkg/unknown/z.bin",
            )
        }
        for order in permutations(ALL_ROLES):
            gate = self.feed(self.epoch2, list(order))
            self.assertEqual(gate.trusted_epoch, 2)
            for target, verdict in expected.items():
                self.assertEqual(
                    gate.admit(target).verdict,
                    verdict,
                    f"mismatch for {target} under order {order}",
                )

    def test_admit_many_is_independent_of_package_order(self) -> None:
        """The order packages are queried cannot change their verdicts."""
        gate = self.feed(self.epoch2, ALL_ROLES)
        targets = [
            "pkg/shared/s.bin",
            "pkg/a/1.bin",
            "pkg/b/2.bin",
            "pkg/ov/x.bin",
        ]
        forward = gate.admit_many(targets)
        reverse = gate.admit_many(list(reversed(targets)))
        self.assertEqual(
            {k: v.verdict for k, v in forward.items()},
            {k: v.verdict for k, v in reverse.items()},
        )
        self.assertEqual(
            forward["pkg/a/1.bin"].verdict, AdmissionVerdict.PROCEED
        )
        self.assertEqual(
            forward["pkg/b/2.bin"].verdict, AdmissionVerdict.PAUSED
        )

    def test_two_identical_statement_sets_swapped(self) -> None:
        """Feed the same slips twice in opposite order: verdict is stable."""
        slips = [
            Statement.pause("channel-a", "pkg/a/1.bin"),
            Statement.resume("channel-b", "pkg/shared/s.bin"),
        ]
        release = self.repo.publish(slips)
        gate_a = self.gate()
        gate_b = self.gate()
        for role in ALL_ROLES:
            gate_a.ingest(role, release[role])
        for role in reversed(ALL_ROLES):
            gate_b.ingest(role, release[role])
        for target in ("pkg/a/1.bin", "pkg/shared/s.bin"):
            self.assertEqual(
                gate_a.admit(target).verdict, gate_b.admit(target).verdict
            )

    # ------------------------------------------------------------------
    # Half sets: nothing is trusted until the full chain verifies.
    # ------------------------------------------------------------------
    def test_half_set_stays_pending_until_completed(self) -> None:
        gate = self.gate()
        first = gate.ingest("channel-a", self.epoch1["channel-a"])
        self.assertEqual(first.status, GateStatus.STAGED)
        self.assertIn("awaiting", first.reason)
        # No complete release yet: every admission fails closed.
        self.assertEqual(
            gate.admit("pkg/a/1.bin").verdict, AdmissionVerdict.PENDING
        )

        for role in ("timestamp", "snapshot", "targets"):
            self.assertEqual(
                gate.ingest(role, self.epoch1[role]).status,
                GateStatus.STAGED,
            )
        completed = gate.ingest("channel-b", self.epoch1["channel-b"])
        self.assertEqual(completed.status, GateStatus.TRUSTED)
        self.assertEqual(completed.promoted_epoch, 1)
        self.assertEqual(
            gate.admit("pkg/a/1.bin").verdict, AdmissionVerdict.PAUSED
        )

    def test_missing_delegated_role_forces_pending_for_its_targets(
        self,
    ) -> None:
        # A release missing one delegated role never promotes: the half set is
        # staged while the device keeps deciding on the last complete epoch.
        gate = self.feed(self.epoch1, ALL_ROLES)
        partial = self.repo.publish(
            [Statement.pause("channel-a", "pkg/a/1.bin")]
        )
        last = None
        for role in ("timestamp", "snapshot", "targets", "channel-a"):
            last = gate.ingest(role, partial[role])
            self.assertEqual(last.status, GateStatus.STAGED)
        self.assertIn("channel-b", last.reason)
        # The trusted view stays on the previous complete epoch.
        self.assertEqual(gate.trusted_epoch, 1)
        # channel-b has not arrived, so it is named as missing, not staged.
        self.assertNotIn("channel-b", gate.staged_roles)
        # Admission still uses the last fully verified release (epoch 1).
        self.assertEqual(
            gate.admit("pkg/shared/s.bin").verdict, AdmissionVerdict.PAUSED
        )

        # Completing the half set with the missing role promotes it.
        completed = gate.ingest("channel-b", partial["channel-b"])
        self.assertEqual(completed.status, GateStatus.TRUSTED)
        self.assertEqual(gate.trusted_epoch, 3)
        # channel-b carried no new statement here; channel-a pause is active.
        self.assertEqual(
            gate.admit("pkg/a/1.bin").verdict, AdmissionVerdict.PAUSED
        )

    def test_no_anchor_half_set_fails_closed(self) -> None:
        # Before any complete release, a half set yields PENDING everywhere.
        gate = self.gate()
        for role in ("timestamp", "snapshot", "targets", "channel-a"):
            gate.ingest(role, self.epoch1[role])
        self.assertFalse(gate.has_trusted_view)
        self.assertEqual(
            gate.admit("pkg/shared/s.bin").verdict, AdmissionVerdict.PENDING
        )

    def test_old_resume_arriving_last_cannot_roll_back(self) -> None:
        gate = self.feed(self.epoch2, ALL_ROLES)
        self.assertEqual(
            gate.admit("pkg/a/1.bin").verdict, AdmissionVerdict.PROCEED
        )
        # The older epoch-1 timestamp shows up last: rejected on its version.
        old_timestamp = gate.ingest("timestamp", self.epoch1["timestamp"])
        self.assertEqual(old_timestamp.status, GateStatus.REJECTED)
        # A lone old delegated slip cannot self-certify its version, so it is
        # held (staged) but can never influence the trusted view.
        old_slip = gate.ingest("channel-a", self.epoch1["channel-a"])
        self.assertEqual(old_slip.status, GateStatus.STAGED)
        # Trusted view and verdict are unchanged regardless of late arrival.
        self.assertEqual(gate.trusted_epoch, 2)
        self.assertEqual(
            gate.admit("pkg/a/1.bin").verdict, AdmissionVerdict.PROCEED
        )

        # Replaying the whole older release together is a rollback and fails.
        rollback_gate = self.feed(self.epoch2, ALL_ROLES)
        for role in ALL_ROLES:
            rollback_gate.ingest(role, self.epoch1[role])
        self.assertEqual(
            rollback_gate.admit("pkg/a/1.bin").verdict,
            AdmissionVerdict.PROCEED,
        )
        self.assertEqual(rollback_gate.trusted_epoch, 2)

    def test_tampered_metadata_is_rejected_and_fails_closed(self) -> None:
        tampered = dict(self.epoch1)
        tampered["channel-a"] = AuthorizationRepository.tamper(
            self.epoch1["channel-a"]
        )
        gate = self.gate()
        for role in ALL_ROLES:
            gate.ingest(role, tampered[role])
        self.assertIn("channel-a", gate.rejected_roles)
        self.assertFalse(gate.has_trusted_view)
        self.assertEqual(
            gate.admit("pkg/a/1.bin").verdict, AdmissionVerdict.PENDING
        )

    def test_foreign_key_signature_is_rejected(self) -> None:
        metadata = Metadata.from_bytes(self.epoch1["channel-a"])
        metadata.signatures.clear()
        metadata.sign(CryptoSigner.generate_ed25519())
        forged = metadata.to_bytes(JSONSerializer())
        gate = self.gate()
        for role in ALL_ROLES:
            data = forged if role == "channel-a" else self.epoch1[role]
            gate.ingest(role, data)
        # The invalid document itself is identified, not an innocent one.
        self.assertEqual(gate.rejected_roles, ("channel-a",))
        self.assertIn("timestamp", gate.staged_roles)

    # ------------------------------------------------------------------
    # Delegation overlap and terminating semantics.
    # ------------------------------------------------------------------
    def test_overlapping_delegations_follow_delegation_order(self) -> None:
        release = self.repo.publish(
            [
                Statement.pause("channel-a", "pkg/ov/x.bin"),
                Statement.resume("channel-b", "pkg/ov/x.bin"),
            ]
        )
        gate = self.feed(release, ALL_ROLES)
        decision = gate.admit("pkg/ov/x.bin")
        # channel-a is visited first in delegation order and lists the target.
        self.assertEqual(decision.verdict, AdmissionVerdict.PAUSED)
        self.assertEqual(decision.statement.role, "channel-a")

    def test_terminating_role_without_statement_defaults_to_proceed(
        self,
    ) -> None:
        gate = self.feed(self.epoch2, ALL_ROLES)
        # channel-b terminating covers pkg/b/* but lists nothing for b/9.
        decision = gate.admit("pkg/b/9.bin")
        self.assertEqual(decision.verdict, AdmissionVerdict.PROCEED)
        self.assertIn("terminating", decision.basis)

    # ------------------------------------------------------------------
    # Already cached targets: caching never grants authority.
    # ------------------------------------------------------------------
    def test_cached_target_is_re_evaluated_against_current_view(self) -> None:
        paused_gate = self.feed(self.epoch1, ALL_ROLES)
        # The package was cached earlier while updates were allowed.
        decision = paused_gate.admit_cached("pkg/a/1.bin")
        self.assertEqual(decision.verdict, AdmissionVerdict.PAUSED)

    def test_cached_content_hash_mismatch_forces_pending(self) -> None:
        gate = self.feed(self.epoch2, ALL_ROLES)
        intact = b"authorization::pkg/a/1.bin"
        self.assertEqual(
            gate.admit_cached("pkg/a/1.bin", intact).verdict,
            AdmissionVerdict.PROCEED,
        )
        tampered = gate.admit_cached("pkg/a/1.bin", b"stale-bytes")
        self.assertEqual(tampered.verdict, AdmissionVerdict.PENDING)
        self.assertIn("failed verification", tampered.basis)

    def test_cached_target_without_description_is_pending(self) -> None:
        gate = self.feed(self.epoch2, ALL_ROLES)
        decision = gate.admit_cached("pkg/never/listed.bin", b"x")
        self.assertEqual(decision.verdict, AdmissionVerdict.PENDING)

    # ------------------------------------------------------------------
    # A later pause on top of an existing trusted view.
    # ------------------------------------------------------------------
    def test_new_pause_after_resume_takes_effect(self) -> None:
        gate = self.feed(self.epoch2, ALL_ROLES)
        self.assertEqual(
            gate.admit("pkg/a/1.bin").verdict, AdmissionVerdict.PROCEED
        )
        epoch3 = self.repo.publish(
            [Statement.pause("channel-a", "pkg/a/1.bin")]
        )
        for role in ALL_ROLES:
            gate.ingest(role, epoch3[role])
        self.assertEqual(gate.trusted_epoch, 3)
        decision = gate.admit("pkg/a/1.bin")
        self.assertEqual(decision.verdict, AdmissionVerdict.PAUSED)
        self.assertEqual(decision.statement.version, 3)

    def test_new_pause_is_order_independent_against_old_release(self) -> None:
        epoch3 = self.repo.publish(
            [Statement.pause("channel-a", "pkg/a/1.bin")]
        )
        verdicts = set()
        for order in permutations(ALL_ROLES):
            gate = self.gate()
            # First fully verify epoch 2, then feed epoch 3 in this order.
            for role in ALL_ROLES:
                gate.ingest(role, self.epoch2[role])
            for role in order:
                gate.ingest(role, epoch3[role])
            verdicts.add(gate.admit("pkg/a/1.bin").verdict)
        self.assertEqual(verdicts, {AdmissionVerdict.PAUSED})

    # ------------------------------------------------------------------
    # Model helpers and audit trail.
    # ------------------------------------------------------------------
    def test_statements_extracted_with_authorization_version(self) -> None:
        gate = self.feed(self.epoch2, ALL_ROLES)
        statements = {(s.role, s.action): s for s in gate.statements()}
        resume = statements[("channel-a", RESUME)]
        self.assertEqual(resume.version, 2)
        self.assertIn("pkg/a/1.bin", resume.targets)
        pause = statements[("channel-b", PAUSE)]
        self.assertEqual(
            pause.targets, frozenset(["pkg/shared/s.bin", "pkg/b/2.bin"])
        )

    def test_audit_log_records_every_ingest(self) -> None:
        gate = self.gate()
        gate.ingest("channel-a", self.epoch1["channel-a"])
        gate.ingest("timestamp", self.epoch1["timestamp"])
        statuses = [entry.status for entry in gate.audit_log]
        self.assertEqual(statuses, [GateStatus.STAGED, GateStatus.STAGED])
        self.assertTrue(all(entry.role for entry in gate.audit_log))


if __name__ == "__main__":
    unittest.main()
