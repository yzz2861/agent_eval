# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  test_reconcile.py

<Author>
  in-toto contributors

<Started>
  Nov 23, 2026

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test cases for in_toto.reconcile: offline reconciliation of
  late-arriving link metadata and material statements against
  caller-approved, versioned, partial material indexes.

"""

import unittest

from in_toto.models.link import Link
from in_toto.models.metadata import Metablock
from in_toto.reconcile import (
    Delivery,
    EventKind,
    MaterialIndex,
    MaterialStatus,
    StepState,
    reconcile,
)
from tests.common import SignerStore

FOO_HASH = {"sha256": "a" * 64}
FOO_HASH_OTHER = {"sha256": "b" * 64}
BAR_HASH = {"sha256": "c" * 64}
EVIL_HASH = {"sha256": "d" * 64}
PRODUCT_HASH = {"sha256": "e" * 64}
PRODUCT_HASH_V2 = {"sha256": "f" * 64}


def _link(name, materials, products, sign=True):
    """Creates a link metablock, signed with the test rsa key by default."""
    metablock = Metablock(
        signed=Link(name=name, materials=materials, products=products)
    )
    if sign:
        metablock.create_signature(SignerStore.rsa)
    return metablock


class TestMaterialIndex(unittest.TestCase):
    """Tests for MaterialIndex.classify."""

    @classmethod
    def setUpClass(cls):
        cls.index = MaterialIndex(
            version=1, approved={"foo.py": FOO_HASH}, denied={"evil.so"}
        )

    def test_approved(self):
        status, _ = self.index.classify("foo.py", FOO_HASH)
        self.assertEqual(status, MaterialStatus.APPROVED)

    def test_denied(self):
        status, _ = self.index.classify("evil.so", EVIL_HASH)
        self.assertEqual(status, MaterialStatus.DENIED)

    def test_contradicted(self):
        status, _ = self.index.classify("foo.py", FOO_HASH_OTHER)
        self.assertEqual(status, MaterialStatus.CONTRADICTED)

    def test_unvouched(self):
        status, _ = self.index.classify("unknown.py", FOO_HASH)
        self.assertEqual(status, MaterialStatus.UNVOUCHED)


class TestReconcileThreeDeliveries(unittest.TestCase):
    """Replays a three-handover acceptance flow.

    Delivery 1: material statement for 'package' arrives without its link
        (artifact blocked); 'build' link is complete (releasable).
    Delivery 2: late 'package' link releases the artifact; a changed
        'build' link is a replacement; a validly signed link for denied
        material 'evil.so' stays blocked; a statement contradicting the
        index blocks 'test'.
    Delivery 3: the caller approves index v2; 'sign-off' is re-delivered
        with a valid signature but the denied material is not revived;
        'bundle' becomes releasable under the new index version.
    """

    @classmethod
    def setUpClass(cls):
        cls.keys = {SignerStore.rsa_pub["keyid"]: SignerStore.rsa_pub}

        cls.index_v1 = MaterialIndex(
            version=1, approved={"foo.py": FOO_HASH}, denied={"evil.so"}
        )
        cls.index_v2 = MaterialIndex(
            version=2,
            approved={"foo.py": FOO_HASH, "bar.so": BAR_HASH},
            denied={"evil.so"},
        )

        cls.deliveries = [
            Delivery(
                sequence=1,
                links=[
                    _link(
                        "build",
                        {"foo.py": FOO_HASH},
                        {"foo.o": PRODUCT_HASH},
                    )
                ],
                materials={"package": {"foo.py": FOO_HASH}},
            ),
            Delivery(
                sequence=2,
                links=[
                    _link(
                        "package",
                        {"foo.py": FOO_HASH},
                        {"foo.tar": PRODUCT_HASH},
                    ),
                    _link(
                        "build",
                        {"foo.py": FOO_HASH},
                        {"foo.o": PRODUCT_HASH_V2},
                    ),
                    _link(
                        "sign-off",
                        {"evil.so": EVIL_HASH},
                        {"sig": PRODUCT_HASH},
                    ),
                ],
                materials={"test": {"foo.py": FOO_HASH_OTHER}},
            ),
            Delivery(
                sequence=3,
                links=[
                    _link(
                        "sign-off",
                        {"evil.so": EVIL_HASH},
                        {"sig": PRODUCT_HASH},
                    ),
                    _link(
                        "bundle",
                        {"bar.so": BAR_HASH},
                        {"bundle.tar": PRODUCT_HASH},
                    ),
                ],
            ),
        ]

        cls.report = reconcile(
            initial_index=cls.index_v1,
            deliveries=cls.deliveries,
            keys=cls.keys,
            index_updates={3: cls.index_v2},
        )

    def _events(self, step=None, kind=None):
        return [
            event
            for event in self.report.events
            if (step is None or event.step == step)
            and (kind is None or event.kind == kind)
        ]

    def _decisions(self, step):
        return [
            decision
            for decision in self.report.decisions
            if decision.step == step
        ]

    def test_artifact_blocked_then_released(self):
        """'package' is blocked at delivery 1, releasable at delivery 2."""
        decisions = self._decisions("package")
        self.assertEqual(
            [(d.sequence, d.state, d.index_version) for d in decisions],
            [
                (1, StepState.BLOCKED, 1),
                (2, StepState.RELEASABLE, 1),
            ],
        )
        self.assertEqual(decisions[0].reason, "no admissible link evidence")
        self.assertEqual(
            self.report.final_states["package"], StepState.RELEASABLE
        )

    def test_late_submission_annotated_on_step(self):
        """The late 'package' link is annotated on the same step."""
        events = self._events("package", EventKind.LATE_SUBMISSION)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].sequence, 2)
        self.assertTrue(events[0].signature_valid)

    def test_replacement_annotated_on_step(self):
        """The changed 'build' link is marked as a replacement."""
        events = self._events("build", EventKind.REPLACEMENT)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].sequence, 2)
        # State does not change: 'build' stays releasable throughout.
        self.assertEqual(
            [d.state for d in self._decisions("build")],
            [StepState.RELEASABLE],
        )

    def test_contradiction_annotated_on_step(self):
        """The statement contradicting the index blocks 'test'."""
        events = self._events("test", EventKind.CONTRADICTION)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].material, "foo.py")
        self.assertEqual(events[0].index_version, 1)
        self.assertEqual(self.report.final_states["test"], StepState.BLOCKED)
        self.assertEqual(
            self.report.material_statuses["test"]["foo.py"],
            MaterialStatus.CONTRADICTED,
        )

    def test_valid_signature_does_not_revive_denied_material(self):
        """'sign-off' stays blocked despite validly signed deliveries."""
        events = self._events("sign-off", EventKind.DENIAL_HELD)
        self.assertEqual(len(events), 2)
        self.assertTrue(all(event.signature_valid for event in events))
        self.assertEqual(
            [d.state for d in self._decisions("sign-off")],
            [StepState.BLOCKED],
        )
        self.assertEqual(
            self.report.final_states["sign-off"], StepState.BLOCKED
        )
        self.assertEqual(
            self.report.material_statuses["sign-off"]["evil.so"],
            MaterialStatus.DENIED,
        )

    def test_explicit_index_update_releases_step(self):
        """'bundle' is releasable only under caller-approved index v2."""
        updates = self._events(kind=EventKind.INDEX_UPDATED)
        self.assertEqual(len(updates), 1)
        self.assertEqual(updates[0].sequence, 3)

        decisions = self._decisions("bundle")
        self.assertEqual(
            [(d.sequence, d.state, d.index_version) for d in decisions],
            [(3, StepState.RELEASABLE, 2)],
        )

    def test_replay_reproduces_state_changes(self):
        """Re-running reconciliation yields identical state changes."""
        replayed = self.report.replay()
        self.assertEqual(replayed.dumps(), self.report.dumps())

        rerun = reconcile(
            initial_index=self.index_v1,
            deliveries=self.deliveries,
            keys=self.keys,
            index_updates={3: self.index_v2},
        )
        self.assertEqual(rerun.dumps(), self.report.dumps())

    def test_decisions_record_index_version(self):
        """Every decision records the index version it relied on."""
        versions = {
            (d.step, d.sequence): d.index_version for d in self.report.decisions
        }
        self.assertEqual(versions[("package", 1)], 1)
        self.assertEqual(versions[("package", 2)], 1)
        self.assertEqual(versions[("sign-off", 2)], 1)
        self.assertEqual(versions[("bundle", 3)], 2)


class TestReconcileGuards(unittest.TestCase):
    """Tests for reconciliation input and signature guards."""

    @classmethod
    def setUpClass(cls):
        cls.keys = {SignerStore.rsa_pub["keyid"]: SignerStore.rsa_pub}
        cls.index = MaterialIndex(version=1, approved={"foo.py": FOO_HASH})

    def test_unsigned_link_is_not_admissible(self):
        """A link without a valid signature does not unblock a step."""
        report = reconcile(
            initial_index=self.index,
            deliveries=[
                Delivery(
                    sequence=1,
                    links=[
                        _link(
                            "package",
                            {"foo.py": FOO_HASH},
                            {"foo.tar": PRODUCT_HASH},
                            sign=False,
                        )
                    ],
                )
            ],
            keys=self.keys,
        )
        self.assertEqual(report.final_states["package"], StepState.BLOCKED)
        self.assertFalse(report.events[0].signature_valid)

    def test_duplicate_sequences_rejected(self):
        with self.assertRaises(ValueError):
            reconcile(
                initial_index=self.index,
                deliveries=[Delivery(sequence=1), Delivery(sequence=1)],
                keys=self.keys,
            )

    def test_non_increasing_index_version_rejected(self):
        with self.assertRaises(ValueError):
            reconcile(
                initial_index=self.index,
                deliveries=[Delivery(sequence=1)],
                keys=self.keys,
                index_updates={1: MaterialIndex(version=1)},
            )


if __name__ == "__main__":
    unittest.main()
