# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  test_sod.py

<Started>
  Nov 22, 2026

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Test cross-layout separation of duties verification, i.e.
  verifylib.verify_cross_layout_separation_of_duties and the signing
  evidence collection in verifylib.in_toto_verify.

"""

import os
import unittest

from in_toto.exceptions import SeparationOfDutiesError
from in_toto.models.layout import SUBLAYOUT_LINK_DIR_FORMAT, Layout, Step
from in_toto.models.link import FILENAME_FORMAT, Link
from in_toto.models.metadata import Metablock
from in_toto.verifylib import (
    in_toto_verify,
    verify_cross_layout_separation_of_duties,
)
from tests.common import SignerStore, TmpDirMixin

ALICE = SignerStore.rsa
ALICE_PUB = SignerStore.rsa_pub
BOB = SignerStore.ecdsa
BOB_PUB = SignerStore.ecdsa_pub
CARL = SignerStore.ed25519
CARL_PUB = SignerStore.ed25519_pub

BOB_KEYID = BOB_PUB["keyid"]
CARL_KEYID = CARL_PUB["keyid"]


def _evidence(layout, step, keyid):
    return {"layout": layout, "step": step, "keyid": keyid}


class TestCrossLayoutSeparationOfDuties(unittest.TestCase):
    """Unit tests for verifylib.verify_cross_layout_separation_of_duties."""

    def test_confirmed_conflict_reports_minimal_step_combination(self):
        """Different keys of one entity, build in sublayout and acceptance
        in the superlayout, are reported as a minimal pair of steps."""
        evidence = [
            _evidence("<root>", "accept", "keyid-accept"),
            _evidence("<root>", "build", "keyid-delegate"),
            _evidence("<root>/build", "compile", "keyid-build"),
        ]
        entity_map = {
            "keyid-accept": "outsourcer-1",
            "keyid-build": "outsourcer-1",
            "keyid-delegate": "integrator-2",
        }

        with self.assertRaises(SeparationOfDutiesError) as ctx:
            verify_cross_layout_separation_of_duties(evidence, entity_map)

        # The conflict is the minimal combination of the two steps, with the
        # original step names, layouts and signing identities as evidence
        self.assertEqual(len(ctx.exception.conflicts), 1)
        conflict = ctx.exception.conflicts[0]
        self.assertEqual(conflict["entity"], "outsourcer-1")
        self.assertEqual(
            conflict["steps"],
            [
                {
                    "layout": "<root>",
                    "step": "accept",
                    "keyids": ["keyid-accept"],
                },
                {
                    "layout": "<root>/build",
                    "step": "compile",
                    "keyids": ["keyid-build"],
                },
            ],
        )
        self.assertEqual(ctx.exception.suspensions, [])

    def test_conflict_aggregates_all_signing_identities(self):
        """Multiple aliased keys of one entity on the same pair of steps
        yield one minimal step combination with all keyids as evidence."""
        evidence = [
            _evidence("main", "accept", "keyid-a1"),
            _evidence("main", "accept", "keyid-a2"),
            _evidence("sub", "build", "keyid-b1"),
        ]
        entity_map = {
            "keyid-a1": "entity-1",
            "keyid-a2": "entity-1",
            "keyid-b1": "entity-1",
        }

        with self.assertRaises(SeparationOfDutiesError) as ctx:
            verify_cross_layout_separation_of_duties(evidence, entity_map)

        self.assertEqual(len(ctx.exception.conflicts), 1)
        conflict = ctx.exception.conflicts[0]
        self.assertEqual(
            conflict["steps"][0]["keyids"], ["keyid-a1", "keyid-a2"]
        )
        self.assertEqual(conflict["steps"][1]["keyids"], ["keyid-b1"])

    def test_same_key_alias_duplication_is_not_a_conflict(self):
        """The same public key authorized in multiple layouts (alias
        duplication) is transparently attributable and not flagged."""
        evidence = [
            _evidence("main", "accept", "keyid-1"),
            _evidence("sub", "build", "keyid-1"),
        ]
        entity_map = {"keyid-1": "entity-1"}

        suspensions = verify_cross_layout_separation_of_duties(
            evidence, entity_map
        )
        self.assertEqual(suspensions, [])

    def test_pairs_within_one_layout_are_ignored(self):
        """Duties inside a single layout are out of scope for the
        cross-layout check."""
        evidence = [
            _evidence("main", "build", "keyid-1"),
            _evidence("main", "accept", "keyid-2"),
        ]
        entity_map = {"keyid-1": "entity-1", "keyid-2": "entity-1"}

        suspensions = verify_cross_layout_separation_of_duties(
            evidence, entity_map
        )
        self.assertEqual(suspensions, [])

    def test_distinct_entities_pass(self):
        evidence = [
            _evidence("main", "accept", "keyid-1"),
            _evidence("sub", "build", "keyid-2"),
        ]
        entity_map = {"keyid-1": "entity-1", "keyid-2": "entity-2"}

        suspensions = verify_cross_layout_separation_of_duties(
            evidence, entity_map
        )
        self.assertEqual(suspensions, [])

    def test_unknown_entity_is_suspended(self):
        """Pairs with unmapped keys cannot be assessed and are suspended
        instead of failing the check."""
        evidence = [
            _evidence("main", "accept", "keyid-1"),
            _evidence("sub", "build", "keyid-2"),
        ]
        entity_map = {"keyid-1": "entity-1"}

        suspensions = verify_cross_layout_separation_of_duties(
            evidence, entity_map
        )
        self.assertEqual(len(suspensions), 1)
        self.assertIn("keyid-2", suspensions[0]["reason"])
        self.assertEqual(
            suspensions[0]["steps"],
            [
                _evidence("main", "accept", "keyid-1"),
                _evidence("sub", "build", "keyid-2"),
            ],
        )

    def test_conflicts_and_suspensions_are_reported_together(self):
        """A confirmed conflict fails the check and still carries the
        separately suspended pairs on the exception."""
        evidence = [
            _evidence("main", "accept", "keyid-1"),
            _evidence("sub", "build", "keyid-2"),
            _evidence("sub", "test", "keyid-3"),
        ]
        entity_map = {"keyid-1": "entity-1", "keyid-2": "entity-1"}

        with self.assertRaises(SeparationOfDutiesError) as ctx:
            verify_cross_layout_separation_of_duties(evidence, entity_map)

        self.assertEqual(len(ctx.exception.conflicts), 1)
        # The pair with the unmapped key is suspended separately
        self.assertEqual(len(ctx.exception.suspensions), 1)
        self.assertIn("keyid-3", ctx.exception.suspensions[0]["reason"])


class TestJointVerification(TmpDirMixin, unittest.TestCase):
    """Joint verification of layouts that each pass in-toto verification on
    their own."""

    def setUp(self):
        self.set_up_test_dir()
        self.addCleanup(self.tear_down_test_dir)

    def _build_supply_chain(self, accept_signer, accept_pub, compile_pub):
        """Create a two-level supply chain in the current directory.

        The root layout (signed by the project owner alice) has a step
        "build", delegated to a sublayout signed by bob, and a step "accept",
        signed with `accept_signer`. The sublayout has a step "compile",
        authorized to `compile_pub`. Each layout passes regular in-toto
        verification individually.
        """
        # Root layout
        root_layout = Metablock(
            signed=Layout(
                keys={
                    BOB_KEYID: BOB_PUB,
                    accept_pub["keyid"]: accept_pub,
                },
                steps=[
                    Step(name="build", pubkeys=[BOB_KEYID]),
                    Step(name="accept", pubkeys=[accept_pub["keyid"]]),
                ],
            )
        )
        root_layout.create_signature(ALICE)

        # Sublayout, treated as link of the root layout's "build" step
        sub_layout = Metablock(
            signed=Layout(
                keys={compile_pub["keyid"]: compile_pub},
                steps=[Step(name="compile", pubkeys=[compile_pub["keyid"]])],
            )
        )
        sub_layout.create_signature(BOB)
        sub_layout.dump(
            FILENAME_FORMAT.format(step_name="build", keyid=BOB_KEYID)
        )

        # Link for the sublayout's "compile" step, in the namespaced
        # sublayout link directory
        sub_link_dir = SUBLAYOUT_LINK_DIR_FORMAT.format(
            name="build", keyid=BOB_KEYID
        )
        os.mkdir(sub_link_dir)
        compile_link = Metablock(signed=Link(name="compile"))
        compile_link.create_signature(self._compile_signer)
        compile_link.dump(
            os.path.join(
                sub_link_dir,
                FILENAME_FORMAT.format(
                    step_name="compile", keyid=compile_pub["keyid"]
                ),
            )
        )

        # Link for the root layout's "accept" step
        accept_link = Metablock(signed=Link(name="accept"))
        accept_link.create_signature(accept_signer)
        accept_link.dump(
            FILENAME_FORMAT.format(
                step_name="accept", keyid=accept_pub["keyid"]
            )
        )

        return root_layout

    def _verify_and_check(self, root_layout, entity_map):
        """Run regular verification with evidence collection, followed by
        the cross-layout separation of duties check."""
        signing_evidence = []
        in_toto_verify(
            root_layout,
            {ALICE_PUB["keyid"]: ALICE_PUB},
            signing_evidence=signing_evidence,
        )
        return verify_cross_layout_separation_of_duties(
            signing_evidence, entity_map
        )

    def test_joint_verification_catches_conflicting_entity(self):
        """Each layer passes threshold verification, but the same entity
        signed build (sublayout) and acceptance (root layout) with different
        keys, which joint verification must catch."""
        # The outsourcing entity builds as "bob" and accepts as "carl"
        self._compile_signer = BOB
        root_layout = self._build_supply_chain(CARL, CARL_PUB, BOB_PUB)

        entity_map = {
            BOB_KEYID: "outsourcer-1",
            CARL_KEYID: "outsourcer-1",
        }

        with self.assertRaises(SeparationOfDutiesError) as ctx:
            self._verify_and_check(root_layout, entity_map)

        # The confirmed conflict is reported as the minimal step combination
        self.assertEqual(len(ctx.exception.conflicts), 1)
        conflict = ctx.exception.conflicts[0]
        self.assertEqual(conflict["entity"], "outsourcer-1")
        self.assertEqual(
            conflict["steps"],
            [
                {
                    "layout": "<root>",
                    "step": "accept",
                    "keyids": [CARL_KEYID],
                },
                {
                    "layout": "<root>/build",
                    "step": "compile",
                    "keyids": [BOB_KEYID],
                },
            ],
        )

    def test_joint_verification_suspends_unknown_entity(self):
        """Without an offline entity mapping, independence is unclear and
        the pair is suspended instead of failing joint verification."""
        self._compile_signer = BOB
        root_layout = self._build_supply_chain(CARL, CARL_PUB, BOB_PUB)

        suspensions = self._verify_and_check(root_layout, {})

        # "accept" (root) vs. "compile" (sublayout) cannot be assessed
        self.assertEqual(len(suspensions), 1)
        self.assertEqual(
            suspensions[0]["steps"],
            [
                _evidence("<root>", "accept", CARL_KEYID),
                _evidence("<root>/build", "compile", BOB_KEYID),
            ],
        )

    def test_alias_duplication_control_passes(self):
        """Control group: the same public key is authorized under both
        layouts (alias duplication only). Joint verification passes."""
        # Build and acceptance are signed with the same key
        self._compile_signer = CARL
        root_layout = self._build_supply_chain(CARL, CARL_PUB, CARL_PUB)

        entity_map = {
            BOB_KEYID: "integrator-2",
            CARL_KEYID: "outsourcer-1",
        }

        suspensions = self._verify_and_check(root_layout, entity_map)
        self.assertEqual(suspensions, [])


if __name__ == "__main__":
    unittest.main()
